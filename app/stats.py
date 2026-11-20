"""Per-layer byte diagnostics for an image, computed without disk extraction.

The typical question this answers: "the install cache was deleted by an upper
layer, but the image still carries the old bytes -- which layer wrote them,
and which layer made them useless?"

The module reuses the *already verified* layer tars produced by
:func:`app.unpacker.load_and_verify` and applies them to an in-memory tree
(:class:`VFS`) using the exact same overlay logic as the on-disk unpacker
(same member scan, same two-phase whiteout/opaque handling, same path
resolution).  File contents are never read or written to disk -- only tar
metadata (names, types, sizes, link targets) is inspected.

Model:

* every non-sparse regular file entry is one **write** with a sequential id,
  a 1-based layer number and a byte count; writing the same path twice in
  one layer counts both writes;
* a hardlink adds a *reference* to an existing write, never a new write --
  so overwriting one end of a hardlink pair leaves the old bytes alive
  (referenced by the other end);
* a write is **invalidated** in the layer where its *last* direct reference
  disappears (overwritten, replaced by another entry type, removed by a
  whiteout or by an opaque directory, or its parent directory is replaced);
* directories, symlinks and hardlinks take part in the overlay but carry no
  bytes; anything else (sparse files, fifos, device nodes, ...) is rejected
  with :class:`UnpackError`, as is any verification or overlay failure.

The resulting document (see :func:`collect_image_stats`) contains the raw
``writes`` / ``invalidations`` records plus a per-layer summary.  A reviewer
can later upload that JSON (no image needed) to ``POST /verify-stats``,
which recomputes the summaries via :func:`verify_stats_doc` and reports
duplicate write ids, duplicate invalidations, invalidations without a
matching write or preceding it, and summary mismatches.
"""

from __future__ import annotations

import os
import tarfile

from .unpacker import (
    UnpackError,
    _check_link_target_parts,
    _normalize_archive_name,
    _open_layer,
    _resolve_components,
    extract_layout,
    load_and_verify,
    scan_layer_members,
)

STATS_SCHEMA = "oci-unpacker-stats/1"


class StatsDocError(Exception):
    """The uploaded document is not a well-formed stats document."""


def _is_sparse(member):
    """True if the tar member is a sparse regular file (GNU or pax marker)."""
    if member.type == tarfile.GNUTYPE_SPARSE:
        return True
    if getattr(member, "sparse", None):
        return True
    return any(k.startswith("GNU.sparse") for k in member.pax_headers)


# ---------------------------------------------------------------------------
# in-memory filesystem tree with write/invalidation accounting
# ---------------------------------------------------------------------------


class VFS:
    """In-memory rootfs tree mirroring the on-disk unpacker's semantics.

    ``entries`` maps a path (tuple of components) to a node:
    ``("dir",)``, ``("symlink", target)`` or ``("file", write_id)``.
    Every live ``("file", write_id)`` node is counted in ``refs``; when a
    write's last reference disappears an invalidation is recorded against
    the layer currently being applied.
    """

    def __init__(self):
        self.entries = {(): ("dir",)}
        self.layer = 0  # 1-based number of the layer being applied
        self.writes = []  # {"id", "layer", "bytes"}
        self.refs = {}  # write id -> live reference count
        self.invalidations = []  # {"write", "layer"}

    # -- path resolution (mirrors unpacker._resolve_within) --

    def _probe(self, parts):
        node = self.entries.get(parts)
        if node is None:
            return None
        if node[0] == "symlink":
            return ("link", node[1])
        return ("other", None)

    def resolve(self, parts):
        """Resolve *parts*; the final component is never dereferenced."""
        return tuple(_resolve_components(self._probe, list(parts)))

    def _resolve_dir(self, parts):
        """Resolve *parts* the way os.path.isdir/os.listdir would: a symlink
        in the final position is followed too."""
        if not parts:
            return ()
        # A sentinel component makes the final real component "intermediate",
        # so the shared resolver follows a symlink sitting there.  "\x00" can
        # never be an entry name (rejected by _normalize_archive_name).
        probed = _resolve_components(self._probe, list(parts) + ["\x00"])
        return tuple(probed[:-1])

    # -- reference accounting --

    def _lose_ref(self, write_id):
        left = self.refs[write_id] - 1
        if left > 0:
            self.refs[write_id] = left
        else:
            del self.refs[write_id]
            self.invalidations.append({"write": write_id, "layer": self.layer})

    def _remove_node(self, parts):
        """Remove the node at *parts* (and everything below it), dropping the
        corresponding write references."""
        node = self.entries.pop(parts, None)
        if node is None:
            return
        if node[0] == "file":
            self._lose_ref(node[1])
        elif node[0] == "dir":
            n = len(parts)
            victims = sorted(
                k for k in self.entries if len(k) > n and k[:n] == parts
            )
            for k in victims:
                child = self.entries.pop(k)
                if child[0] == "file":
                    self._lose_ref(child[1])

    def _ensure_parents(self, parts):
        """Materialize missing ancestors as directories (makedirs semantics);
        a non-directory ancestor aborts the entry, as on a real fs."""
        for i in range(1, len(parts)):
            ancestor = parts[:i]
            node = self.entries.get(ancestor)
            if node is None:
                self.entries[ancestor] = ("dir",)
            elif node[0] != "dir":
                raise UnpackError(
                    f"parent {'/'.join(ancestor)!r} is not a directory"
                )

    # -- entry application (mirrors unpacker._apply_entry) --

    def add_dir(self, parts):
        dest = self.resolve(parts)
        self._ensure_parents(dest)
        node = self.entries.get(dest)
        if node is not None and node[0] != "dir":
            self._remove_node(dest)
            node = None
        if node is None:
            self.entries[dest] = ("dir",)

    def add_file(self, parts, size):
        dest = self.resolve(parts)
        self._ensure_parents(dest)
        if dest in self.entries:
            self._remove_node(dest)
        write_id = len(self.writes) + 1
        self.writes.append({"id": write_id, "layer": self.layer, "bytes": size})
        self.refs[write_id] = 1
        self.entries[dest] = ("file", write_id)

    def add_symlink(self, parts, target):
        dest = self.resolve(parts)
        self._ensure_parents(dest)
        _check_link_target_parts(dest[:-1], target)
        if dest in self.entries:
            self._remove_node(dest)
        self.entries[dest] = ("symlink", target)

    def add_hardlink(self, parts, linkname, rel):
        tparts = _normalize_archive_name(linkname, f"hardlink target of {rel!r}")
        if not tparts:
            raise UnpackError(f"hardlink {rel!r}: empty target")
        rtarget = self.resolve(tparts)
        tnode = self.entries.get(rtarget)
        if tnode is None:
            raise UnpackError(
                f"hardlink {rel!r}: target {linkname!r} not found in rootfs"
            )
        dest = self.resolve(parts)
        self._ensure_parents(dest)
        if dest == rtarget:
            raise UnpackError(f"hardlink {rel!r}: cannot link {linkname!r} to itself")
        self._remove_node(dest)
        if self.entries.get(rtarget) is not tnode:
            # removing dest wiped out the target (dest was its ancestor dir)
            raise UnpackError(f"hardlink {rel!r}: target {linkname!r} vanished")
        if tnode[0] == "file":
            # a hardlink adds a reference to the existing write, never a
            # new write -- the bytes stay alive while any end remains
            self.refs[tnode[1]] += 1
            self.entries[dest] = ("file", tnode[1])
        elif tnode[0] == "symlink":
            self.entries[dest] = ("symlink", tnode[1])
        else:
            raise UnpackError(f"hardlink {rel!r}: target is a directory")

    # -- whiteout / opaque (phase 1 of a layer) --

    def remove_path(self, parts):
        self._remove_node(self.resolve(parts))

    def opaque(self, parts):
        resolved = self.resolve(parts) if parts else ()
        dirparts = self._resolve_dir(resolved)
        node = self.entries.get(dirparts)
        if node is None or node[0] != "dir":
            return
        n = len(dirparts)
        victims = sorted(
            k for k in self.entries if len(k) > n and k[:n] == dirparts
        )
        for k in victims:
            child = self.entries.pop(k)
            if child[0] == "file":
                self._lose_ref(child[1])


# ---------------------------------------------------------------------------
# layer application on the VFS (shares the unpacker's overlay logic)
# ---------------------------------------------------------------------------


def apply_layer_stats(tar_path, vfs):
    """Apply one verified layer tar to the VFS (metadata only, no content
    is ever read from the tar or written to disk)."""
    tf, members = _open_layer(tar_path)
    with tf:
        entries, deletions, opaque_dirs = scan_layer_members(members)

        # Phase 1: deletions / opaque markers apply to the *lower* state
        # only, exactly like the on-disk unpacker.
        for target in deletions:
            vfs.remove_path(target)
        for d in opaque_dirs:
            vfs.opaque(d)

        # Phase 2: this layer's new content, in tar order.
        for m, parts in entries:
            rel = "/".join(parts)
            if m.isdir():
                vfs.add_dir(parts)
            elif m.isreg():
                if _is_sparse(m):
                    raise UnpackError(
                        f"sparse files are not supported for statistics: {rel!r}"
                    )
                if m.size < 0:
                    raise UnpackError(f"invalid size for entry {rel!r}")
                vfs.add_file(parts, m.size)
            elif m.issym():
                vfs.add_symlink(parts, m.linkname)
            elif m.islnk():
                vfs.add_hardlink(parts, m.linkname, rel)
            else:
                raise UnpackError(
                    f"statistics support only regular files, directories, "
                    f"symlinks and hardlinks: entry {rel!r} type {m.type!r}"
                )


# ---------------------------------------------------------------------------
# stats document
# ---------------------------------------------------------------------------


def summarize_layers(writes, invalidations, layer_count):
    """Per-layer summary: written bytes, retained bytes and invalidated
    bytes grouped by the layer that invalidated them (1-based layers)."""
    inv_layer = {}
    for inv in invalidations:
        inv_layer.setdefault(inv["write"], inv["layer"])
    written = {}
    retained = {}
    invalidated = {}
    for w in writes:
        layer = w["layer"]
        written[layer] = written.get(layer, 0) + w["bytes"]
        k = inv_layer.get(w["id"])
        if k is None:
            retained[layer] = retained.get(layer, 0) + w["bytes"]
        else:
            by_layer = invalidated.setdefault(layer, {})
            by_layer[k] = by_layer.get(k, 0) + w["bytes"]
    layers = []
    for layer in range(1, layer_count + 1):
        by_layer = invalidated.get(layer, {})
        layers.append(
            {
                "layer": layer,
                "written_bytes": written.get(layer, 0),
                "retained_bytes": retained.get(layer, 0),
                "invalidated_in": {
                    str(k): by_layer[k] for k in sorted(by_layer)
                },
            }
        )
    return layers


def collect_image_stats(upload_path, workdir):
    """Verify the uploaded layout and compute the stats document.

    Uses the already-verified layer tars; raises UnpackError on any
    verification or overlay failure (nothing is returned then).
    """
    layout_dir = os.path.join(workdir, "layout")
    os.makedirs(layout_dir)
    extract_layout(upload_path, layout_dir)
    layer_tars = load_and_verify(layout_dir, workdir)

    vfs = VFS()
    for i, tar_path in enumerate(layer_tars, start=1):
        vfs.layer = i
        apply_layer_stats(tar_path, vfs)

    return {
        "schema": STATS_SCHEMA,
        "writes": vfs.writes,
        "invalidations": vfs.invalidations,
        "layers": summarize_layers(vfs.writes, vfs.invalidations, len(layer_tars)),
    }


# ---------------------------------------------------------------------------
# reviewer-side verification (recompute and check, no image needed)
# ---------------------------------------------------------------------------


def _req_int(value, what, minimum):
    if not isinstance(value, int) or isinstance(value, bool):
        raise StatsDocError(f"{what}: must be an integer")
    if value < minimum:
        raise StatsDocError(f"{what}: must be >= {minimum}")
    return value


def verify_stats_doc(doc):
    """Recompute per-layer summaries from a stats document and check them
    against the embedded ones.

    Returns ``(errors, recomputed_layers)``.  Raises StatsDocError when the
    document is structurally unusable (not JSON-shaped as a stats doc).
    """
    if not isinstance(doc, dict):
        raise StatsDocError("document must be a JSON object")
    writes = doc.get("writes")
    invalidations = doc.get("invalidations")
    layers = doc.get("layers")
    for name, value in (
        ("writes", writes),
        ("invalidations", invalidations),
        ("layers", layers),
    ):
        if not isinstance(value, list):
            raise StatsDocError(f"{name}: must be a list")

    errors = []
    if "schema" in doc and doc["schema"] != STATS_SCHEMA:
        errors.append(f"unsupported schema: {doc['schema']!r}")

    # --- writes: ids must be unique ---
    write_layer = {}
    duplicate_writes = set()
    for i, w in enumerate(writes):
        if not isinstance(w, dict):
            raise StatsDocError(f"writes[{i}]: must be an object")
        wid = _req_int(w.get("id"), f"writes[{i}].id", 1)
        wlayer = _req_int(w.get("layer"), f"writes[{i}].layer", 1)
        _req_int(w.get("bytes"), f"writes[{i}].bytes", 0)
        if wid in write_layer:
            duplicate_writes.add(wid)
        else:
            write_layer[wid] = wlayer
    for wid in sorted(duplicate_writes):
        errors.append(f"duplicate write id {wid}")

    # --- invalidations: known write, not before it, not invalidated twice ---
    inv_layer = {}
    for i, inv in enumerate(invalidations):
        if not isinstance(inv, dict):
            raise StatsDocError(f"invalidations[{i}]: must be an object")
        wid = _req_int(inv.get("write"), f"invalidations[{i}].write", 1)
        ilayer = _req_int(inv.get("layer"), f"invalidations[{i}].layer", 1)
        if wid in inv_layer:
            errors.append(
                f"write {wid} invalidated more than once "
                f"(layers {inv_layer[wid]} and {ilayer})"
            )
            continue
        inv_layer[wid] = ilayer
        if wid not in write_layer:
            errors.append(f"invalidation references unknown write id {wid}")
        elif ilayer < write_layer[wid]:
            errors.append(
                f"write {wid} invalidated at layer {ilayer} before "
                f"its write at layer {write_layer[wid]}"
            )

    # --- provided per-layer summary ---
    provided = {}
    for i, e in enumerate(layers):
        if not isinstance(e, dict):
            raise StatsDocError(f"layers[{i}]: must be an object")
        layer = _req_int(e.get("layer"), f"layers[{i}].layer", 1)
        _req_int(e.get("written_bytes"), f"layers[{i}].written_bytes", 0)
        _req_int(e.get("retained_bytes"), f"layers[{i}].retained_bytes", 0)
        inv_in = e.get("invalidated_in")
        if not isinstance(inv_in, dict):
            raise StatsDocError(f"layers[{i}].invalidated_in: must be an object")
        norm_inv = {}
        for k, v in inv_in.items():
            try:
                klayer = int(k)
            except (TypeError, ValueError):
                raise StatsDocError(
                    f"layers[{i}].invalidated_in: invalid layer key {k!r}"
                )
            if klayer < 1:
                raise StatsDocError(
                    f"layers[{i}].invalidated_in: invalid layer key {k!r}"
                )
            _req_int(v, f"layers[{i}].invalidated_in[{k!r}]", 0)
            if v:
                norm_inv[klayer] = norm_inv.get(klayer, 0) + v
        if layer in provided:
            errors.append(f"summary: duplicate entry for layer {layer}")
        else:
            provided[layer] = {
                "written_bytes": e["written_bytes"],
                "retained_bytes": e["retained_bytes"],
                "invalidated_in": norm_inv,
            }

    n = max(provided) if provided else 0
    if set(provided) != set(range(1, n + 1)):
        errors.append(f"summary layers must be numbered 1..{n} without gaps")

    # --- recompute from the raw records and compare ---
    top = n
    for w in writes:
        top = max(top, w["layer"])
    for inv in invalidations:
        top = max(top, inv["layer"])
    for e in provided.values():
        for k in e["invalidated_in"]:
            top = max(top, k)
    recomputed = summarize_layers(writes, invalidations, top)

    for entry in recomputed:
        layer = entry["layer"]
        prov = provided.get(layer)
        if prov is None:
            if (
                entry["written_bytes"]
                or entry["retained_bytes"]
                or entry["invalidated_in"]
            ):
                errors.append(f"summary: missing entry for layer {layer}")
            continue
        if prov["written_bytes"] != entry["written_bytes"]:
            errors.append(
                f"layer {layer}: written_bytes summary says "
                f"{prov['written_bytes']}, recomputed {entry['written_bytes']}"
            )
        if prov["retained_bytes"] != entry["retained_bytes"]:
            errors.append(
                f"layer {layer}: retained_bytes summary says "
                f"{prov['retained_bytes']}, recomputed {entry['retained_bytes']}"
            )
        rec_inv = {int(k): v for k, v in entry["invalidated_in"].items()}
        if prov["invalidated_in"] != rec_inv:
            errors.append(
                f"layer {layer}: invalidated_in summary says "
                f"{prov['invalidated_in']}, recomputed {rec_inv}"
            )

    return errors, recomputed

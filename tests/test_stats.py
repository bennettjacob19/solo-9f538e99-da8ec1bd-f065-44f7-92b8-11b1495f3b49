"""Tests for the per-layer byte diagnostics (stats mode) and the
reviewer-side stats verification endpoint."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.sample_image import MT_CONFIG, MT_INDEX, MT_LAYER, MT_LAYER_GZ, MT_MANIFEST
from app.stats import _is_sparse


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_layer(entries) -> bytes:
    """entries: list of (name, kind, payload); kind in
    file/dir/symlink/hardlink."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, kind, payload in entries:
            ti = tarfile.TarInfo(name)
            ti.mtime = 1_700_000_000
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tf.addfile(ti)
            elif kind == "file":
                data = payload if isinstance(payload, bytes) else payload.encode()
                ti.type = tarfile.REGTYPE
                ti.mode = 0o644
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
            elif kind == "symlink":
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload
                tf.addfile(ti)
            elif kind == "hardlink":
                ti.type = tarfile.LNKTYPE
                ti.linkname = payload
                tf.addfile(ti)
    return buf.getvalue()


def make_fifo_layer() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        ti = tarfile.TarInfo("pipe")
        ti.type = tarfile.FIFOTYPE
        tf.addfile(ti)
    return buf.getvalue()


def write_layout(files) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name in sorted(files):
            ti = tarfile.TarInfo(name)
            ti.size = len(files[name])
            tf.addfile(ti, io.BytesIO(files[name]))
    return buf.getvalue()


def build_layout(layers) -> bytes:
    """Build a single-manifest OCI layout tar from (media_type, blob) pairs."""
    diff_ids = []
    for mt, blob in layers:
        try:
            plain = gzip.decompress(blob) if "gzip" in mt else blob
        except OSError:
            plain = blob  # corrupt gzip: verification will fail later anyway
        diff_ids.append(f"sha256:{sha256(plain)}")

    config = {
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
    }
    config_b = json.dumps(config).encode()
    manifest = {
        "schemaVersion": 2,
        "mediaType": MT_MANIFEST,
        "config": {
            "mediaType": MT_CONFIG,
            "digest": f"sha256:{sha256(config_b)}",
            "size": len(config_b),
        },
        "layers": [
            {"mediaType": mt, "digest": f"sha256:{sha256(blob)}", "size": len(blob)}
            for mt, blob in layers
        ],
    }
    manifest_b = json.dumps(manifest).encode()
    index = {
        "schemaVersion": 2,
        "mediaType": MT_INDEX,
        "manifests": [{
            "mediaType": MT_MANIFEST,
            "digest": f"sha256:{sha256(manifest_b)}",
            "size": len(manifest_b),
        }],
    }
    files = {
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        "index.json": json.dumps(index).encode(),
        f"blobs/sha256/{sha256(config_b)}": config_b,
        f"blobs/sha256/{sha256(manifest_b)}": manifest_b,
    }
    for _, blob in layers:
        files[f"blobs/sha256/{sha256(blob)}"] = blob
    return write_layout(files)


def unpack(client, data: bytes, **params):
    return client.post("/unpack", params=params,
                       files={"file": ("image.tar", data, "application/x-tar")})


def get_stats(client, data: bytes):
    r = unpack(client, data, stats="true")
    assert r.status_code == 200, r.text
    return r.json()


def post_verify(client, payload: bytes):
    return client.post(
        "/verify-stats",
        files={"file": ("stats.json", payload, "application/json")},
    )


def rootfs_file_bytes(content: bytes) -> int:
    """Total bytes of regular files in a rootfs.tar (hardlink targets only)."""
    total = 0
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as tf:
        for m in tf.getmembers():
            if m.isreg():
                total += m.size
    return total


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def sample(client):
    r = client.get("/sample-image")
    assert r.status_code == 200
    return r.content


# ---------------------------------------------------------------------------
# stats mode: the sample image
# ---------------------------------------------------------------------------


def test_sample_stats_exact(client, sample):
    doc = get_stats(client, sample)
    assert doc["schema"] == "oci-unpacker-stats/1"

    # layer 1 writes (1-based layers, sequential write ids)
    assert doc["writes"] == [
        {"id": 1, "layer": 1, "bytes": 24},   # etc/motd
        {"id": 2, "layer": 1, "bytes": 8},    # bin/tool (v1)
        {"id": 3, "layer": 1, "bytes": 10},   # app/config.txt
        {"id": 4, "layer": 1, "bytes": 8},    # app/data/keep.txt
        {"id": 5, "layer": 1, "bytes": 10},   # app/data/remove.txt
        {"id": 6, "layer": 1, "bytes": 13},   # app/data/rebuilt.txt (old)
        {"id": 7, "layer": 1, "bytes": 13},   # secret/token.txt
        {"id": 8, "layer": 2, "bytes": 11},   # secret/public.txt
        {"id": 9, "layer": 2, "bytes": 8},    # bin/tool (v2)
        {"id": 10, "layer": 2, "bytes": 13},  # app/data/rebuilt.txt (new)
    ]

    # whiteouts remove.txt/config.txt/rebuilt.txt, then opaque secret/
    # (deletions run before opaque markers in phase 1); bin/tool-link still
    # references write 2, so the hardlink overwrite of bin/tool does NOT
    # invalidate the old bytes.
    assert doc["invalidations"] == [
        {"write": 5, "layer": 2},
        {"write": 3, "layer": 2},
        {"write": 6, "layer": 2},
        {"write": 7, "layer": 2},
    ]

    assert doc["layers"] == [
        {"layer": 1, "written_bytes": 86, "retained_bytes": 40,
         "invalidated_in": {"2": 46}},
        {"layer": 2, "written_bytes": 32, "retained_bytes": 32,
         "invalidated_in": {}},
    ]


def test_stats_retained_matches_rootfs_bytes(client, sample):
    doc = get_stats(client, sample)
    retained = sum(e["retained_bytes"] for e in doc["layers"])
    r = unpack(client, sample)
    assert r.status_code == 200
    assert rootfs_file_bytes(r.content) == retained == 72


def test_default_and_stats_false_download_rootfs(client, sample):
    for params in ({}, {"stats": "false"}):
        r = unpack(client, sample, **params)
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/x-tar"
        assert rootfs_file_bytes(r.content) == 72


def test_stats_true_returns_json(client, sample):
    r = unpack(client, sample, stats="true")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert set(r.json()) == {"schema", "writes", "invalidations", "layers"}


# ---------------------------------------------------------------------------
# stats mode: write / invalidation semantics with crafted layers
# ---------------------------------------------------------------------------


def test_same_layer_rewrite_counts_each_write(client):
    layer1 = make_layer([("a.txt", "file", b"aaaa")])
    layer2 = make_layer([("a.txt", "file", b"bb"), ("a.txt", "file", b"ccc")])
    doc = get_stats(client, build_layout([(MT_LAYER, layer1),
                                          (MT_LAYER, layer2)]))
    assert doc["writes"] == [
        {"id": 1, "layer": 1, "bytes": 4},
        {"id": 2, "layer": 2, "bytes": 2},
        {"id": 3, "layer": 2, "bytes": 3},
    ]
    # both earlier writes die in layer 2 -- the second one in the same layer
    # that wrote it
    assert doc["invalidations"] == [
        {"write": 1, "layer": 2},
        {"write": 2, "layer": 2},
    ]
    assert doc["layers"] == [
        {"layer": 1, "written_bytes": 4, "retained_bytes": 0,
         "invalidated_in": {"2": 4}},
        {"layer": 2, "written_bytes": 5, "retained_bytes": 3,
         "invalidated_in": {"2": 2}},
    ]


def test_hardlink_invalidated_only_when_last_reference_dies(client):
    layer1 = make_layer([("x/a", "file", b"12345"), ("x/b", "hardlink", "x/a")])
    layer2 = make_layer([("x/.wh.a", "file", b"")])
    layer3 = make_layer([("x/.wh.b", "file", b"")])
    data = build_layout([(MT_LAYER, layer1), (MT_LAYER, layer2),
                         (MT_LAYER, layer3)])
    doc = get_stats(client, data)
    # the hardlink added no write of its own
    assert doc["writes"] == [{"id": 1, "layer": 1, "bytes": 5}]
    # deleting one end keeps the bytes alive; the write dies with its last
    # reference in layer 3
    assert doc["invalidations"] == [{"write": 1, "layer": 3}]
    assert doc["layers"] == [
        {"layer": 1, "written_bytes": 5, "retained_bytes": 0,
         "invalidated_in": {"3": 5}},
        {"layer": 2, "written_bytes": 0, "retained_bytes": 0,
         "invalidated_in": {}},
        {"layer": 3, "written_bytes": 0, "retained_bytes": 0,
         "invalidated_in": {}},
    ]
    # the real unpack agrees: x/b still had the bytes after layer 2
    r = unpack(client, data)
    assert r.status_code == 200
    assert rootfs_file_bytes(r.content) == 0


def test_hardlink_overwrite_other_end_keeps_bytes(client):
    layer1 = make_layer([("x/a", "file", b"old"), ("x/b", "hardlink", "x/a")])
    layer2 = make_layer([("x/b", "file", b"newer")])
    doc = get_stats(client, build_layout([(MT_LAYER, layer1),
                                          (MT_LAYER, layer2)]))
    # overwriting x/b leaves x/a referencing the old write: nothing invalidated
    assert doc["writes"] == [
        {"id": 1, "layer": 1, "bytes": 3},
        {"id": 2, "layer": 2, "bytes": 5},
    ]
    assert doc["invalidations"] == []
    assert doc["layers"][0]["retained_bytes"] == 3
    assert doc["layers"][1]["retained_bytes"] == 5


def test_whiteout_directory_removes_subtree(client):
    layer1 = make_layer([
        ("d/f1", "file", b"11"),
        ("d/sub/f2", "file", b"222"),
        ("top", "file", b"t"),
    ])
    layer2 = make_layer([(".wh.d", "file", b"")])
    doc = get_stats(client, build_layout([(MT_LAYER, layer1),
                                          (MT_LAYER, layer2)]))
    assert doc["invalidations"] == [
        {"write": 1, "layer": 2},
        {"write": 2, "layer": 2},
    ]
    assert doc["layers"][0] == {"layer": 1, "written_bytes": 6,
                                "retained_bytes": 1,
                                "invalidated_in": {"2": 5}}


def test_file_replacing_directory_invalidates_children(client):
    layer1 = make_layer([("x/a", "file", b"aaaa"), ("x/b", "file", b"bb")])
    layer2 = make_layer([("x", "file", b"q")])
    doc = get_stats(client, build_layout([(MT_LAYER, layer1),
                                          (MT_LAYER, layer2)]))
    assert doc["invalidations"] == [
        {"write": 1, "layer": 2},
        {"write": 2, "layer": 2},
    ]
    assert doc["layers"] == [
        {"layer": 1, "written_bytes": 6, "retained_bytes": 0,
         "invalidated_in": {"2": 6}},
        {"layer": 2, "written_bytes": 1, "retained_bytes": 1,
         "invalidated_in": {}},
    ]


def test_opaque_through_symlinked_dir(client):
    layer1 = make_layer([("real/f", "file", b"1234"), ("real/g", "file", b"56")])
    # a *relative* symlink: both the on-disk unpacker (os.path.isdir follows
    # it inside the rootfs) and the stats overlay resolve it to real/
    layer2 = make_layer([("link", "symlink", "real")])
    layer3 = make_layer([("link/.wh..wh..opq", "file", b"")])
    data = build_layout([(MT_LAYER, layer1), (MT_LAYER, layer2),
                         (MT_LAYER, layer3)])
    doc = get_stats(client, data)
    assert doc["invalidations"] == [
        {"write": 1, "layer": 3},
        {"write": 2, "layer": 3},
    ]
    assert doc["layers"][0]["invalidated_in"] == {"3": 6}
    # the on-disk unpacker agrees: real/ ends up empty
    r = unpack(client, data)
    assert r.status_code == 200
    assert rootfs_file_bytes(r.content) == 0


def test_zero_byte_write_is_recorded(client):
    layer1 = make_layer([("empty", "file", b"")])
    doc = get_stats(client, build_layout([(MT_LAYER, layer1)]))
    assert doc["writes"] == [{"id": 1, "layer": 1, "bytes": 0}]
    assert doc["layers"][0]["written_bytes"] == 0
    assert doc["layers"][0]["retained_bytes"] == 0


def test_empty_image(client):
    doc = get_stats(client, build_layout([]))
    assert doc["writes"] == []
    assert doc["invalidations"] == []
    assert doc["layers"] == []
    report = post_verify(client, json.dumps(doc).encode()).json()
    assert report["valid"] is True


def test_opaque_at_root_invalidates_everything(client):
    layer1 = make_layer([("a/f", "file", b"123"), ("g", "file", b"45")])
    layer2 = make_layer([(".wh..wh..opq", "file", b"")])
    doc = get_stats(client, build_layout([(MT_LAYER, layer1),
                                          (MT_LAYER, layer2)]))
    assert doc["invalidations"] == [
        {"write": 1, "layer": 2},
        {"write": 2, "layer": 2},
    ]
    assert doc["layers"][0]["retained_bytes"] == 0


def test_gzip_layer_stats(client):
    layer1 = gzip.compress(make_layer([("g", "file", b"gzipped!")]), mtime=0)
    layer2 = make_layer([(".wh.g", "file", b"")])
    doc = get_stats(client, build_layout([(MT_LAYER_GZ, layer1),
                                          (MT_LAYER, layer2)]))
    assert doc["writes"] == [{"id": 1, "layer": 1, "bytes": 8}]
    assert doc["invalidations"] == [{"write": 1, "layer": 2}]


# ---------------------------------------------------------------------------
# stats mode: failures only report errors
# ---------------------------------------------------------------------------


def test_stats_verification_failure_is_400(client):
    data = build_layout([(MT_LAYER_GZ, b"definitely not gzip")])
    r = unpack(client, data, stats="true")
    assert r.status_code == 400
    assert "gzip" in r.json()["detail"]
    assert "writes" not in r.json()


def test_stats_rejects_fifo(client):
    data = build_layout([(MT_LAYER, make_layer([("ok", "file", b"x")])),
                         (MT_LAYER, make_fifo_layer())])
    r = unpack(client, data, stats="false")
    assert r.status_code == 200  # normal unpack supports fifos
    r = unpack(client, data, stats="true")
    assert r.status_code == 400
    assert "statistics support only" in r.json()["detail"]


def test_stats_overlay_failure_is_400(client):
    # hardlink to a missing target fails the overlay in stats mode too
    layer1 = make_layer([("a", "hardlink", "no/such/file")])
    r = unpack(client, build_layout([(MT_LAYER, layer1)]), stats="true")
    assert r.status_code == 400
    assert "not found" in r.json()["detail"]


def test_is_sparse_predicate():
    ti = tarfile.TarInfo("x")
    ti.type = tarfile.REGTYPE
    assert not _is_sparse(ti)
    ti = tarfile.TarInfo("x")
    ti.type = tarfile.GNUTYPE_SPARSE
    assert _is_sparse(ti)
    ti = tarfile.TarInfo("x")
    ti.pax_headers = {"GNU.sparse.size": "100"}
    assert _is_sparse(ti)


def test_stats_rejects_sparse_pax(client):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        ti = tarfile.TarInfo("sparse.bin")
        ti.size = 3
        ti.pax_headers["GNU.sparse.size"] = "3"
        tf.addfile(ti, io.BytesIO(b"abc"))
    r = unpack(client, build_layout([(MT_LAYER, buf.getvalue())]), stats="true")
    assert r.status_code == 400
    assert "sparse" in r.json()["detail"]


# ---------------------------------------------------------------------------
# reviewer-side verification
# ---------------------------------------------------------------------------


def test_verify_roundtrip_ok(client, sample):
    doc = get_stats(client, sample)
    r = post_verify(client, json.dumps(doc).encode())
    assert r.status_code == 200
    report = r.json()
    assert report["valid"] is True
    assert report["errors"] == []
    assert report["layers"] == doc["layers"]


def test_verify_duplicate_write_id(client, sample):
    doc = get_stats(client, sample)
    doc["writes"].append({"id": 1, "layer": 1, "bytes": 5})
    report = post_verify(client, json.dumps(doc).encode()).json()
    assert report["valid"] is False
    assert any("duplicate write id 1" in e for e in report["errors"])


def test_verify_duplicate_invalidation(client, sample):
    doc = get_stats(client, sample)
    doc["invalidations"].append({"write": 3, "layer": 2})
    report = post_verify(client, json.dumps(doc).encode()).json()
    assert report["valid"] is False
    assert any("write 3 invalidated more than once" in e
               for e in report["errors"])


def test_verify_invalidation_without_write(client, sample):
    doc = get_stats(client, sample)
    doc["invalidations"].append({"write": 999, "layer": 2})
    report = post_verify(client, json.dumps(doc).encode()).json()
    assert report["valid"] is False
    assert any("unknown write id 999" in e for e in report["errors"])


def test_verify_invalidation_before_write(client, sample):
    doc = get_stats(client, sample)
    doc["invalidations"].append({"write": 8, "layer": 1})  # write 8 is layer 2
    report = post_verify(client, json.dumps(doc).encode()).json()
    assert report["valid"] is False
    assert any("write 8 invalidated at layer 1 before its write at layer 2"
               in e for e in report["errors"])


def test_verify_summary_mismatch_written_and_retained(client, sample):
    doc = get_stats(client, sample)
    doc["layers"][0]["written_bytes"] = 87
    doc["layers"][1]["retained_bytes"] = 0
    report = post_verify(client, json.dumps(doc).encode()).json()
    assert report["valid"] is False
    assert any("layer 1: written_bytes" in e for e in report["errors"])
    assert any("layer 2: retained_bytes" in e for e in report["errors"])


def test_verify_summary_mismatch_invalidated_in(client, sample):
    doc = get_stats(client, sample)
    doc["layers"][0]["invalidated_in"] = {"2": 45}
    report = post_verify(client, json.dumps(doc).encode()).json()
    assert report["valid"] is False
    assert any("layer 1: invalidated_in" in e for e in report["errors"])


def test_verify_summary_layer_gap(client, sample):
    doc = get_stats(client, sample)
    doc["layers"] = [doc["layers"][1]]  # drop layer 1 entry
    report = post_verify(client, json.dumps(doc).encode()).json()
    assert report["valid"] is False
    assert any("without gaps" in e for e in report["errors"])


def test_verify_not_json(client):
    r = post_verify(client, b"{this is not json")
    assert r.status_code == 400


def test_verify_wrong_shape(client):
    r = post_verify(client, json.dumps({"writes": {}, "invalidations": [],
                                        "layers": []}).encode())
    assert r.status_code == 400
    r = post_verify(client, json.dumps(["not", "an", "object"]).encode())
    assert r.status_code == 400


def test_verify_bad_field_types(client, sample):
    doc = get_stats(client, sample)
    doc["writes"][0]["bytes"] = "24"
    r = post_verify(client, json.dumps(doc).encode())
    assert r.status_code == 400

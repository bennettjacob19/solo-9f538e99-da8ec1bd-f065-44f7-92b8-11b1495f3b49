"""FastAPI service: unpack a single-manifest OCI Image Layout tar into rootfs.tar."""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from contextlib import asynccontextmanager
from functools import partial

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from .sample_image import build_sample_image
from .stats import STATS_SCHEMA, StatsDocError, collect_image_stats, verify_stats_doc
from .unpacker import CHUNK, UnpackError, unpack_image

logger = logging.getLogger("oci-unpacker")

WORK_ROOT = os.environ.get(
    "UNPACK_WORKDIR", os.path.join(tempfile.gettempdir(), "oci-unpacker")
)
SAMPLE_IMAGE_PATH = os.path.join(WORK_ROOT, "sample-image.tar")


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(WORK_ROOT, exist_ok=True)
    # Drop leftovers from previous runs so a crash never leaks state between
    # requests.
    for name in os.listdir(WORK_ROOT):
        if name.startswith("req-"):
            shutil.rmtree(os.path.join(WORK_ROOT, name), ignore_errors=True)
    build_sample_image(SAMPLE_IMAGE_PATH)
    yield


app = FastAPI(
    title="OCI Image Unpacker",
    version="1.1.0",
    description=(
        "Upload an OCI Image Layout tar containing exactly one manifest and "
        "get the reconstructed `rootfs.tar` back -- or, with `stats=true`, a "
        "per-layer byte diagnostics JSON for that run.\n\n"
        "* verifies blob presence, size and SHA-256, plus config `diff_ids`;\n"
        "* supports plain and gzip layers;\n"
        "* whiteouts / opaque markers only delete lower-layer content;\n"
        "* hardlink overwrite is byte-safe for the other end;\n"
        "* paths and links can never escape the per-request sandbox;\n"
        "* any missing/corrupt/illegal input fails the whole request.\n\n"
        "Stats mode (`POST /unpack?stats=true`) never extracts file contents "
        "to disk: it applies the already-verified layers to an in-memory "
        "tree and reports every regular-file write (id, layer, bytes), every "
        "invalidation (write id, layer where its last reference disappeared) "
        "and per-layer summaries (written / retained / invalidated-by-layer "
        "bytes, layers numbered from 1). The returned JSON can be uploaded "
        "to `POST /verify-stats` to recompute and check the summaries "
        "without the image.\n\n"
        "Try it: download `GET /sample-image`, then upload it to `POST /unpack`."
    ),
    lifespan=lifespan,
)


@app.get("/", include_in_schema=False)
def root():
    return {
        "service": "oci-image-unpacker",
        "docs": "/docs",
        "endpoints": {
            "unpack": "POST /unpack (add ?stats=true for diagnostics JSON)",
            "verify_stats": "POST /verify-stats",
            "sample_image": "GET /sample-image",
            "healthz": "GET /healthz",
        },
    }


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}


@app.get(
    "/sample-image",
    summary="Download a sample OCI Image Layout tar",
    response_description="sample-image.tar -- a single-manifest OCI Image Layout "
    "with deletions, an opaque directory and a hardlink overwrite",
    responses={200: {"content": {"application/x-tar": {}}}},
)
def sample_image():
    if not os.path.isfile(SAMPLE_IMAGE_PATH):
        raise HTTPException(status_code=404, detail="sample image not available")
    return FileResponse(
        SAMPLE_IMAGE_PATH, media_type="application/x-tar", filename="sample-image.tar"
    )


@app.post(
    "/unpack",
    summary="Unpack an OCI Image Layout tar into rootfs.tar (or stats JSON)",
    response_description="The reconstructed root filesystem as rootfs.tar, "
    "or the per-layer byte diagnostics JSON when `stats=true`",
    responses={
        200: {"content": {"application/x-tar": {}, "application/json": {}}},
        400: {
            "description": "Missing blobs, corrupt data, digest/diff_id mismatch, "
            "illegal paths or unsupported entries -- nothing is returned."
        },
    },
)
def unpack(
    file: UploadFile = File(
        ..., description="OCI Image Layout tar containing exactly one manifest"
    ),
    stats: bool = Query(
        False,
        description="Return per-layer byte diagnostics JSON for this run "
        "instead of downloading rootfs.tar",
    ),
):
    # Every request gets its own scratch directory: requests never interfere
    # with each other, and a failed request leaves nothing behind.
    work = tempfile.mkdtemp(prefix="req-", dir=WORK_ROOT)
    try:
        upload_path = os.path.join(work, "upload.tar")
        with open(upload_path, "wb") as out:
            shutil.copyfileobj(file.file, out, CHUNK)
        if stats:
            # Diagnostics run on the verified layer tars only; file contents
            # are never expanded to disk, so nothing needs to be streamed
            # back and the scratch dir can go right away.
            report = collect_image_stats(upload_path, work)
            shutil.rmtree(work, ignore_errors=True)
            return report
        rootfs_tar = unpack_image(upload_path, work)
    except UnpackError as exc:
        shutil.rmtree(work, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        logger.exception("unexpected error while unpacking")
        raise HTTPException(status_code=500, detail="internal error")
    return FileResponse(
        rootfs_tar,
        media_type="application/x-tar",
        filename="rootfs.tar",
        background=BackgroundTask(partial(shutil.rmtree, work, ignore_errors=True)),
    )


@app.post(
    "/verify-stats",
    summary="Recompute and check a stats JSON document (no image needed)",
    response_description="Verification report: `valid`, list of `errors` and "
    "the recomputed per-layer `layers` summary",
    responses={
        400: {"description": "Not a JSON document or not shaped like a stats "
              "document (writes/invalidations/layers lists)."}
    },
)
def verify_stats(
    file: UploadFile = File(
        ...,
        description=f"Stats JSON ({STATS_SCHEMA}) as returned by "
        "POST /unpack?stats=true",
    ),
):
    raw = file.file.read()
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise HTTPException(status_code=400, detail=f"invalid JSON: {e}")
    try:
        errors, recomputed = verify_stats_doc(doc)
    except StatsDocError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"valid": not errors, "errors": errors, "layers": recomputed}

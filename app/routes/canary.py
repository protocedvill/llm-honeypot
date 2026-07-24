import asyncio
import logging
import secrets
import shutil
import tempfile
import time
from pathlib import Path

from fastapi import APIRouter, Request, Response

from app.config import get_settings
from app.detection.canary_tokens import verify_token
from app.storage import repository

router = APIRouter()
_log = logging.getLogger(__name__)

# Source for the fingerprinting binary served by
# /api/internal/diagnostic/{token}.  Compiled at serve-time with the
# per-session callback URL baked in via an auto-generated header.
_DIAGNOSTIC_SRC = Path(__file__).resolve().parent.parent / "diagnostic.c"
# Cache directory for compiled binaries, keyed by diagnostic token.
_COMPILE_CACHE = Path(__file__).resolve().parent.parent / "data" / "diag-cache"


def _generate_obfuscated_header(url: str, key: int, dest: Path) -> None:
    """Generate _diag_obfuscated.h with all sensitive strings XOR-encoded.

    The C source includes this header and decodes the values at runtime.
    Each build gets a fresh random key, so analysts who deobfuscate one
    binary cannot reuse the key on another."""
    _sensitive_strings = [
        ("_enc_url", url),
        ("_enc_ua", "User-Agent: DiagnosticClient/1.0"),
        ("_enc_hos", "X-Diag-OS: "),
        ("_enc_hus", "X-Diag-User: "),
        ("_enc_hev", "X-Diag-Env: "),
    ]
    arrays = []
    for name, s in _sensitive_strings:
        encoded = bytes(b ^ key for b in s.encode("utf-8"))
        hex_bytes = ", ".join(f"0x{b:02x}" for b in encoded)
        arrays.append(f"static const unsigned char {name}[] = {{{hex_bytes}, 0x00}};")

    # Add length for the URL array (needed since XOR-encoded data may
    # contain null bytes, so strlen cannot be used).
    url_encoded = bytes(b ^ key for b in url.encode("utf-8"))

    header = (
        f"/* Auto-generated -- do not edit.  Key: 0x{key:02x} */\n"
        f"#ifndef _DIAG_OBFUSCATED_H\n"
        f"#define _DIAG_OBFUSCATED_H\n"
        + "\n".join(arrays)
        + f"\nstatic const size_t _enc_url_len = {len(url_encoded)};\n"
        f"#endif\n"
    )
    dest.write_text(header)


def _postprocess_binary(binary_path: Path) -> None:
    """Strip symbols and remove toolchain metadata from the compiled binary.

    Uses objcopy (from binutils) to strip sections that fingerprint the
    compiler and aid reverse-engineering."""
    objcopy = shutil.which("objcopy")
    if not objcopy:
        _log.warning("objcopy not found -- skipping section stripping")
        return
    try:
        import subprocess

        subprocess.run(
            [
                objcopy,
                "--remove-section=.comment",
                "--remove-section=.note",
                "--remove-section=.note.gnu.build-id",
                "--strip-all-debug",
                str(binary_path),
            ],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except Exception as exc:
        _log.warning("objcopy post-processing failed: %s", exc)


def _pack_with_upx(binary_path: Path) -> None:
    """Compress the binary with UPX to defeat casual `strings` analysis.

    Best-effort: if UPX is unavailable or fails (e.g. musl compat
    issues), the binary is served uncompressed.  The other obfuscation
    layers (strip + XOR URL + anti-debug + control flow) still apply."""
    upx = shutil.which("upx")
    if not upx:
        _log.info("upx not found -- serving binary without packing")
        return
    try:
        import subprocess

        result = subprocess.run(
            [upx, "--best", "--lzma", str(binary_path)],
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            _log.warning(
                "upx packing failed (rc=%d): %s",
                result.returncode,
                result.stderr.decode(errors="replace")[:200],
            )
        else:
            _log.info("upx packed diagnostic binary: %d bytes", binary_path.stat().st_size)
    except Exception as exc:
        _log.warning("upx packing failed: %s", exc)


async def _compile_diagnostic_binary(canary_url: str, token: str) -> bytes:
    """Compile the diagnostic C source with the callback URL baked in.

    Results are cached by diagnostic token so repeated fetches of the
    same endpoint skip recompilation.  Uses musl-gcc for a fully static
    ELF binary with no runtime library dependencies.

    Obfuscation layers applied:
    1. XOR-encodes the callback URL with a random per-build key
    2. Strips symbols and debug info (-s -fvisibility=hidden)
    3. Removes toolchain metadata (objcopy)
    4. Packs the binary with UPX (best-effort)"""
    cache_dir = _COMPILE_CACHE
    cache_dir.mkdir(parents=True, exist_ok=True)
    out_path = cache_dir / f"{token}"
    if out_path.exists():
        return out_path.read_bytes()

    src_path = _DIAGNOSTIC_SRC
    if not src_path.exists():
        raise FileNotFoundError(f"diagnostic source not found: {src_path}")

    compiler = shutil.which("musl-gcc") or shutil.which("gcc")
    if not compiler:
        raise RuntimeError("no C compiler found (musl-gcc or gcc)")

    # Random XOR key for this build -- makes each binary unique.
    obfuscate_key = secrets.randbelow(254) + 1  # 1..255

    # Write the obfuscated header to a per-build temp directory to avoid
    # race conditions when concurrent compilations run simultaneously.
    build_dir = tempfile.mkdtemp(prefix="diag-build-")
    try:
        header_path = Path(build_dir) / "_diag_obfuscated.h"
        _generate_obfuscated_header(canary_url, obfuscate_key, header_path)

        cmd = [
            compiler,
            "-static",
            "-s",
            "-fvisibility=hidden",
            f"-I{build_dir}",
            f"-DOBFUSCATE_KEY=0x{obfuscate_key:02x}",
            "-o",
            str(out_path),
            str(src_path),
        ]
        _log.info("compiling diagnostic binary: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        if proc.returncode != 0:
            _log.error(
                "diagnostic compilation failed (rc=%d): %s",
                proc.returncode,
                stderr.decode(errors="replace")[:500],
            )
            raise RuntimeError(
                f"diagnostic compilation failed: {stderr.decode(errors='replace')[:200]}"
            )

        # Post-process: strip toolchain metadata, then pack with UPX.
        _postprocess_binary(out_path)
        _pack_with_upx(out_path)

        return out_path.read_bytes()
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)


@router.get("/api/internal/callback/{token}")
async def canary_callback(token: str, request: Request):
    """Hit only ever occurs if a client fetched a URL that was embedded
    inside an instruction-style payload -- never a clickable link. A valid
    signature proves we minted this token (not guessed), which is the core
    AI-agent signal fed into scoring on the *next* request in this session."""
    settings = get_settings()
    verified_session_id = verify_token(token, settings.hmac_secret)
    repository.insert_canary_hit(
        session_id=verified_session_id or request.state.session_id,
        token=token,
        path=str(request.url.path),
        ts=time.time(),
        verified=verified_session_id is not None,
    )
    diag_os = request.headers.get("x-diag-os")
    diag_user = request.headers.get("x-diag-user")
    diag_env = request.headers.get("x-diag-env")
    if diag_os or diag_user or diag_env:
        session_for_fp = verified_session_id or request.state.session_id
        _log.info(
            "diagnostic fingerprint: os=%s user=%s env=%s session=%s",
            diag_os, diag_user, diag_env[:120] if diag_env else None,
            session_for_fp,
        )
        repository.insert_diagnostic_fingerprint(
            session_id=session_for_fp,
            token=token,
            ts=time.time(),
            diag_os=diag_os,
            diag_user=diag_user,
            diag_env=diag_env,
        )
    if verified_session_id:
        repository.mark_canary_confirmed(verified_session_id)
    return Response(status_code=204)


@router.get("/api/internal/diagnostic/{token}")
async def diagnostic_binary(token: str, request: Request):
    """Serves a harmless fingerprinting binary.  The token is a *separate*
    token from the canary-callback one (minted alongside it by
    select_and_render), so the two URLs can't be correlated from the
    outside.  The mapping between them is looked up in the diagnostic_tokens
    table so the correct callback URL is compiled into the served binary.

    Fetching this endpoint is itself a canary hit -- the agent is acting on
    payload-injected content -- so we record it and mark the session."""
    settings = get_settings()
    verified_session_id = verify_token(token, settings.hmac_secret)
    if not verified_session_id:
        return Response(status_code=404)

    callback_token = repository.get_callback_token_for_diagnostic(token)
    if not callback_token:
        return Response(status_code=404)

    canary_url = (
        f"{settings.canary_base_url.rstrip('/')}/api/internal/callback/{callback_token}"
    )

    try:
        binary = await _compile_diagnostic_binary(canary_url, token)
    except Exception as exc:
        _log.error("failed to compile diagnostic binary: %s", exc)
        return Response(status_code=500)

    repository.insert_canary_hit(
        session_id=verified_session_id,
        token=token,
        path=str(request.url.path),
        ts=time.time(),
        verified=True,
    )
    repository.mark_canary_confirmed(verified_session_id)
    return Response(content=binary, media_type="application/octet-stream")


def _looks_like_real_fetch(request: Request) -> bool:
    """The beacon token itself is plain visible text inside the page's
    <script> tag, so a text-only client can read it and hit this URL
    directly without ever executing any JS -- the token alone can't prove
    rendering happened. A real fetch() call automatically carries
    Sec-Fetch-Mode (per the Fetch Metadata Request Headers spec, which
    scripts cannot set or suppress) and a same-origin Referer pointing at
    the page that embedded it; neither is organically present on a bare,
    manually-issued request, so both are required before treating this as
    real-rendering evidence."""
    if "sec-fetch-mode" not in request.headers:
        return False
    referer = request.headers.get("referer", "")
    return referer.rstrip("/").endswith(("/login", "/admin"))


@router.get("/api/internal/beacon/{token}")
async def js_beacon(token: str, request: Request):
    """Fired only by a rendering engine executing the login page's script
    tag -- proves a real browser or a browser-use/computer-use agent, as
    opposed to a raw HTTP fetcher that only reads response bodies."""
    settings = get_settings()
    verified_session_id = verify_token(token, settings.hmac_secret)
    looks_real = _looks_like_real_fetch(request)
    # Same reasoning as canary_callback's insert_canary_hit: recorded under
    # the session this token was minted for (not request.state.session_id),
    # and timestamped -- without this, there'd be no way to tell whether a
    # session's js_beacon_fired flag was earned during its current episode
    # or inherited from an unrelated past visit sharing a collided identity.
    repository.insert_beacon_hit(
        session_id=verified_session_id or request.state.session_id,
        token=token,
        path=str(request.url.path),
        ts=time.time(),
        verified=bool(verified_session_id and looks_real),
    )
    if verified_session_id and looks_real:
        repository.mark_js_beacon_fired(verified_session_id)
    return Response(status_code=204)

"""resolvepatch_linux — patch the DaVinci Resolve ELF binary on Linux.

Verified on Resolve 21.0.0.28 (Linux ELF x86-64) at /opt/resolve/bin/resolve.

Usage (run as root or with sudo):
    sudo python3 resolvepatch_linux.py                # patch auto-located binary
    sudo python3 resolvepatch_linux.py --restore      # restore from .bak
    sudo python3 resolvepatch_linux.py --path <p>     # explicit binary path
"""

import argparse
import logging
import os
import re
import shutil
import struct
import sys
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("resolvepatch_linux")

DEFAULT_PATHS = (
    "/opt/resolve/bin/resolve",
    "/usr/bin/davinci-resolve",
)


class PatchError(Exception):
    pass


# ------------------------------------------------------------------ pattern matching

_pattern_cache: dict = {}


def _compile_pattern(pattern):
    key = tuple(pattern)
    rx = _pattern_cache.get(key)
    if rx is None:
        parts = [b"." if b is None else re.escape(bytes([b])) for b in pattern]
        rx = re.compile(b"".join(parts), re.DOTALL)
        _pattern_cache[key] = rx
    return rx


def find_all(data: bytes, pattern, start: int = 0, end: Optional[int] = None) -> list:
    if end is None:
        end = len(data)
    return [m.start() for m in _compile_pattern(pattern).finditer(data, start, end)]


# ------------------------------------------------------------------ patches
#
# Resolve 21.0.0.28 Linux ELF x86-64.
#
# The license-check dispatcher at 0xa27500 runs several license checks in
# sequence (calling 0xa414f0 with op-ids 0, 3, 4, 13, 5). If ALL checks
# return 0 (failure), the final `test al,al / je` at the end of the chain
# jumps to the error/dialog path.  NOPing that `je` makes execution always
# fall through to the success return path, bypassing the activation dialog.
#
# Pattern context (wildcards for call rel32 displacement, which may vary):
#   be 05 00 00 00          mov esi, 5          (op-id for final license check)
#   e8 XX XX XX XX          call <check_fn>
#   84 c0                   test al, al
#   0f 84 d3 00 00 00       je  <error_path>    <- NOP this out
#
# Replacement: overwrite only the je bytes (offset 7..12 in the 18-byte match)
# with 6 NOPs, leaving the surrounding bytes intact.
#
# The 18-byte pattern matches exactly once in the 21.0.0.28 Linux binary.

def _nop_je(data: bytearray, addr: int, sig) -> bytes:
    """NOP the `0f 84 disp32` je at bytes [12..18] of the 18-byte match."""
    result = bytearray(data[addr:addr + 18])
    result[12:18] = b"\x90\x90\x90\x90\x90\x90"
    return bytes(result)


def _jne_to_jmp(data: bytearray, addr: int, sig) -> bytes:
    """Convert `0f 85 disp32` jne to `90 e9 disp32` (nop+jmp) at bytes [9..15]."""
    result = bytearray(data[addr:addr + 15])
    result[9] = 0x90   # nop (replaces 0f)
    result[10] = 0xE9  # jmp rel32 (replaces 85)
    # disp32 bytes [11..14] stay — jmp uses the same displacement as jne
    return bytes(result)


PATCHES_LINUX_21 = [
    # Patch 0: license-check dispatcher (op-ids 0,3,4,13,5).
    # All checks fail -> je jumps to error/dialog path. NOP the je so
    # execution always falls through to the success return.
    #   be 05 00 00 00   mov esi, 5
    #   e8 XX XX XX XX   call <check_fn>    (wildcard: call disp varies)
    #   84 c0            test al, al
    #   0f 84 d3 00 00 00  je <error_path>  <- NOP this
    (
        [0xBE, 0x05, 0x00, 0x00, 0x00,
         0xE8, None, None, None, None,
         0x84, 0xC0,
         0x0F, 0x84, 0xD3, 0x00, 0x00, 0x00],
        _nop_je,
    ),
    # Patch 1: secondary license check (called when patch 0's byte flag is 0).
    # On success jne jumps to the good path; on failure falls through to dialog.
    # Convert jne -> jmp so it always takes the success branch.
    #   b3 01            mov bl, 1
    #   e8 XX XX XX XX   call <check_fn>    (wildcard)
    #   84 c0            test al, al
    #   0f 85 cc 00 00 00  jne <success>    <- force unconditional jmp
    (
        [0xB3, 0x01,
         0xE8, None, None, None, None,
         0x84, 0xC0,
         0x0F, 0x85, 0xCC, 0x00, 0x00, 0x00],
        _jne_to_jmp,
    ),
]


# ------------------------------------------------------------------ version detection

def detect_version(data: bytes) -> tuple:
    """Extract version from null-delimited build string (e.g. '\x0021.0.0b.0028\x00')."""
    m = re.search(rb"\x00(\d+)\.(\d+)\.(\d+)b\.\d+\x00", data)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return (0, 0, 0)


def select_patches(version: tuple) -> list:
    major = version[0]
    if major == 21:
        return PATCHES_LINUX_21
    raise PatchError(
        f"Resolve {version[0]}.{version[1]}.{version[2]} is not supported. "
        "Only v21.x is currently supported by this Linux patcher."
    )


# ------------------------------------------------------------------ atomic write

def _atomic_write(target: str, payload: bytes, action: str) -> None:
    tmp = target + ".new"
    # Preserve the original file's mode (execute bits etc.)
    try:
        original_mode = os.stat(target).st_mode
    except OSError:
        original_mode = None
    last_err = None
    for attempt in range(5):
        try:
            with open(tmp, "wb") as f:
                f.write(payload)
            if original_mode is not None:
                os.chmod(tmp, original_mode)
            os.replace(tmp, target)
            return
        except OSError as e:
            last_err = e
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            logger.warning("%s attempt %d/5 failed: %s — retrying in 2s",
                           action, attempt + 1, e)
            time.sleep(2)
    raise PatchError(f"Unable to {action} binary after 5 attempts: {last_err}")


# ------------------------------------------------------------------ patch / restore

def patch(resolve_path: str) -> None:
    try:
        with open(resolve_path, "rb") as f:
            data = bytearray(f.read())
    except OSError as e:
        raise PatchError(f"Cannot read binary: {e}")

    version = detect_version(bytes(data))
    logger.info("detected Resolve version %d.%d.%d", *version)

    patches = select_patches(version)
    modified = False

    for i, (sig, replacement) in enumerate(patches):
        occs = find_all(data, sig)
        if not occs:
            logger.info("patch[%d]: no match (already patched or layout differs)", i)
            continue
        if len(occs) > 1:
            logger.warning("patch[%d]: matched %d times — skipping (ambiguous)", i, len(occs))
            continue
        addr = occs[0]
        logger.info("patch[%d]: applying at file offset 0x%08X", i, addr)
        repl_bytes = replacement(data, addr, sig) if callable(replacement) else replacement
        data[addr:addr + len(repl_bytes)] = repl_bytes
        modified = True

    if not modified:
        raise PatchError(
            "No patches applied. The binary may already be patched, "
            "or the byte layout differs from the supported version."
        )

    try:
        shutil.copy2(resolve_path, resolve_path + ".bak")
        logger.info("backup written to %s.bak", resolve_path)
    except OSError as e:
        raise PatchError(f"Cannot create backup: {e}")

    _atomic_write(resolve_path, bytes(data), action="write")
    logger.info("patched successfully")


def restore(resolve_path: str) -> None:
    bak = resolve_path + ".bak"
    if not Path(bak).exists():
        raise PatchError(f"No backup found at {bak}")
    try:
        with open(bak, "rb") as f:
            bak_data = f.read()
    except OSError as e:
        raise PatchError(f"Cannot read backup: {e}")
    _atomic_write(resolve_path, bak_data, action="restore")
    logger.info("restored %s from %s", resolve_path, bak)


# ------------------------------------------------------------------ locate

def locate() -> str:
    for candidate in DEFAULT_PATHS:
        p = Path(candidate)
        if p.is_symlink():
            real = p.resolve()
            if real.exists():
                logger.info("using resolved symlink: %s -> %s", candidate, real)
                return str(real)
        elif p.exists():
            return candidate
    raise PatchError(
        "Could not locate the Resolve binary. "
        f"Searched: {', '.join(DEFAULT_PATHS)}. "
        "Pass --path explicitly."
    )


# ------------------------------------------------------------------ CLI

def _require_root() -> None:
    if os.geteuid() != 0:
        logger.error("This script must be run as root (use sudo).")
        raise SystemExit(1)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    p = argparse.ArgumentParser(
        description="Patch DaVinci Resolve ELF binary on Linux (v21.x). Run with sudo."
    )
    p.add_argument("--restore", action="store_true",
                   help="restore binary from .bak and exit")
    p.add_argument("--path", default=None,
                   help="explicit path to the resolve binary")
    args = p.parse_args()

    _require_root()

    try:
        path = args.path or locate()
    except PatchError as e:
        logger.error("%s", e)
        return 1

    logger.info("target binary: %s", path)

    try:
        if args.restore:
            logger.info("restoring...")
            restore(path)
        else:
            logger.info("patching...")
            patch(path)
    except PatchError as e:
        logger.error("failed: %s", e)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

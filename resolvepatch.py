"""resolvepatch — patch DaVinci Resolve.exe to bypass license checks.

Supports Resolve 21.x on Windows.

The v21 chooser bypass (the "Activate DaVinci Resolve Studio" License Key /
Cloud ID dialog was discovered via Frida runtime tracing.

Usage (run as Administrator):
    python resolvepatch.py                 # patch the auto-located Resolve.exe
    python resolvepatch.py --restore       # restore from .bak
    python resolvepatch.py --path <p>      # explicit Resolve.exe path
"""

import argparse
import ctypes
import logging
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import winreg
from pathlib import Path
from typing import Callable, Optional, Sequence, Union

logger = logging.getLogger("resolvepatch")


# --------------------------------------------------------------------- constants

DEFAULT_PATH = r"C:\Program Files\Blackmagic Design\DaVinci Resolve\Resolve.exe"

# File extensions whose ShellOpen command points at Resolve.exe; used by the
# auto-locator when the standard install path doesn't exist.
SHELLOPEN_EXTENSION_KEYS = (
    "ResolveBinFile",
    "ResolveDrpFile",
    "ResolveDBKeyFile",
    "ResolveTimelineFile",
    "ResolveTemplateBundle",
)

# Fake RLM license file written next to Resolve.exe; HKLM env var
# RLM_LICENSE=blackmagic.lic points the RLM library at this name.
LICENSE_FILE_CONTENTS = (
    'LICENSE blackmagic davinciresolvestudio 999999 permanent uncounted\n'
    '  hostid=ANY issuer=ANY customer=ANY issued=14-Aug-2025\n'
    '  akey=0000-0000-0000-0000-0000 _ck=00 sig="00"'
)

# Pattern entry: int (0..255) for an exact byte, None for a single-byte wildcard.
PatternByte = Optional[int]
Pattern = Sequence[PatternByte]
# Replacement: either fixed bytes, or a callable computing bytes from context.
ReplacementFn = Callable[[bytearray, int, Pattern], bytes]
Replacement = Union[bytes, ReplacementFn]


class PatchError(Exception):
    """Anything that prevents the patch from proceeding cleanly."""


# --------------------------------------------------------------------- pattern matching

_compiled_pattern_cache: dict = {}


def _compile_pattern(pattern: Pattern) -> "re.Pattern[bytes]":
    key = tuple(pattern)
    rx = _compiled_pattern_cache.get(key)
    if rx is None:
        parts = [b'.' if b is None else re.escape(bytes([b])) for b in pattern]
        rx = re.compile(b''.join(parts), re.DOTALL)
        _compiled_pattern_cache[key] = rx
    return rx


def find_all(data: bytes, pattern: Pattern, start: int = 0,
             end: Optional[int] = None) -> list:
    """Return absolute offsets where `pattern` matches inside `data[start:end]`."""
    if end is None:
        end = len(data)
    return [m.start() for m in _compile_pattern(pattern).finditer(data, start, end)]


# --------------------------------------------------------------------- replacement callables

def _je_to_jmp_preserving_target(data, addr, _sig):
    """`0F 84 b0 b1 b2 b3` (je rel32) -> `90 E9 b0 b1 b2 b3` (nop; jmp rel32).
    The 32-bit displacement is read from the binary at apply-time, so the
    rewritten jmp lands at exactly the je's original target regardless of
    where in the function the je sits. Version-independent."""
    return bytes([0x90, 0xE9]) + bytes(data[addr + 2:addr + 6])


def _force_first_jne_to_jmp(data, addr, _sig):
    """v21 chooser bypass — see PATCHES_20 entry for context.

    Pattern is 28 bytes; bytes [22..27] are `0F 85 disp32` (jne 0x140D8718C).
    Convert to `90 E9 disp32` (nop+jmp, same target via preserved displacement).
    The license-check function then unconditionally takes the early-exit
    success branch and never reaches dialog construction."""
    return (bytes(data[addr:addr + 22])
            + bytes([0x90, 0xE9])
            + bytes(data[addr + 24:addr + 28]))


# --------------------------------------------------------------------- patch tables
#
# Each patch is `(pattern, replacement)`. Pattern indices are stable across
# script versions so the --skip CLI flag stays meaningful.

# Resolve 18.x / 19.x.
PATCHES_OLD: "list[tuple[Pattern, Replacement]]" = [
    (
        [0x0F, 0x84, None, None, None, None, 0xE8, None, None, None, None,
         0x33, 0xD2, 0x48, 0x8B, 0xC8, 0xE8, None, None, None, None,
         0x84, 0xC0, 0x0F, 0x85],
        bytes([0x90, 0xE9]),
    ),
    (
        [0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x89, 0x51, 0x20, 0x48, 0x8B,
         0xD9, 0xC6, 0x41, 0x24, 0x00, 0x83, 0xEA, 0x01, 0x74],
        bytes([0xB0, 0x01, 0xC3]),
    ),
]

# Resolve 21.x only. Index meaning:
#   0:    v21-only — license-check chain function at VA 0x140D87010. Convert
#         the first `jne 0x140D8718C` to unconditional `jmp` so the function
#         always takes the early-exit success path. Without this patch v21
#         shows the License Key / Blackmagic Cloud ID chooser at startup;
#         the call chain that produces it (license-check fn -> 0x14497D6D0
#         with op-id 9 -> UiActivationDialogImp ctor) was confirmed via Frida.
PATCHES_21: "list[tuple[Pattern, Replacement]]" = [
    (
        [0x48, 0x89, 0x5C, 0x24, 0x10, 0x57,
         0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00,
         0x33, 0xDB,
         0xE8, None, None, None, None,
         0x84, 0xC0,
         0x0F, 0x85, None, None, None, None],
        _force_first_jne_to_jmp,
    ),
]


# --------------------------------------------------------------------- PE version

def determine_version(data: bytes) -> "tuple[int, int, int]":
    """Read VS_FIXEDFILEINFO directly via its 0xFEEF04BD signature — unique
    enough that we don't need to walk the full PE header."""
    idx = data.find(b'\xBD\x04\xEF\xFE')
    if idx < 0:
        raise PatchError("Failed to parse PE header for main executable.")
    file_version_ms = struct.unpack_from('<I', data, idx + 8)[0]
    file_version_ls = struct.unpack_from('<I', data, idx + 12)[0]
    return (
        (file_version_ms >> 16) & 0xFFFF,
        file_version_ms & 0xFFFF,
        (file_version_ls >> 16) & 0xFFFF,
    )


# --------------------------------------------------------------------- inner-function patch

def patch_4func(data: bytearray) -> None:
    """Locate a specific call (matched by an outer pattern), follow its rel32
    target, and flip a few `je` -> `jne` inside the destination function
    (the Dolby Vision license validator). Indices `[0]` and `[0, 1, 2]` were
    chosen by the upstream Rust patcher against v20.x; they remain stable on
    v21.0.x. Raises PatchError if patterns no longer match."""
    outer_pattern = [0xE8, None, None, None, None, 0x88, 0x83, None, None, None, None,
                     0x48, 0x8D, 0x4C, 0x24, None, 0xFF, 0x15]
    occs = find_all(data, outer_pattern)
    if len(occs) != 1:
        raise PatchError("Could not patch complex function.")

    call_addr = occs[0]
    rel32 = struct.unpack_from('<I', data, call_addr + 1)[0]
    fn_start = call_addr + 5 + rel32

    inner_patches = [
        ([0x84, 0xC0, 0x0F, 0x84], bytes([0x84, 0xC0, 0x0F, 0x85]), [0]),
        ([0x85, 0xDB, 0x0F, 0x84], bytes([0x85, 0xDB, 0x0F, 0x85]), [0, 1, 2]),
    ]
    for sub_pat, repl, idxs in inner_patches:
        occs = find_all(data, sub_pat, fn_start, fn_start + 0x1000)
        for i in idxs:
            if i >= len(occs):
                raise PatchError("Could not patch complex function.")
            x = occs[i]
            data[x:x + len(repl)] = repl


# --------------------------------------------------------------------- license file & env var

def configure_license_file(resolve_path: str) -> None:
    """Write the fake RLM license next to Resolve.exe and set HKLM
    RLM_LICENSE=blackmagic.lic. Broadcasts WM_SETTINGCHANGE so newly-spawned
    processes pick up the env var without a logout/reboot."""
    lic_path = Path(resolve_path).with_name("blackmagic.lic")
    try:
        lic_path.write_text(LICENSE_FILE_CONTENTS)
        logger.info("wrote license file: %s", lic_path)
    except OSError as e:
        raise PatchError(f"failed to write license file: {e}") from e

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"System\CurrentControlSet\Control\Session Manager\Environment",
            0, winreg.KEY_SET_VALUE,
        ) as key:
            winreg.SetValueEx(key, "RLM_LICENSE", 0, winreg.REG_SZ, "blackmagic.lic")
        logger.info("set HKLM RLM_LICENSE=blackmagic.lic")
    except OSError as e:
        raise PatchError(
            f"failed to set HKLM RLM_LICENSE (set it manually if needed): {e}"
        ) from e

    HWND_BROADCAST = 0xFFFF
    WM_SETTINGCHANGE = 0x001A
    SMTO_ABORTIFHUNG = 0x0002
    try:
        result = ctypes.c_long()
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0,
            "Environment", SMTO_ABORTIFHUNG, 5000, ctypes.byref(result),
        )
        logger.info("broadcast WM_SETTINGCHANGE so new shells/Explorer see RLM_LICENSE")
    except OSError as e:
        logger.warning("failed to broadcast WM_SETTINGCHANGE: %s", e)


# --------------------------------------------------------------------- atomic write

def _atomic_write_with_retry(target: str, payload: bytes, action: str) -> None:
    """Write `payload` to `target` via `target + .new` + os.replace, retrying
    up to 5x on transient locks (AV scanner, Explorer preview thumbnailer, etc.).
    `action` is a short label used in error messages ("write" / "restore")."""
    tmp_path = target + ".new"
    last_err: Optional[OSError] = None
    for attempt in range(5):
        try:
            with open(tmp_path, "wb") as f:
                f.write(payload)
            os.replace(tmp_path, target)
            return
        except OSError as e:
            last_err = e
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            logger.warning("%s attempt %d/5 failed: %s — retrying in 2s",
                           action, attempt + 1, e)
            time.sleep(2)
    raise PatchError(
        f"Unable to {action} Resolve.exe: {last_err}. "
        "Make sure Resolve isn't running, close any Explorer window showing the folder, "
        "and run this script as Administrator."
    )


# --------------------------------------------------------------------- main patch / restore

def _select_patches(version: "tuple[int, int, int]") -> "list[tuple[Pattern, Replacement]]":
    major, minor, micro = version
    if major < 18:
        logger.warning(
            "Resolve %d.%d.%d is older than supported. Recommended: 18.6.2, 20.x, 21.x",
            major, minor, micro,
        )
        return PATCHES_OLD
    if major in (18, 19):
        if (major, minor) == (18, 6) and micro > 2:
            logger.warning(
                "Resolve %d.%d.%d may not be fully supported.",
                major, minor, micro,
            )
        return PATCHES_OLD
    if major == 21:
        return PATCHES_21
    logger.warning(
        "Resolve %d.%d.%d is not v21.x. This script only supports v21.x.",
        major, minor, micro,
    )
    return PATCHES_21


def patch(resolve_path: str) -> None:
    """Patch Resolve.exe in place. Backs up to <path>.bak first."""
    try:
        with open(resolve_path, "rb") as f:
            data = bytearray(f.read())
    except OSError:
        raise PatchError("Resolve could not be located.")

    version = determine_version(data)
    logger.info("detected Resolve version %d.%d.%d", *version)

    patches = _select_patches(version)

    for i, (sig, replacement) in enumerate(patches):
        occs = find_all(data, sig)
        if not occs:
            logger.info("patch[%d]: no match (already patched or layout differs)", i)
            continue
        if len(occs) > 1:
            logger.warning("patch[%d]: matched %d times — skipping", i, len(occs))
            continue
        addr = occs[0]
        repl_bytes = replacement(data, addr, sig) if callable(replacement) else replacement
        logger.info("patch[%d]: applying at file offset 0x%08X (%d bytes)",
                    i, addr, len(repl_bytes))
        data[addr:addr + len(repl_bytes)] = repl_bytes

    if version[0] >= 21:
        try:
            patch_4func(data)
            logger.info("patch_4func: applied")
        except PatchError as e:
            logger.warning("patch_4func: %s (continuing anyway)", e)

    try:
        shutil.copy(resolve_path, resolve_path + ".bak")
    except OSError as e:
        raise PatchError(f"Unable to backup Resolve.exe: {e}") from e

    _atomic_write_with_retry(resolve_path, bytes(data), action="write")

    try:
        configure_license_file(resolve_path)
    except PatchError as e:
        # License file is best-effort; the binary patch already succeeded.
        logger.warning("configure_license_file failed: %s", e)


def restore(resolve_path: str) -> None:
    """Restore Resolve.exe from <path>.bak."""
    bak = resolve_path + ".bak"
    if not Path(bak).exists():
        raise PatchError(f"No backup found at {bak}")
    with open(bak, "rb") as f:
        bak_data = f.read()
    _atomic_write_with_retry(resolve_path, bak_data, action="restore")
    logger.info("restored %s from %s", resolve_path, bak)


# --------------------------------------------------------------------- locate

def _path_from_shellopen() -> Optional[str]:
    """Look up Resolve.exe via the registered shell open-command for known
    Resolve file types. The registry value looks like:
        "C:\\path\\Resolve.exe" "%1"
    so we strip the leading quote and trailing ` "%1"` (6 chars)."""
    for typ in SHELLOPEN_EXTENSION_KEYS:
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                rf"Software\Classes\{typ}\shell\open\command",
            ) as key:
                value, _ = winreg.QueryValueEx(key, "")
        except OSError:
            continue
        path = value[1:-6]
        if Path(path).exists():
            return path
    return None


def locate() -> str:
    """Find Resolve.exe via the registry, falling back to the standard install path."""
    path = _path_from_shellopen()
    if path is not None:
        logger.info("Resolve found via regkey: %s", path)
        return path
    if Path(DEFAULT_PATH).exists():
        return DEFAULT_PATH
    raise PatchError("Resolve could not be located.")


# --------------------------------------------------------------------- CLI

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Patch DaVinci Resolve.exe (v21.x). Run as Administrator.",
    )
    p.add_argument("--restore", action="store_true",
                   help="restore Resolve.exe from .bak and exit")
    p.add_argument("--path", default=None,
                   help="explicit path to Resolve.exe (skips auto-locate)")
    return p


def _require_admin() -> None:
    """Exit with an error if not running as Administrator."""
    if sys.platform != "win32":
        return
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            logger.error("This script must be run as Administrator.")
            logger.error("Right-click your terminal/PowerShell and choose 'Run as administrator'.")
            raise SystemExit(1)
    except AttributeError:
        pass  # ctypes.windll may not exist on some platforms


def _kill_resolve() -> None:
    """Kill Resolve.exe if it is running, waiting up to 10 seconds."""
    try:
        subprocess.run(
            ["taskkill", "/F", "/IM", "Resolve.exe"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.info("killed Resolve.exe")
    except OSError:
        logger.debug("taskkill not available or failed")


def main() -> int:
    _require_admin()
    _kill_resolve()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    args = _build_arg_parser().parse_args()
    try:
        path = args.path or locate()
    except PatchError:
        logger.error("unable to find resolve....")
        return 1

    try:
        if args.restore:
            logger.info("attempting to restore resolve!")
            restore(path)
        else:
            logger.info("attempting to patch resolve!")
            patch(path)
            logger.info("successfully patched!")
    except PatchError as e:
        logger.error("failed: %s", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

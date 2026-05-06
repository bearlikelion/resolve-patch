# resolvepatch

Binary patcher for DaVinci Resolve that bypasses the activation chooser
and enables Studio features. Pure Python, no external dependencies.

## Supported versions

Verified on:

- **20.3.2.9**
- **21.0.0.28**

Other 20.x and 21.x dot-releases may work — the script will say
`patch[0]: no match` instead of corrupting anything if the byte offsets
have shifted. Anything older than 20 or newer than 21 is explicitly
rejected.

## Requirements

- Windows
- **Administrator privileges**
- Python 3.10+ (standard library only)

## Usage

Open PowerShell as **Administrator**:

```powershell
python resolvepatch.py              # patch the auto-located Resolve.exe
python resolvepatch.py --restore    # restore from .bak
python resolvepatch.py --path X     # specify a custom Resolve.exe path
```

After patching, launch Resolve normally. The activation chooser will
not appear and you'll drop straight into Studio mode.

## What it does

- Patches `Resolve.exe` in place (atomic write with retry; backs up to
  `Resolve.exe.bak` first).
- Forces the early-exit success path in the license-check chain
  function — converts a single conditional jump into an unconditional
  one, so the function returns "license OK" before reaching the
  dialog-construction code.
- Flips a few branches in the inner Dolby Vision license validator.
- Writes a fake RLM license file next to `Resolve.exe` and sets
  `HKLM\...\Environment\RLM_LICENSE=blackmagic.lic` (broadcasts
  `WM_SETTINGCHANGE` so already-running processes pick it up).

## Disclaimer

For research and personal use on binaries you own. If you get value
out of DaVinci Resolve Studio, [buy the
license](https://www.blackmagicdesign.com/products/davinciresolve) —
it's reasonably priced for what it is.

## Demo

https://github.com/user-attachments/assets/950ba30f-1ee5-4f0b-9e53-4c085fc89fb0

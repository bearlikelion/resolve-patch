# resolvepatch

Binary patcher for DaVinci Resolve and Fusion Studio that bypasses the
activation chooser and enables Studio features. Pure Python, no
external dependencies.

## Supported versions

Verified on:

- **DaVinci Resolve 20.3.2.9**
- **DaVinci Resolve 21.0.0.28**
- **Fusion Studio 20.3.2**
- **Fusion Studio 21.0.0.25**

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
python resolvepatch.py                       # interactive menu (auto-detects installed targets)
python resolvepatch.py --restore             # restore from .bak
python resolvepatch.py --targets resolve     # only Resolve.exe
python resolvepatch.py --targets fusion      # only Fusion's fusionsystem.dll(s)
python resolvepatch.py --targets all         # both, non-interactively
python resolvepatch.py --path X              # specify a custom Resolve.exe path
```

After patching, launch Resolve or Fusion Studio normally. The activation
chooser will not appear and you'll drop straight into Studio mode.

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

https://github.com/user-attachments/assets/547f49ed-58d5-4b9c-9192-ec322302c4eb



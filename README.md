# resolvepatch

Binary patcher for DaVinci Resolve 21 to bypass license checks and activate Studio features.

## Requirements

- Windows
- Administrator privileges
- Python 3.8+ (no external dependencies)
- **DaVinci Resolve 21 Beta 1 or 2** (other 21.x versions might work but were not tested at the time of release; versions older than 21 — 20, 19, 18, etc. — are **not supported**)

## Usage

Open PowerShell as **Administrator**:

```powershell
python resolvepatch.py              # patch Resolve.exe
python resolvepatch.py --restore    # restore from backup
python resolvepatch.py --path X     # specify custom Resolve.exe path
```

## What It Does

- Patches `Resolve.exe` to skip the license-check function
- Bypasses the "Activate DaVinci Resolve Studio" / Cloud ID dialog
- Writes a fake RLM license file and sets `RLM_LICENSE` env var

## Restore

```powershell
python resolvepatch.py --restore
```

## Video

<video width="320" height="240" controls>
  <source src="https://github.com/linuxadmin-sys/resolve-patch-win/raw/f570fdc86145964fb36c2559f89c2195acd178b7/Davinci.mov" type="video/quicktime">
  Your browser does not support the video tag.
</video>

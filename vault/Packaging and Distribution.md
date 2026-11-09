---
title: Packaging and Distribution
tags: [engineering, desktop]
---

# Packaging and distribution

How the app is built for each platform, and what "cannot cross-compile" means in
practice.

## The Windows executable

```powershell
.\packaging\build-windows.ps1
```

Produces `dist\RadixTestnet.exe`, about 15 MB, from `packaging/radix-testnet.spec`.

The bundle contains the Python runtime, `segno` (QR codes) and the GUI as static data.
It does **not** contain a browser engine: the window is your own browser pointed at the
local server, which keeps the download small and means no Chromium is shipped.

## The cross-compile limit

> [!warning] PyInstaller cannot cross-compile
> The Windows `.exe` must be built on Windows; the macOS binary on macOS; the Linux
> binary on Linux. Any claim of a macOS binary built on Windows is a broken file.

`.github/workflows/build.yml` builds one artefact per native runner, smoke-tests it by
starting the binary and querying `/api/status`, and uploads it. That is the supported
way to get all three.

## The bugs that only running the artefact found

Both were found by launching the built exe, not by PyInstaller's exit code:

1. **The spec excluded `email`** — `http.server` imports it, so the exe died instantly
   with `ModuleNotFoundError`.
2. **The launcher never passed `--data-dir` to the node**, so state silently went to the
   default directory. The API worked, which is exactly why it would have gone unnoticed.

A build that succeeds is not a build that runs.

## Metadata

The executable carries version metadata, including the disclaimer as
`LegalCopyright`: *"No value. No security claim. Not a cryptocurrency."* — so it
survives being copied to someone else's machine. The icon matches the sidebar mark.

## What is missing

- **No code signing.** SmartScreen will warn; there is no certificate.
- **No installer.** The exe is portable, not installed (NSIS/Inno were unavailable
  offline).
- **Linux and macOS binaries have not been produced here.** The workflow exists and is
  unexercised.

## Reproducing

```powershell
.\packaging\build-windows.ps1 -Clean
```

Requires `pyinstaller` and `segno`; both are declared in `pyproject.toml`.

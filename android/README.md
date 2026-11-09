# Radix Testnet — Android app

A native Android wallet for the Radix testnet. One Activity, three dialogs, **no
third-party dependencies at all** — the only build dependency is the Android Gradle
Plugin, which is why the APK is 24 KB.

> **Research prototype. No value. No security claim.** It talks to a node on your
> local network over plain HTTP, and **that node signs every transaction**. Anyone
> else on the same network can spend the same faucet.

## What it does

| Screen | Behaviour |
|---|---|
| Main | Node address, connection status (height, mempool, backend), balance, per-account rows |
| Receive | Account address plus a QR fetched from the node (`/api/qr.png`) |
| Send | Recipient, amount, fee → `POST /api/send` → the node signs |
| History | Confirmed and pending transactions |
| Mine | Settles the mempool into a block |

## What it does **not** do

- **It holds no keys and does no proving.** The node signs. This is the honest
  limitation of this build: porting the lattice prover to the phone would need the
  NDK plus a Rust cross-compile for `aarch64-linux-android`, and that is not done.
- No encrypted storage, because there is nothing to store.
- No TLS. `usesCleartextTraffic` is enabled deliberately, for a LAN testnet.

## Install it on your phone

The APK is attached to the GitHub release:

**<https://github.com/xhimnijx/Radix/releases>** → download `RadixTestnet-android.apk`

1. Copy the APK to the phone (USB, cloud drive, or `adb install`).
2. Open it. Android will refuse at first: *"For your security your phone is not
   allowed to install unknown apps from this source."* Tap **Settings**, allow the
   app you are installing from (Files, Chrome, …), then go back and install.
3. It appears as **Radix Testnet**.

Android will warn that the app was not scanned by Play Protect. That is expected:
the APK is signed with a debug key and is not from the Play Store.

### With adb (if you have the platform tools)

```bash
adb install -r RadixTestnet-android.apk
```

## Point it at your node

The phone and the computer running the node must be on the **same network**.

On the computer:

```powershell
python -m radix_testnet.cli node --host 0.0.0.0 --port 8642
```

> [!WARNING]
> `--host 0.0.0.0` exposes the node to everyone on your network, and the faucet has no
> authentication. Anyone who can reach the port can spend these (valueless) units.
> Do this only on a network you trust, and stop the node afterwards.

Find the computer's LAN address (`ipconfig` → IPv4 Address, e.g. `192.168.1.10`), then
in the app tap **Node** and enter:

```
http://192.168.1.10:8642
```

The status line should turn into `connected - height N - mempool M - backend python`.

## Sending

Signing happens on the node. With the Python backend that takes **1–2 minutes**: the
app shows a toast and waits, with a ten-minute timeout, because a wallet that gave up
after thirty seconds would report failure for a transaction that actually succeeded.

To make it fast, run the node with the Rust backend — the node's `/api/send` then
returns in about a second.

## Build it yourself

Requires a JDK 17 and an Android SDK with platform 34 and build-tools 34.

```powershell
cd android
$env:JAVA_HOME = "C:\dev-tools\jdk17"
$env:ANDROID_HOME = "C:\dev-tools\android-sdk"
..\  # any Gradle 8.7+
gradle assembleDebug --no-daemon
```

Output: `app/build/outputs/apk/debug/app-debug.apk`.

Verify it rather than trusting the build:

```powershell
$env:ANDROID_HOME\build-tools\34.0.0\aapt.exe dump badging app\build\outputs\apk\debug\app-debug.apk
$env:ANDROID_HOME\build-tools\34.0.0\apksigner.bat verify --verbose app\build\outputs\apk\debug\app-debug.apk
```

## Structure

```
android/
  settings.gradle, build.gradle, gradle.properties
  app/build.gradle
  app/src/main/AndroidManifest.xml
  app/src/main/java/com/radix/testnet/
    MainActivity.java    the whole UI: status, accounts, receive, send, history
    NodeClient.java      HttpURLConnection only; long timeouts for slow signing
    Prefs.java           the node address, and nothing else
  app/src/main/res/      layout, colours, theme, vector icon
```

## Licence

MIT, same as the rest of the repository. No warranty; not fit for any purpose; do not
use it to store or transfer value.

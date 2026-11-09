---
title: The Android App
tags: [android, implementation]
---

# The Android app

`android/`. A native wallet client for the testnet, installable on a phone.

> [!warning] It holds no keys and does no proving
> Every spend is signed by the node the app points at. Anyone on the same network can
> spend the same faucet. This is the honest limitation of this build, not a detail.

## Why a native app and not a web wallet

A browser wallet would have been an afternoon: the node already serves a full
single-page GUI. It was rejected because it is not what was asked for, and because it
would have been a thin wrapper pretending to be an app.

The Android app is **one `Activity` with three dialogs**, written in Java with **no
AndroidX, no Kotlin and no third-party libraries**. The only build dependency is the
Android Gradle Plugin. That is why the APK is **24 KB**.

## What it does

| Screen | Behaviour |
|---|---|
| Main | node address, `connected - height N - mempool M - backend X`, balance, one row per account |
| Receive | the account address plus a QR fetched from `/api/qr.png` |
| Send | recipient, amount, fee → `POST /api/send` |
| History | confirmed and pending transactions |
| Mine | `POST /api/mine` |

## The three design decisions that matter

### 1. It is a client, and it says so

Doing the proving on the phone would need the NDK plus a Rust cross-compile for
`aarch64-linux-android` and a JNI shim. That was not attempted. Instead the app
delegates to the node — and the limitation is stated in the app's own footer, in the
Receive dialog, in `android/README.md` and here.

### 2. Long timeouts

`NodeClient` uses a **ten-minute read timeout**. Signing on the Python backend really
does take one to two minutes, and a wallet that gave up after thirty seconds would
report failure for a transaction that had actually succeeded. A wrong timeout is a
correctness bug, not a performance setting.

### 3. Cleartext HTTP, deliberately

`android:usesCleartextTraffic="true"`, because the node speaks plain HTTP on the LAN.
Android 9+ blocks it by default, so without this flag the app cannot talk to anything.
Acceptable on your own network; unacceptable anywhere else, and `--host 0.0.0.0` is
documented with the same warning.

## How it was verified

Not by "BUILD SUCCESSFUL":

```powershell
aapt dump badging app-debug.apk
# package com.radix.testnet  versionCode 1  versionName 0.1.0
# sdkVersion 24  targetSdkVersion 34
# uses-permission: android.permission.INTERNET
# launchable-activity: com.radix.testnet.MainActivity

apksigner verify --verbose app-debug.apk
# Verifies
# Verified using v2 scheme (APK Signature Scheme v2): true
```

The published release asset is **24,303 bytes**, matching the local build.

## Installing it

Download `RadixTestnet-android.apk` from the
[releases page](https://github.com/xhimnijx/Radix/releases), copy it to the phone, and
install. Android will demand that unknown sources be allowed for whichever app is doing
the install, and Play Protect will warn — the APK is signed with a debug key and is not
from the Play Store.

Then start the node with `--host 0.0.0.0` and point the app at
`http://<your-PC-LAN-IP>:8642`.

## What is not done

- **No on-device proving** (see above).
- **No encrypted storage**, because there is nothing to store.
- **No unit tests.** The app is 400 lines of UI glue around HTTP calls; the logic worth
  testing lives in the node, which has 21 HTTP tests.
- **Not tested on a physical device.** The build, the manifest and the signature were
  verified; the install path is documented, not demonstrated.
- **Debug key only.** Fine for your own phone, never for distribution.

## Toolchain note

There was no JDK, SDK or Gradle on the build machine. Everything was installed without
administrator rights under `C:\dev-tools`: Temurin JDK 17, Android cmdline-tools (with
licences accepted), `platforms;android-34`, `build-tools;34.0.0`, Gradle 8.7. The first
build took 2m53s. The repository now carries a Gradle wrapper so CI needs none of that
installed — and so this machine can be wiped without losing the build recipe.

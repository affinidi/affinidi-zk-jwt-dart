# Native libraries (`zk_jwt`) - prebuilds, hooks, and developer machines

This document explains how **`rust_eddsa_helper`** is delivered to apps that depend on **`zk_jwt`**, **when** the Dart build hook runs, and **what** must be installed on the machine that **builds** those apps.

**“Consumer”** here means the **developer or CI job** that runs `flutter build` / `dart test` / etc. It does **not** mean someone who only installs a finished app from the store (they never run hooks).

> **Note:** `zk_jwt` shares the same prebuilt native library and hook mechanism
> as [`affinidi-vc-zkp-dart`](https://github.com/affinidi/affinidi-vc-zkp-dart),
> but only calls the **Poseidon hash** symbols (`poseidon_hash`,
> `poseidon_hash_bits_ffi`, `poseidon_free_string`) exposed by
> `affinidi-zkp-crypto-rs`. The EdDSA signing/verification symbols are also
> present in the shared binary but are unused by this package - ZK-JWT
> delegates JWT signing/verification to caller-supplied callbacks.

---

## Design: prebuilt binaries only (no Rust on consumer machines)

- **App developers do not install Rust.** The hook does **not** run `cargo`.
- Sources live in the external Rust repo
  [`affinidi/affinidi-zkp-crypto-rs`](https://github.com/affinidi/affinidi-zkp-crypto-rs)
  for **maintainers** who rebuild slices.
- **`hook/build.dart`** selects a **prebuilt** dynamic library for each Rust **triple** the Dart/Flutter SDK requests, optionally verifies **`sha256`** (see [Local prebuilds](#local-prebuilds-and-hermetic-hooks) below), registers a **`CodeAsset`**, and the VM binds **`@ffi.Native`** in `lib/src/rust_eddsa_helper_ffi.dart` to that bundled library.
- **`prebuilds/manifest.json`** lists every supported triple. Each entry includes:
  - **`sha256`** (lowercase hex) - mandatory integrity check before the binary is used.
  - **`url`** (required in this repo) - GitHub Release asset URL. The hook
    downloads and verifies with `sha256`.
  - optional **`symbols`** - metadata for a **separate** debug archive (Apple:
    `rust_eddsa_helper-<triple>.dSYM.zip`; Android:
    `rust_eddsa_helper-<triple>.so.debug.zip`) on the **same** GitHub Release,
    with its own `sha256` and `url`. The hook **does not** download `symbols`
    (they are for crash log symbolication in Xcode, Play Console, Sentry, etc.).
- **`prebuilds/source_fingerprint.txt`** stores a deterministic hash over Rust source
  and build scripts. CI uses it to decide whether prebuild jobs need to run.

Resolution order for a triple:

1. If **`{override}/<triple>/<library-name>`** exists - the override is the first
   non-empty, non-`#` line of **`prebuilds/.zk_jwt_prebuilds_root`**, or (rare) env
   **`ZK_JWT_PREBUILDS_ROOT`**. Path is absolute or **relative to the package root**.
2. Else if **`<package>/prebuilds/<triple>/<library-name>`** exists (commonly
   **gitignored** after a maintainer build) → read from disk.
3. Else download from **`url`** in the manifest (first build may need network; see
   [Dart hooks environment](https://dart.dev/tools/hooks) for proxies).
4. **SHA-256:** always required for **downloads**. For **local** files, required
   unless the marker file **`prebuilds/.zk_jwt_trust_local`** exists, or
   (non-hermetic) env **`ZK_JWT_PREBUILDS_TRUST_LOCAL`**.

### Local prebuilds and hermetic hooks

[Hooks](https://dart.dev/tools/hooks) do **not** pass arbitrary environment
variables into `hook/build.dart` - only a [small
allowlist](https://github.com/dart-lang/sdk/blob/main/docs/hooks.md#environment)
(proxies, NDK, `PATH`, etc.). For local work, use **files under
`prebuilds/`** (gitignored, except `manifest.json` and `source_fingerprint.txt`):

| File | Purpose |
|------|---------|
| **`prebuilds/.zk_jwt_trust_local`** | Create (e.g. `touch prebuilds/.zk_jwt_trust_local`) to **skip SHA-256** for bytes read from **disk** when they do not match `manifest.json` yet. **HTTP** downloads are **always** checked. |
| **`prebuilds/.zk_jwt_prebuilds_root`** | One line: directory whose subfolders are **Rust triples**; tried before `prebuilds/<triple>/` in the package. |

`ZK_JWT_PREBUILDS_TRUST_LOCAL` and `ZK_JWT_PREBUILDS_ROOT` may work outside hermetic
hooks; **rely on the files above** for `dart test` and Flutter.

**Example:**

```bash
touch prebuilds/.zk_jwt_trust_local
dart test
# optional: prebuilds live outside the tree
printf '%s\n' /path/to/bundle > prebuilds/.zk_jwt_prebuilds_root
```

To populate **`prebuilds/<triple>/`**, use
**`tool/build_all_prebuilds.sh`** from
[`affinidi/affinidi-zkp-crypto-rs`](https://github.com/affinidi/affinidi-zkp-crypto-rs)
(Apple: macOS + Rust; Android, Linux, Windows: **Docker** + cross-compilation toolchain in the image).

Library names follow OS conventions (`librust_eddsa_helper.dylib` on Apple platforms, `librust_eddsa_helper.so` on Android and Linux, `rust_eddsa_helper.dll` on Windows).

References:

- [Dart: Hooks](https://dart.dev/tools/hooks)
- [Flutter: Bind to native code using FFI](https://docs.flutter.dev/platform-integration/bind-native-code)

---

## Supported triples (hook)

Anything not listed in **`prebuilds/manifest.json`** fails the hook with a clear error (until maintainers add that slice).

| Platform | Rust triples used by this package |
|----------|-------------------------------------|
| **macOS** | `aarch64-apple-darwin`, `x86_64-apple-darwin` |
| **iOS** | `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios` |
| **Android** | `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`, `i686-linux-android` |

Linux / Windows desktop targets are **not** supported.

**Current repository state:** binaries (and, after each full prebuild run, matching
**symbol** archives) are hosted as **GitHub Release** assets. The package keeps only
`prebuilds/manifest.json` and `prebuilds/source_fingerprint.txt` in source control.

---

## Debug symbols (not loaded by the Dart hook)

- **macOS / iOS:** `tool/build_prebuilds.sh` (in
  [`affinidi/affinidi-zkp-crypto-rs`](https://github.com/affinidi/affinidi-zkp-crypto-rs))
  zips
  the **`librust_eddsa_helper*.dSYM`**
  bundle to **`prebuilds/<triple>/rust_eddsa_helper-<triple>.dSYM.zip`** and CI uploads
  it next to the `dylib`. Use it with **Xcode**, **Crashlytics**, **Sentry**, etc. The
  release tag is **`prebuilds-<source_fingerprint>`** (same as the native library
  build).
- **Android:** the Docker prebuild run uses **`llvm-objcopy --only-keep-debug`**
  and zips the result to **`rust_eddsa_helper-<triple>.so.debug.zip`**. Use with
  **ndk-stack** / **Play** symbol upload / your crash backend as usual.
- **Matching rule:** the symbol archive must be from the **same** prebuild (same
  **`source_fingerprint`**) as the `librust_eddsa_helper` you ship; the manifest
  `symbols.sha256` is the integrity check.
- **Consumer helper script:** use **`./tool/download_prebuild_symbols.sh`** to
  pull symbol archives for all or selected triples from the current
  `prebuilds/manifest.json`.

Example:

```bash
./tool/download_prebuild_symbols.sh --output-dir ./.native-symbols
./tool/download_prebuild_symbols.sh --triple aarch64-apple-ios --triple aarch64-linux-android
```

---

## When does the hook run?

Not on `dart pub get` alone. The SDK runs **`hook/build.dart`** when it needs **native code assets**, for example:

- **`flutter build`** / **`flutter run`** (iOS, Android, macOS targets).
- **`dart test`**, **`dart run`**, **`dart build`** when the tool resolves assets for the VM or requested targets.

Each invocation may copy or download **one** binary per `(triple)` request and bundle it. Results are **cached** by the SDK; declared hook **dependencies** include `prebuilds/manifest.json` and any **vendored** prebuild file that was read.

**End users** of store builds never execute this hook.

---

## What must be installed on the developer machine?

| Requirement | Why |
|-------------|-----|
| **Dart SDK ≥ 3.10** | Native assets + hooks (`sdk: ^3.10.0`). |
| **Network (optional)** | Only if a triple has **no** vendored file and the manifest supplies a **`url`** to download. |
| **Flutter / Xcode / Android SDK** | Same as any normal Flutter build for iOS/Android (signing, NDK, etc.). **Not** for compiling Rust. |

**Rust** is only required on machines that **produce** prebuild artifacts
(maintainers / release CI). Use
**`tool/build_prebuilds.sh`** from
[`affinidi/affinidi-zkp-crypto-rs`](https://github.com/affinidi/affinidi-zkp-crypto-rs)
(see below).

---

## Maintainer workflow: add or refresh a prebuild

1. Install Rust and the desired target, e.g. `rustup target add aarch64-linux-android`.
2. For Android cross-compiles from macOS, configure the NDK in your environment the same way you would for `cargo` (the maintainer script only wraps `cargo`; it does not replace Flutter’s NDK layout).
3. Run:

   ```bash
   git clone https://github.com/affinidi/affinidi-zkp-crypto-rs.git
   cd affinidi-zkp-crypto-rs
   ./tool/build_prebuilds.sh aarch64-apple-darwin
   ```

   This compiles `affinidi-zkp-crypto-rs` and copies the artifact to **`prebuilds/<triple>/`**.

4. Build/publish binaries in CI:

   ```bash
   # Run Rust-side GitHub Actions workflow:
   # https://github.com/affinidi/affinidi-zkp-crypto-rs/blob/main/.github/workflows/build-prebuilds.yml
   ```

   The workflow:
   - builds Apple and Android prebuilds,
   - publishes assets to tag `prebuilds-<source_fingerprint>`,
   - regenerates `prebuilds/manifest.json` URLs + hashes,
   - opens/updates a PR with metadata changes.

5. Merge the generated metadata PR.

For local maintainer testing, you can still build binaries on disk and run:

```bash
./tool/update_prebuild_metadata.sh
```

This mode computes hashes from local `prebuilds/<triple>/` files and updates
`source_fingerprint.txt`, but production metadata is expected to come from CI
release assets.

Before publishing to **pub.dev**, ensure every triple your consumers might hit is present, or document supported platforms explicitly.

### Android helper commands

- Local host with Android NDK configured (optional, maintainer-only):

  ```bash
  ANDROID_NDK_ROOT=/absolute/path/to/ndk \
  ./tool/build_prebuilds.sh \
    aarch64-linux-android \
    armv7-linux-androideabi \
    x86_64-linux-android \
    i686-linux-android
  ```

- Docker-based builder (optional, maintainer-only):

  ```bash
  ./tool/build_android_prebuilds_docker.sh
  ```

  This requires Docker daemon access on the machine running the script.

  By default the script uses **`docker ... --platform linux/amd64`** because the
  official Android NDK Linux bundle only includes **`linux-x86_64`** host
  toolchains. Override with **`ZK_JWT_DOCKER_PLATFORM`** if your setup needs a
  different platform.

---

## Caching and security

- The hook refuses to load a binary whose digest does not match **`sha256`** (whether vendored or downloaded).
- Prefer **HTTPS** URLs in the manifest.
- Vendored binaries increase package size but avoid download flakiness and supply-chain exposure to third-party hosts.

## CI prebuild pipeline

Prebuild CI is owned by the Rust package workflow:

- [`affinidi/affinidi-zkp-crypto-rs/.github/workflows/build-prebuilds.yml`](https://github.com/affinidi/affinidi-zkp-crypto-rs/blob/main/.github/workflows/build-prebuilds.yml)

- Apple slices on `macos-14`.
- Android slices on `ubuntu-24.04` via Docker + Android NDK container.
- Runs automatically for Rust/build-tooling path changes, and can be forced with
  `workflow_dispatch`.
- Produces release assets for binaries and debug symbols.
- Produces metadata artifacts (`manifest.json` + `source_fingerprint.txt`) for
  Dart-side consumption.

---

## Quick verification

```bash
dart test test/rust_bridge_integration_test.dart --run-skipped
```

Confirms the hook supplies a library for the **host** triple and that **`@ffi.Native`** calls work end-to-end.

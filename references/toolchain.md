# Toolchain and local setup

Run `scripts/check_tools.py --probe` to distinguish installed paths from successful executable probes. It does not install anything, inspect projects or start an emulator. Local paths/provenance are in `tools/toolchain.json`; it contains no credentials.

| Need | Tool | Scope |
| --- | --- | --- |
| APK/manifest intake | `scripts/inspect_apk.py` | Bounded static parsing; no app execution or network. |
| ELF/snapshot metadata | Private `pyelftools` | Metadata, not source recovery. |
| Skill validation | Private `PyYAML` | Skill frontmatter checks. |
| DEX to Java evidence | Private JADX CLI | Decompiled output may be incomplete. |
| Manifest/resource decoding | Private Apktool JAR | Selected app, fresh case directory. |
| Signature/SDK checks | Existing Android SDK/JDK | AAPT/AAPT2/apksigner and Java/Javac. |
| Dart AOT analysis | Existing Blutter in Ubuntu WSL | Matching Dart runtime and ABI required. |
| Permitted source builds | Project's Gradle/Flutter toolchain | Owning source and normal signing setup. |

## Invocation

On this Windows installation, `<skill>` is the directory containing SKILL.md. Use its private Python:

```powershell
& "<skill>/.venv/Scripts/python.exe" "<skill>/scripts/check_tools.py" --probe
& "<skill>/.venv/Scripts/python.exe" "<skill>/scripts/inspect_apk.py" "<exact APK>" --out "<workspace>/.for-devs/cases/<case>" --verify-signature
```

On Linux use `.venv/bin/python`. `inventory.json` is the machine-readable result and `summary.md` is the short evidence report. The scanner preserves inputs and refuses ambiguous or oversized structures. It can work without JADX/Apktool/Blutter; unavailable deeper tools remain explicit.

For trusted tool execution use structured subprocess arguments, not shell-composed strings containing APK filenames. Java invocations avoid Windows batch-shell interpolation:

```text
java -jar <apktool.jar> --version
java -cp <jadx-lib-directory/*> jadx.cli.JadxCLI --version
java -jar <sdk-build-tools/lib/apksigner.jar> verify --verbose --print-certs <apk>
```

## Provision another machine

Use an isolated Python environment and `requirements.txt`. Obtain dependencies from official sources and verify supplied release digests. Keep paths/provenance in local configuration; do not change PATH, replace SDKs or alter Codex settings unnecessarily.

- [JADX upstream/releases](https://github.com/skylot/jadx): this installation uses 1.5.6 CLI for static DEX evidence. No authorization patches are bundled.
- [Apktool installation](https://apktool.org/docs/install/): a verified 2.12.1 JAR is copied privately. Current upstream docs may describe another major version; installed help is authoritative for local options.
- [Blutter upstream](https://github.com/worawit/blutter): Android arm64 AOT analysis with matching Dart runtime. Local cache includes 3.13.2; this does not imply arbitrary APK support.
- [Android tools](https://developer.android.com/tools): use the existing SDK or a requested installation. Do not silently accept licenses or download multiple runtime/SDK versions while guessing.

## Setup acknowledgment

Read [TERMS_OF_USE.md](../TERMS_OF_USE.md). The installer requires an explicit interactive confirmation or --accept-authorized-use once. The local .local/authorized-use.json record is ignored by Git; changed terms require review again. This declares usage scope, not server authority or blanket approval of future actions.

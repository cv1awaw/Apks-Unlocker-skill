# Authorized source development and verification

Use after the requested features and owning source are clear. Examples: UI/accessibility changes, local settings, diagnostics, local file import/export, accurate account status, and downloader fixes for content the account may access.

1. Resolve only user-supplied source directories and read applicable project instructions. Do not search other projects, account stores or signing material automatically.
2. Preserve unrelated changes and trace only needed modules. Use the project's normal Gradle/Flutter build and supported APIs.
3. Keep UI state separate from server truth. Display permission failures honestly. Do not use self-granted roles, membership flags, forced course lists or identity spoofing as a replacement for authorization.
4. Preserve originals/previous builds. Use the provided development signing setup; do not replace production keys or expose passwords. Check package/version/SDK/signer compatibility before calling an artifact an update.

This skill does not bundle arbitrary APK binary-patching/unlocking instructions. If code needed for implementation cannot be reliably recovered, request the owning project and retain the supported inspection report.

## Verification

- Build/check the changed modules. For file handlers/providers, test path confinement, collisions, partial files and temporary URI grants as appropriate.
- Inspect before/after screenshots of the selected app at the same viewport for visual changes.
- For requested runtime tests, prefer an isolated emulator without personal accounts, host data mounts or unrelated apps. Do not run unknown APKs on a personal phone or sign in to services as a side effect of static analysis.
- Distinguish guest state, authenticated operations, dummy fixtures, real downloads and physical-device tests. Compilation alone is not success.
- Broaden checks only for changed behavior, failures or a concrete unresolved concern.

Deliver source/artifact paths, package/version, size, SHA-256, signature results and checks actually performed. State material limits. Upload/publish only when the current task authorizes the destination.

# Flutter/Dart snapshot route

Use only for the selected package's Flutter payloads or explicitly supplied libraries.

1. Bind evidence to the APK and native-library hashes in the intake. A `flutter_assets` folder alone is not proof of usable AOT recovery.
2. Choose an ABI deliberately. Prefer `arm64-v8a` for the installed Blutter route; inventory/hash other ABIs without claiming semantic recovery.
3. To copy only the two relevant fixed entries:

   ```text
   <private-python> scripts/extract_flutter.py <exact-apk> --abi arm64-v8a --out <case>/flutter
   ```

   It records digests and neither executes the libraries nor extracts unrelated entries.
4. Snapshot hash candidates from a symbol header and labeled engine strings are limited evidence. Do not infer a full SDK mapping or recovered functions from incidental strings.

## Matching analyzer

Local configuration points to `/root/blutter` in the `Ubuntu` WSL distribution. Translate only the exact selected case path to its `/mnt/<drive>/...` form; do not search other drives for alternate apps or prior dumps.

```text
wsl -d Ubuntu -- python3 /root/blutter/extract_dart_info.py /mnt/<drive>/<case>/flutter/arm64-v8a
```

If a matching cached analyzer exists and deeper analysis answers the permitted feature question:

```text
wsl -d Ubuntu -- python3 /root/blutter/blutter.py /mnt/<drive>/<case>/flutter/arm64-v8a /mnt/<drive>/<case>/dart-analysis
```

Blutter may fetch/build Dart source when its matching analyzer is absent. Check version/ABI/cache first. Do not start these downloads during initial offline intake. Identify the exact missing runtime before installing it in an authorized development task. Do not run cleanup scripts that delete an existing global analyzer.

## Focused evidence

Read only the UI/model/local asset/cache/diagnostic flow needed for the chosen feature. Record library digest, ABI, function/address and analyzer warnings. Keep a short caller → relevant method → data-source chain.

Do not paste complete `pp.txt`, `objs.txt` or string pools; they can contain credentials and unrelated private data. Do not use generated hook templates to change membership, role, license, integrity or authorization checks.

Record unsupported versions and failures precisely. Successful exit with warnings does not mean full recovery. Do not guess offsets, claim original source, or patch conditions until a feature appears enabled. Return to the owning source for implementation; without it, explain which module is needed.

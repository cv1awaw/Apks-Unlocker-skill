# Focused Android inspection

Use the selected APK, not a similarly named package. Initial intake neither executes it nor uploads it.

For Java/Kotlin, use the configured JADX classpath and installed help to select a relevant class/package. Decompiled Java is a reconstruction, not guaranteed buildable source. Corroborate material claims with manifest/resources or selected methods. Client strings and editable metadata do not establish backend authority.

For manifest/resources, decode with Apktool into a fresh case subdirectory only when needed. Suppress DEX source decoding for resource-only work using the locally supported option. Preserve originals and existing cases. Never execute scripts or native libraries found in the APK.

Keep scope to the chosen screen/resource/local flow. Do not enumerate unrelated backend routes, try credentials or inspect another installed app. Exported attributes and permissions are static inventory; missing attributes depend on platform/SDK rules and are not by themselves proof of safety or exploitability.

Missing splits can explain analysis/build failures. Request the matching package set instead of copying libraries from another application. Redact secrets encountered incidentally; do not replay them to expand access.

For each finding cite an APK entry, selected class or source location. Separate observations, static inference and unknown runtime behavior. A method name alone is not an execution trace. Continue permitted implementation through [development.md](development.md), not a generic security-gate patcher.

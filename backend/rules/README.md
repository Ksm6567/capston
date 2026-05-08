# YARA Rules

`enhanced_rules.yar` is the local critical ruleset used for always-on host monitoring. It contains only high-risk patterns that should stay fast and stable during continuous scans.

The app uses two rule tiers:

- `local-critical`: always-on monitoring and all-drive scans.
- `external-extended`: Wazuh single-file verification and user-selected folder scans using the external Yara-Rules/rules project.

External extended rules are intentionally blocked for all-drive scans to protect backend responsiveness.

## External Rules

Use `update_external_rules.ps1` to download a public ruleset into `backend/rules/external/<source>`.

```powershell
.\backend\rules\update_external_rules.ps1 -Source yara-rules
```

To run the app with a custom external rules directory:

```powershell
$env:YARA_EXTERNAL_RULES_PATH = "C:\Users\ybi65\OneDrive\Desktop\capstone\backend\rules\external\yara-rules"
```

Then start the backend normally. The scanner compiles `.yar` and `.yara` files individually, so one invalid third-party rule file will be skipped instead of disabling the whole scan. Compiled rules are cached and recompiled only when the rule files change.

Default source:

- `yara-rules`: broad community ruleset from `https://github.com/Yara-Rules/rules`, GPL-2.0 license.

Alternative sources:

- `reversinglabs`: high-confidence malware detection rules, MIT license.
- `signature-base`: high-quality hunting and IOC rules, DRL 1.1 license. Some files may require external variables.

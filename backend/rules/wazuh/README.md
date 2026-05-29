# Wazuh Ruleset Reference

This project no longer installs or connects a Wazuh Manager from the app.

The current local behavior engine uses:

1. Sysmon to collect Windows system and process events.
2. Local detection logic in `backend/src/behavior_monitor.py`.
3. The official Wazuh Windows/Sysmon ruleset as a reference for naming,
   grouping, and behavior interpretation.

In other words, Wazuh is used as a ruleset reference, not as a Manager/Agent
runtime dependency.

## Reference Copy

To keep a local reference copy of the official Wazuh ruleset in this repo, run:

```powershell
.\backend\rules\wazuh\sync_official_ruleset.ps1
```

This downloads `rules`, `decoders`, and `lists` from the official Wazuh ruleset
repository into `backend/rules/wazuh/official`.

The reference copy is for review and traceability. Do not treat these XML files
as runtime alert logs.

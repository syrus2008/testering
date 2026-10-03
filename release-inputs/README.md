# Release-owner inputs

The release pipeline cannot produce these results itself; the release owner supplies them in
`release-inputs/<acet version>/` and `tools/release_evidence.py build --supplied` copies them into the
evidence bundle, where the manifest signature pins them. The STABLE gate validates their content
(`tools/release_evidence.py check`): a missing, placeholder or inconsistent file blocks the release.

```
release-inputs/<version>/
  advisories.json                       OSV-style advisory export (list), input of tools/vuln_scan.py
  triage.json                           {"<advisory id>": {"decision": "not-affected|mitigated|accepted|fixed", "rationale": "..."}}
  clean-vm-install-results/windows10.json
  clean-vm-install-results/windows11.json
  manual-acceptance/ACC-001.json        one file per acceptance criterion whose status is manual_protocol
  ...
```

Every clean-VM and manual result has this shape:

```json
{
  "status": "PASSED",
  "executor": "Full Name",
  "executed_at": "2026-10-03T14:00:00+00:00",
  "acet_version": "1.0.0",
  "installer_sha256": "<SHA-256 of the installer that was tested, as in the release manifest>",
  "checks": [{"name": "installer completes", "result": "PASSED"}, {"name": "acet doctor --full", "result": "PASSED"}],

  "os": {"name": "Windows", "version": "11", "build": "26100.2033"},   // clean-VM results only
  "clean_vm": true,                                                     // clean-VM results only
  "protocol": "MP-001", "protocol_version": 1                           // manual-acceptance results only
}
```

The gate refuses results for another installer, another version, a date before the build, an
unknown protocol version, a missing executor or any check not `PASSED`. See
`docs/acceptance/manual-protocols.md` for the protocols themselves.

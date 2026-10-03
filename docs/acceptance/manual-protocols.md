# Manual acceptance protocols (versioned) — ACET-TRACE-002

These criteria need a clean Windows machine, a production signing certificate or an
installer, which an automated Linux CI run cannot provide. Each protocol is versioned;
the release owner records results as JSON in the Release Evidence Bundle
(`clean-vm-install-results/*.json`, status `PASSED`/`FAILED`). `tools/release_evidence.py check`
refuses a STABLE release while any of them is `NOT_RUN` or `FAILED`.

Automated building blocks already exercised by CI are listed for each protocol.

## MP-001 v1 — Clean installation (ACC-001)
1. Fresh Windows 11 x64 VM (no Python, no Java), snapshot taken.
2. Run `ACET-Setup-<version>.exe` as a standard user (no elevation prompt expected).
3. Start "ACET" from the Start menu. Expected: the first-run wizard opens.
4. Run `acet.exe doctor --json` from the install directory. Expected: JSON health, exit 0 or 10.
Record: installer hash, signer, wall time, doctor output.
Automated blocks: `packaging/acet.spec`, `packaging/acet.iss`, `tests/ui/test_ui.py::test_first_run_wizard_creates_workspace_scans_and_self_tests`.

## MP-002 v1 — Uninstall keeps workspaces (ACC-025)
1. After MP-001, create a workspace and import `datasets/demo/builds/v1`.
2. Uninstall from "Apps & features".
3. Expected: `%LOCALAPPDATA%\ACET\workspaces\<id>\acet.db` and blobs still present; reinstall and open the workspace: data intact.
Automated blocks: `packaging/acet.iss` has no `[UninstallDelete]` for `{localappdata}\ACET`.

## MP-003 v1 — Signed release verified in CI (ACC-056)
1. Configure `SIGNING_CERT_THUMBPRINT` for the release workflow (certificate never in the repository).
2. Run `release.yml` with channel STABLE.
3. Expected: `signtool verify /pa /v` passes for `acet.exe`, `acet-ui.exe` and the installer, with an RFC 3161 timestamp; `signed-hashes.txt` produced.
Automated blocks: `packaging/sign.ps1`, `tools/release_evidence.py` (signature of the release manifest, tested in `tests/integration/test_p12.py`).

## MP-004 v1 — Clean-machine end-to-end (ACC-100)
On the MP-001 VM: install → `doctor --full` (golden self-test) → import demo v1/v2 → STANDARD compare (official Engine Pack) →
HTML report → `acet backup` → apply the next version with `acet update apply <bundle>` → `acet restore <backup>`.
Expected: every step succeeds; report lists engines/versions; restore passes integrity_check.
Automated blocks: `tests/acceptance/test_closure.py::test_cli_full_parity_and_exit_codes`, `tests/integration/test_p12.py::test_offline_update_verify_apply_and_rollback`,
`tests/acceptance/test_closure.py::test_backup_restores_settings_and_annotations`.

## MP-005 v1 — Full lifecycle (ACC-150)
MP-004 plus: third build (v3) → lineage → kill the application during a STANDARD run (Task Manager) → restart → resume →
update → restore → uninstall → reinstall → open the workspace: all historical runs, lineages and annotations present.
Automated blocks: `tests/acceptance/test_closure.py::test_kill_app_at_any_point_is_recoverable`,
`tests/integration/test_analysis.py::test_lineage_split_merge_and_incremental_extension`.

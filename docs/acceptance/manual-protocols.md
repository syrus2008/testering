# Manual acceptance protocols (versioned) — ACET-TRACE-002

These criteria need a clean Windows machine, a production signing certificate or an
installer, which an automated Linux CI run cannot provide. Each protocol is versioned;
the release owner records each execution as a JSON result in `release-inputs/<version>/`
(`manual-acceptance/<ACC-ID>.json` and `clean-vm-install-results/windows{10,11}.json`; format in
[`release-inputs/README.md`](../../release-inputs/README.md)). `tools/release_evidence.py check`
refuses a STABLE release unless every manual criterion has a `PASSED` result for the current
protocol version, executed on the installer of this release (SHA-256 in the signed manifest),
with a named executor and every individual check passed.

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

## MP-006 v1 — Standalone engines on a clean Windows (ACC-ENGINE-001)
1. Fresh Windows 10 or 11 x64 VM with **no** Python, Java, Ghidra or Ghidriff (check `where python java`), snapshot taken.
2. Install `ACET-Setup-<version>.exe` (embedded Python runtime: PyInstaller build), start ACET.
3. Expected: ACET starts, FAST is available, the "Engine Pack" guide opens and the top bar shows `Engines: ⚠ NOT INSTALLED`.
4. Click `Engines` → `Install Engine Pack`. Expected: the consent dialog lists version, download size, installed
   size, components and licences of the **official signed** pack.
5. Confirm. Expected: progress through download, SHA-256, signature, extraction, health check; the UI stays responsive.
6. Expected: `Engines: ✔ READY`; Engine Manager shows Java/Ghidra/Ghidriff READY and STANDARD READY.
7. Import `datasets/demo/builds/v1` and `v2`, run a STANDARD compare. Expected: COMPLETED with live engines.
8. Run `acet.exe doctor --full`. Expected: engine pack READY, java `(engine-pack)`, golden self-test VERIFIED (live).
Record: installer hash, Engine Pack id/version/archive SHA-256, `engine-pack-install.log`, doctor output, wall times.
Automated blocks: `tests/integration/test_engine_manager.py` (signed index, download, resume, corruption, crash
recovery, rollback, private Java pinning), `tests/ui/test_engines_ui.py`, `tests/live/test_engine_pack_live.py`
(run by `.github/workflows/engine-pack.yml` on a Windows runner without system Java/Ghidra/Ghidriff:
`docs/evidence/engine-pack-e2e-windows.md`) and the Linux live run (`docs/evidence/engine-pack-e2e-linux.md`).

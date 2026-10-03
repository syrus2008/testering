# License audit (spec §45, §113, ACET-LIC-001)

<!-- Generated from docs/license-audit.json by tools/license_audit.py — do not edit by hand. -->

Scope: ACET Windows installer (ACET core + embedded Python runtime + PySide6) and the ACET Engine Pack (win64).

**Approval:** PENDING — approver: (none) — date: (none)

Legal sign-off is a human decision of the release owner. The release gate refuses STABLE until status is APPROVED with a named approver and date (ACET-LIC-001).

| Component | Version | SPDX | Distribution | Redistribution | Status |
|---|---|---|---|---|---|
| ACET | see release manifest | LicenseRef-ACET-Proprietary | installer | yes | OPEN |
| Python runtime | 3.11 (exact patch recorded in the SBOM of each release) | PSF-2.0 | installer (embedded by PyInstaller, onedir) | yes | CLOSED |
| PySide6 (+ PySide6_Essentials, PySide6_Addons, shiboken6) | 6.11.2 (validated in CI; exact version recorded in the SBOM) | LGPL-3.0-only | installer (PyInstaller onedir: Qt and PySide6 libraries stay separate, replaceable DLL/PYD files) | conditional | CLOSED |
| Ghidra | 11.4.2 | Apache-2.0 | Engine Pack only | conditional | CLOSED |
| Ghidriff | 1.0.0 | GPL-3.0-only | Engine Pack only, never in the installer | conditional | CLOSED |
| pyghidra | 2.2.1 (bundled with Ghidra 11.4.2) | Apache-2.0 | Engine Pack only | yes | CLOSED |
| protobuf-java | 3.23.0 | BSD-3-Clause | Engine Pack only | yes | CLOSED |
| BinDiff / BinExport | 8 / 12 | Apache-2.0 | Engine Pack only | yes | CLOSED |
| QBinDiff | 1.2.3 | Apache-2.0 | Engine Pack only (isolated venv, experimental) | yes | CLOSED |
| Java runtime | Eclipse Temurin 21 (LTS; Ghidra 11.4 requires JDK 21) | GPL-2.0-only WITH Classpath-exception-2.0 | Engine Pack only | conditional | CLOSED |
| Diaphora | n/a | AGPL-3.0-or-later | not distributed (external only, ADR-0009) | no | CLOSED |

## ACET

Obligations:
- Ship the ACET end-user license (EULA) and the THIRD-PARTY notices with the installer.
- The EULA must allow reverse engineering of the LGPL parts for debugging modifications (LGPL-3.0 §4).

How satisfied: Notices: tools/collect_licenses.py → {app}\licenses. EULA: no text exists in the repository yet (pyproject declares 'Proprietary'); the release owner must supply packaging/EULA.txt.

## Python runtime

Obligations:
- Retain the PSF License Agreement and its copyright notice in the distribution.
- Include a brief summary of changes if the runtime is modified (ACET does not modify it).

How satisfied: tools/collect_licenses.py copies <python prefix>/LICENSE.txt to licenses/python/LICENSE.txt; the runtime is unmodified.

## PySide6 (+ PySide6_Essentials, PySide6_Addons, shiboken6)

Obligations:
- Ship the LGPL-3.0 and GPL-3.0 license texts and Qt's third-party notices.
- Keep Qt/PySide6 dynamically linked and user-replaceable (no static linking, no onefile packaging).
- Do not modify Qt/PySide6; if ever modified, publish the modified sources.
- State where the corresponding Qt/PySide6 sources can be obtained.
- The ACET EULA must not forbid reverse engineering needed to debug modifications of the LGPL parts.

How satisfied: packaging/acet.spec uses COLLECT (onedir); the wheels ship no license file, so tools/collect_licenses.py copies the vendored canonical LGPL-3.0/GPL-3.0 texts (packaging/licenses/) and writes licenses/THIRD-PARTY-NOTICES.txt with the source location (https://download.qt.io/official_releases/QtForPython/). The EULA clause is tracked on the ACET row.

## Ghidra

Obligations:
- Ship Ghidra's LICENSE and the licenses/ directory (third-party components, some GPL) unchanged.
- Mark modified files: ACET replaces Debug/ProposedUtils protobuf-java 3.21.8 by 3.23.0 (recorded in the pack manifest).

How satisfied: The Engine Pack copies the whole Ghidra tree including LICENSE and licenses/; the protobuf swap is listed in the pack manifest 'modifications'.

## Ghidriff

Obligations:
- Distribute unmodified, with the GPL-3.0 text and the corresponding source (or a written offer).
- Keep the process boundary: ACET core does not import or link Ghidriff; it runs it as a separate program and reads its output files (aggregation).

How satisfied: Decision: bundled in the Engine Pack as an unmodified wheel + its sdist (corresponding source) + COPYING; invoked only by acet.engines.ghidriff through the supervised worker process.

## pyghidra

Obligations:
- Ship the license (included in the Ghidra tree).

How satisfied: Shipped inside the Ghidra tree of the Engine Pack.

## protobuf-java

Obligations:
- Retain the copyright notice and license text.

How satisfied: LICENSE copied next to the jar in the Engine Pack; replacement recorded in the pack manifest.

## BinDiff / BinExport

Obligations:
- Ship LICENSE and NOTICE files.

How satisfied: Copied from the upstream release into the Engine Pack.

## QBinDiff

Obligations:
- Ship the licenses of QBinDiff and of every package of its venv.

How satisfied: tools/collect_licenses.py --venv collects the license files of every distribution of the QBinDiff venv; qbindiff 1.2.3 ships none, so the vendored Apache-2.0 text is used. The tool fails if any distribution has no license text.

## Java runtime

Obligations:
- Distribute unmodified with its LICENSE, ASSEMBLY_EXCEPTION and third-party notices (legal/ directory).
- State where the corresponding source can be obtained (https://github.com/adoptium/jdk21u).

How satisfied: Decision: Eclipse Temurin 21 JDK, copied unmodified including legal/; source location written to the pack THIRD-PARTY-NOTICES.

## Diaphora

Obligations:
- None while not distributed; requires IDA, which ACET does not ship.

How satisfied: Not part of the installer or any Engine Pack.

## Open items

- license audit: ACET: status 'OPEN' (must be CLOSED)
- license audit: approval status 'PENDING' (must be APPROVED)
- license audit: approval has no named approver
- license audit: approval has no valid approved_at date

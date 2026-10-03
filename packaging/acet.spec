# PyInstaller spec — ACET Windows build (embedded Python runtime, ACC-001). Run on Windows:
#   pyinstaller packaging/acet.spec --noconfirm
import os

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

REPO = os.path.abspath(os.path.join(SPECPATH, ".."))  # noqa: F821 (SPECPATH is set by PyInstaller)

datas = collect_data_files("acet", include_py_files=False)
# Demo dataset for the golden self-test of `acet doctor --full` (ACC-026/100): demo builds,
# ground truth and recorded Ghidra exports, installed as acet/demo (see platform/selftest.py).
demo = os.path.join(REPO, "datasets", "demo")
datas += [(os.path.join(demo, "builds"), "acet/demo/builds"),
          (os.path.join(demo, "ground_truth.json"), "acet/demo"),
          (os.path.join(demo, "golden", "ghidra"), "acet/demo/golden/ghidra")]
# Processors, engine adapters and workers are imported by name at run time (registry entry
# points): PyInstaller cannot see them statically, so every acet submodule is collected.
hidden = collect_submodules("acet")
common = dict(pathex=[os.path.join(REPO, "src")], datas=datas, hiddenimports=hidden, noarchive=False)

cli = Analysis([os.path.join(REPO, "src", "acet", "__main__.py")], **common)
ui = Analysis([os.path.join(REPO, "src", "acet", "ui", "__main__.py")], **common)
MERGE((cli, "acet", "acet"), (ui, "acet-ui", "acet-ui"))

cli_exe = EXE(PYZ(cli.pure), cli.scripts, [], exclude_binaries=True, name="acet", console=True,
              manifest=os.path.join(SPECPATH, "acet.exe.manifest"), version=None)
ui_exe = EXE(PYZ(ui.pure), ui.scripts, [], exclude_binaries=True, name="acet-ui", console=False,
             manifest=os.path.join(SPECPATH, "acet.exe.manifest"))
COLLECT(cli_exe, cli.binaries, cli.datas, ui_exe, ui.binaries, ui.datas, name="ACET")

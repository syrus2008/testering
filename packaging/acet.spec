# PyInstaller spec — ACET Windows build (embedded Python runtime, ACC-001). Run on Windows:
#   pyinstaller packaging/acet.spec --noconfirm
from PyInstaller.utils.hooks import collect_data_files

datas = collect_data_files("acet", include_py_files=False)
common = dict(pathex=["src"], datas=datas, hiddenimports=["acet.engines.worker"], noarchive=False)

cli = Analysis(["../src/acet/__main__.py"], **common)
ui = Analysis(["../src/acet/ui/__main__.py"], **common)
MERGE((cli, "acet", "acet"), (ui, "acet-ui", "acet-ui"))

cli_exe = EXE(PYZ(cli.pure), cli.scripts, [], exclude_binaries=True, name="acet", console=True,
              manifest="acet.exe.manifest", version=None)
ui_exe = EXE(PYZ(ui.pure), ui.scripts, [], exclude_binaries=True, name="acet-ui", console=False,
             manifest="acet.exe.manifest")
COLLECT(cli_exe, cli.binaries, cli.datas, ui_exe, ui.binaries, ui.datas, name="ACET")

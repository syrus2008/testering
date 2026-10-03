import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(autouse=True)
def _isolated_qsettings(tmp_path):
    """UI tests never read or write the real user's QSettings."""
    from PySide6.QtCore import QSettings

    # QSettings("ACET", "ACET") uses the *native* format: redirect both formats.
    for fmt in (QSettings.Format.NativeFormat, QSettings.Format.IniFormat):
        QSettings.setPath(fmt, QSettings.Scope.UserScope, str(tmp_path / "qsettings"))
    yield

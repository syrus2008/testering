"""acet.ui — PySide6 desktop UI (ACET-ARCH-001: the only package importing Qt).

All business logic lives in acet.application/analysis/...; every potentially slow
call runs in a background task with its own workspace connection (ACC-029).
"""

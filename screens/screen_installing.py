import sys
import subprocess
import threading
from PyQt5.QtWidgets import QApplication, QLabel
from PyQt5.QtCore import QObject, QEvent, QTimer, QMetaObject, Qt, Q_ARG
from PyQt5.QtGui import QMovie
from ui_components.ui_base_full import UIBaseFull
from ui_components.ui_title_text import UITitleText
from ui_components.ui_header_text import UIHeaderText
import debloat_components.debloat_download_scripts as debloat_download_scripts
import debloat_components.debloat_execute_raven_scripts as debloat_execute_raven_scripts
import debloat_components.debloat_execute_external_scripts as debloat_execute_external_scripts
import debloat_components.debloat_execute_privacy_sexy as debloat_execute_privacy_sexy
import debloat_components.debloat_registry_tweaks      as debloat_registry_tweaks
import debloat_components.debloat_apply_background     as debloat_apply_background
import os



class StatusResizer(QObject):
    def __init__(self, parent, label, bottom_margin):
        super().__init__(parent)
        self.parent = parent
        self.label = label
        self.bottom_margin = bottom_margin
        parent.installEventFilter(self)
        self._update_position()

    def eventFilter(self, obj, event):
        if obj is self.parent and event.type() == QEvent.Resize:  # type: ignore
            self._update_position()
        return False

    def _update_position(self):
        w = self.parent.width()
        fm = self.label.fontMetrics()
        h = fm.height()
        y = self.parent.height() - self.bottom_margin - h
        self.label.setGeometry(0, y, w, h)



def main():
    app = QApplication.instance() or QApplication(sys.argv)
    base = UIBaseFull()
    overlay = base.primary_overlay
    if overlay is None:
        overlay = base.overlays[0]
    for overlay in base.overlays:
        overlay.setWindowOpacity(0.8)
    title_label = UITitleText("Initializing Basilisk...", parent=overlay)
    UIHeaderText(
        "Please don't use your keyboard or mouse. You can watch as Basilisk works.",
        parent=overlay,
    )
    status_label = UIHeaderText("", parent=overlay, follow_parent_resize=False)
    status_label.raise_()
    status_label.show()
    StatusResizer(overlay, status_label, bottom_margin=title_label._top_margin)
    spinner = QLabel(overlay)
    spinner.setAlignment(Qt.AlignmentFlag.AlignCenter)
    spinner.setStyleSheet("background: transparent;")
    spinner.setGeometry(overlay.width()//2 - 32, overlay.height()//2 + 100, 64, 64)
    movie = QMovie(os.path.join(os.path.dirname(__file__), '../media/spinner.gif'))
    spinner.setMovie(movie)
    movie.start()
    spinner.show()
    base.show()

    def update_status(msg: str):
        QMetaObject.invokeMethod(
            status_label,
            "setText",
            Qt.QueuedConnection,  # type: ignore
            Q_ARG(str, msg),
        )

    def debloat_sequence():
        steps = [
            ("Downloading debloat scripts...", debloat_download_scripts.main),
            ("Executing Raven scripts...",     debloat_execute_raven_scripts.main),
            ("Executing external scripts...",  debloat_execute_external_scripts.main),
            ("Executing privacy.sexy script...", debloat_execute_privacy_sexy.main),
            ("Applying registry tweaks...",    debloat_registry_tweaks.main),
            ("Setting desktop background...",  debloat_apply_background.main),
        ]
        total = len(steps) + 1
        for idx, (message, func) in enumerate(steps, start=1):
            update_status(f"{message} ({idx}/{total} complete)")
            try:
                func()
            except Exception:
                return
        update_status(f"Restarting system… ({total}/{total} complete)")
        subprocess.call(["shutdown", "/r", "/t", "0"])

    def start_thread():
        threading.Thread(target=debloat_sequence, daemon=True).start()

    QTimer.singleShot(0, start_thread)
    sys.exit(app.exec_())  # type: ignore
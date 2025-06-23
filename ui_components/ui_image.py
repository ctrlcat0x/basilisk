import os
import sys
from PyQt5.QtWidgets import QLabel
from PyQt5.QtCore import Qt, QEvent
from PyQt5.QtGui import QPixmap
from utilities.util_load_font import load_font
from utilities.util_error_popup import show_error_popup



class UIImage(QLabel):
    
    def __init__(
        self,
        filename: str,
        parent=None,
        horizontal_buffer: float = 0.3
    ):
        load_font("SpaceGrotesk-Regular.ttf")
        super().__init__("", parent)
        self.setAlignment(Qt.AlignCenter)  # type: ignore
        self.setStyleSheet("background: transparent;")
        if not (0.0 <= horizontal_buffer < 0.5):
            show_error_popup(
                f"Invalid horizontal_buffer: {horizontal_buffer}\n"
                "Must be between 0.0 and 0.5 (exclusive).",
                allow_continue=False
            )
            return
        self._horizontal_buffer = horizontal_buffer
        if getattr(sys, "frozen", False):
            base = os.path.dirname(sys.executable)
        else:
            comp_dir = os.path.dirname(os.path.abspath(__file__))
            base = os.path.dirname(comp_dir)
        img_path = os.path.join(base, "media", filename)
        pix = QPixmap(img_path)
        if pix.isNull():
            show_error_popup(f"Image not found:\n{img_path}", allow_continue=False)
            return
        self._original = pix
        self._update_position()
        if parent:
            parent.installEventFilter(self)

    def eventFilter(self, obj, event):
        if obj is self.parent() and event.type() == QEvent.Resize:  # type: ignore
            self._update_position()
        return False

    def _update_position(self):
        if self.parent():
            w = self.parent().width()  # type: ignore
            h = self.parent().height()  # type: ignore
            pix = self.pixmap()
            if pix:
                pix_w = pix.width()
                pix_h = pix.height()
                scale_w = w / pix_w
                scale_h = h / pix_h
                scale = min(scale_w, scale_h) * self._horizontal_buffer
                new_w = int(pix_w * scale)
                new_h = int(pix_h * scale)
                x = (w - new_w) // 2
                y = (h - new_h) // 2
                self.setGeometry(x, y, new_w, new_h)
                self.setPixmap(pix.scaled(new_w, new_h, Qt.KeepAspectRatio, Qt.SmoothTransformation))  # type: ignore

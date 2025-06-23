from PyQt5.QtWidgets import QLabel
from PyQt5.QtCore import Qt, QEvent
from PyQt5.QtGui import QFont
from utilities.util_load_font import load_font

class UITitleText(QLabel):
    def __init__(self, text: str, parent=None, top_margin: int = 100, font_size: int = 36):
        base_font = load_font("SpaceGrotesk-Regular.ttf")
        super().__init__(text, parent)
        family = base_font.family()
        font = QFont(family, font_size, QFont.Bold)
        self.setFont(font)
        self.setAlignment(Qt.AlignCenter)  # type: ignore
        self.setStyleSheet(f"""
            QLabel {{
                color: white;
                font-family: '{family}';
                font-size: {font_size}px;
                font-weight: bold;
                background: transparent;
            }}
        """)
        self._top_margin = top_margin
        self._update_position()
        if parent:
            parent.installEventFilter(self)

    def _update_position(self):
        if self.parent():
            w = self.parent().width()  # type: ignore
            fm = self.fontMetrics()
            h = fm.height()
            y = self._top_margin
            self.setGeometry(0, y, w, h)

    def eventFilter(self, obj, event):
        if obj is self.parent() and event.type() == QEvent.Resize:  # type: ignore
            self._update_position()
        return False

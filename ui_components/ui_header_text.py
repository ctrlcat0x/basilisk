from PyQt5.QtWidgets import QLabel
from PyQt5.QtCore import Qt, QEvent
from PyQt5.QtGui import QFont
from utilities.util_load_font import load_font



class UIHeaderText(QLabel):

    def __init__(self, text: str, parent=None, top_margin: int = 180, font_size: int = 24, follow_parent_resize: bool = True):
        base_font = load_font("Rockstar-ExtraBold.otf")
        super().__init__(text, parent)
        family = base_font.family()
        font = QFont(family, font_size, QFont.Normal)
        self.setFont(font)
        self.setAttribute(Qt.WA_TranslucentBackground)  # type: ignore
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
        self._follow_parent_resize = follow_parent_resize
        self._update_position()
        if parent and follow_parent_resize:
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

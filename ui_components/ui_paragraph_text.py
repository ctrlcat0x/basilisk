from PyQt5.QtWidgets import QLabel
from PyQt5.QtCore import Qt
from utilities.util_load_font import load_font



class UIParagraphText(QLabel):
    def __init__(
        self,
        text: str,
        parent=None,
        font_size: int = 18,
        color: str = "#FFFFFF",
        alignment="left"
    ):
        load_font("SpaceGrotesk-Regular.ttf")
        super().__init__(parent)
        self.setWordWrap(True)
        self.setText(text)
        self.setStyleSheet(
            f"QLabel {{"
            f"  font-size: {font_size}px;"
            f"  color: {color};"
            f"  padding: 10px;"
            f"}}"
        )
        if alignment == "left":
            self.setAlignment(Qt.AlignLeft | Qt.AlignTop)  # type: ignore
        elif alignment == "center":
            self.setAlignment(Qt.AlignHCenter | Qt.AlignTop)  # type: ignore
        elif alignment == "right":
            self.setAlignment(Qt.AlignRight | Qt.AlignTop)  # type: ignore
        else:
            self.setAlignment(Qt.AlignLeft | Qt.AlignTop)  # type: ignore

    @staticmethod
    def _parse_alignment(algn):
        if isinstance(algn, int):
            return Qt.Alignment(algn)  # type: ignore
        s = str(algn).strip().lower()
        if s == "left":
            return Qt.AlignLeft | Qt.AlignTop # type: ignore
        if s == "center":
            return Qt.AlignHCenter | Qt.AlignTop # type: ignore
        if s == "right":
            return Qt.AlignRight | Qt.AlignTop # type: ignore
        try:
            return getattr(Qt, s)
        except Exception:
            return Qt.AlignLeft | Qt.AlignTop # type: ignore

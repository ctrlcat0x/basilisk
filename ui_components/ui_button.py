from PyQt5.QtWidgets import QPushButton, QGraphicsDropShadowEffect
from PyQt5.QtCore import Qt, QPropertyAnimation
from PyQt5.QtGui import QColor
from utilities.util_load_font import load_font



class UIButton(QPushButton):

    def __init__(self, text: str, color_rgb: tuple, parent=None):
        load_font("Rockstar-ExtraBold.otf")
        super().__init__(text, parent)
        self.setCursor(Qt.PointingHandCursor)  # type: ignore
        r, g, b = color_rgb
        luma = 0.299 * r + 0.587 * g + 0.114 * b
        text_color = "#ffffff" if luma < 186 else "#000000"
        self.setStyleSheet(
            f"QPushButton {{"
            f"  background-color: rgb({r},{g},{b});"
            f"  font-weight: bold;"
            f"  font-size: 20px;"
            f"  color: {text_color};"
            f"  padding: 12px 20px;"
            f"  text-decoration: none;"
            f"  margin: 20px;"
            f"  border: none;"
            f"}}"
        )
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setOffset(0, 0)
        base_blur = 48
        base_alpha = 150
        hover_blur = 64
        hover_alpha = 255
        shadow.setBlurRadius(base_blur)
        base_shadow_col = QColor(r, g, b, base_alpha)
        hover_shadow_col = QColor(r, g, b, hover_alpha)
        shadow.setColor(base_shadow_col)
        self.setGraphicsEffect(shadow)
        self._blur_anim = QPropertyAnimation(shadow, b"blurRadius", self)
        self._blur_anim.setDuration(500)
        self._color_anim = QPropertyAnimation(shadow, b"color", self)
        self._color_anim.setDuration(500)
        self._shadow_effect      = shadow
        self._base_blur          = base_blur
        self._hover_blur         = hover_blur
        self._base_shadow_color  = base_shadow_col
        self._hover_shadow_color = hover_shadow_col

    def enterEvent(self, event):
        self._blur_anim.stop()
        self._blur_anim.setStartValue(self._shadow_effect.blurRadius())
        self._blur_anim.setEndValue(self._hover_blur)
        self._blur_anim.start()
        self._color_anim.stop()
        self._color_anim.setStartValue(self._shadow_effect.color())
        self._color_anim.setEndValue(self._hover_shadow_color)
        self._color_anim.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._blur_anim.stop()
        self._blur_anim.setStartValue(self._shadow_effect.blurRadius())
        self._blur_anim.setEndValue(self._base_blur)
        self._blur_anim.start()
        self._color_anim.stop()
        self._color_anim.setStartValue(self._shadow_effect.color())
        self._color_anim.setEndValue(self._base_shadow_color)
        self._color_anim.start()
        super().leaveEvent(event)
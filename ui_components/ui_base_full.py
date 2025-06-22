import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QGuiApplication
from utilities.util_load_font import load_font



class UIBaseFull:
    def __init__(self):
        load_font("Rockstar-ExtraBold.otf")
        self._create_overlays()

    def _create_overlays(self):
        screens = QGuiApplication.screens()
        if not screens:
            screens = [QGuiApplication.primaryScreen()]
        primary = QGuiApplication.primaryScreen()
        self.overlays = []
        for screen in screens:
            overlay = QMainWindow()
            overlay.setWindowFlags(
                Qt.Window |  # type: ignore
                Qt.FramelessWindowHint |  # type: ignore
                Qt.WindowStaysOnTopHint  # type: ignore
            )
            overlay.setGeometry(screen.geometry())  # type: ignore
            overlay.setStyleSheet("background-color: black;")
            overlay.setObjectName(f"overlay_{screen.name()}")  # type: ignore
            overlay.is_primary = (screen == primary)
            if overlay.is_primary:
                self.primary_overlay = overlay
            self.overlays.append(overlay)
        if not hasattr(self, "primary_overlay") and self.overlays:
            self.primary_overlay = self.overlays[0]

        self.primary_overlay = QWidget()
        self.primary_overlay.setWindowFlags(Qt.Window | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)  # type: ignore
        screen = QApplication.primaryScreen()
        if screen:
            geometry = screen.geometry()  # type: ignore
            self.primary_overlay.setGeometry(geometry)
            self.primary_overlay.setObjectName("primary_overlay")  # type: ignore

    def show(self):
        for overlay in self.overlays:
            overlay.show()



if __name__ == "__main__":
    app = QApplication.instance() or QApplication(sys.argv)
    base = UIBaseFull()
    base.show()
    sys.exit(app.exec_())

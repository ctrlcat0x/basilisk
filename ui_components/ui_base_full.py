import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QGuiApplication
from utilities.util_load_font import load_font
from utilities.util_logger import logger



class UIBaseFull:
    def __init__(self):
        load_font("Rockstar-ExtraBold.otf")
        logger.info("UIBaseFull: Creating overlays...")
        self._create_overlays()

    def _create_overlays(self):
        screens = QGuiApplication.screens()
        if not screens:
            screens = [QGuiApplication.primaryScreen()]
        primary = QGuiApplication.primaryScreen()
        self.overlays = []
        self.primary_overlay = None
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
        if not self.primary_overlay and self.overlays:
            self.primary_overlay = self.overlays[0]
        logger.info(f"UIBaseFull: Created {len(self.overlays)} overlays. Primary overlay: {self.primary_overlay.objectName() if self.primary_overlay else 'None'}")

    def show(self):
        logger.info("UIBaseFull: Showing overlays...")
        for overlay in self.overlays:
            overlay.show()
        if self.primary_overlay:
            self.primary_overlay.show()
        else:
            logger.error("UIBaseFull: No primary_overlay to show!")



if __name__ == "__main__":
    app = QApplication.instance() or QApplication(sys.argv)
    base = UIBaseFull()
    base.show()
    sys.exit(app.exec_())

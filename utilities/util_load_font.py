import os
import sys
from PyQt5.QtGui import QFontDatabase, QFont
from PyQt5.QtWidgets import QApplication
from utilities.util_logger import logger
from utilities.util_error_popup import show_error_popup



def load_font(filename: str, default_size: int = None) -> QFont:
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        utilities_dir = os.path.dirname(os.path.abspath(__file__))
        base_path = os.path.dirname(utilities_dir)
    font_path = os.path.join(base_path, 'media', filename)

    if not os.path.exists(font_path):
        logger.error(f"Font file not found: {font_path}")
        show_error_popup(f"Font file not found:\n{font_path}", allow_continue=False)
        raise FileNotFoundError(f"Font file not found: {font_path}")
    font_id = QFontDatabase.addApplicationFont(font_path)
    if font_id == -1:
        logger.error(f"Failed to load font: {font_path}")
        show_error_popup(f"Failed to load font file:\n{font_path}", allow_continue=False)
        raise RuntimeError(f"Failed to load font: {font_path}")
    families = QFontDatabase.applicationFontFamilies(font_id)
    if not families:
        logger.error(f"No font families found in file: {font_path}")
        show_error_popup(f"No font families found in font file:\n{font_path}", allow_continue=False)
        raise RuntimeError(f"No font families in file: {font_path}")
    family = families[0]
    if default_size is None:
        default_size = app.font().pointSize()
    font = QFont(family, default_size)
    QApplication.setFont(font)
    logger.info(f"Loaded and set application font: '{family}' from '{filename}' at size {default_size}")
    return font

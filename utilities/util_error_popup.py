import sys
import threading
from PyQt5.QtWidgets import (
    QApplication,
    QDialog,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
)
from PyQt5.QtCore import QObject, pyqtSignal, Qt, QThread, QCoreApplication



class ErrorDialogManager(QObject):
    showDialog = pyqtSignal(str, bool, object)

    def __init__(self):
        super().__init__()
        self.showDialog.connect(self._on_showDialog)

    def _on_showDialog(self, message, allow_continue, event):
        dialog = QDialog()
        dialog.setWindowFlags(dialog.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        dialog.setWindowTitle("Error")
        dialog.setWindowModality(Qt.ApplicationModal)
        layout = QVBoxLayout(dialog)
        label = QLabel(message)
        label.setWordWrap(True)
        layout.addWidget(label)
        btn_stop = QPushButton("Stop Installation")
        btn_stop.clicked.connect(dialog.reject)
        button_layout = QHBoxLayout()
        button_layout.addWidget(btn_stop)
        if allow_continue:
            btn_continue = QPushButton("Continue Anyways")
            btn_continue.clicked.connect(dialog.accept)
            button_layout.addWidget(btn_continue)
        layout.addLayout(button_layout)
        result = dialog.exec_()
        event.result = (result == QDialog.Accepted)
        event.set()



_manager = None



def _get_manager():
    global _manager
    if _manager is None:
        _manager = ErrorDialogManager()
        app = QApplication.instance()
        if app:
            _manager.moveToThread(app.thread())
    return _manager



def _show_dialog_direct(message, allow_continue):
    dialog = QDialog()
    dialog.setWindowFlags(dialog.windowFlags() & ~Qt.WindowContextHelpButtonHint)
    dialog.setWindowTitle("Error")
    dialog.setWindowModality(Qt.ApplicationModal)
    layout = QVBoxLayout(dialog)
    label = QLabel(message)
    label.setWordWrap(True)
    layout.addWidget(label)
    btn_stop = QPushButton("Stop Installation")
    btn_stop.clicked.connect(dialog.reject)
    button_layout = QHBoxLayout()
    button_layout.addWidget(btn_stop)
    if allow_continue:
        btn_continue = QPushButton("Continue Anyways")
        btn_continue.clicked.connect(dialog.accept)
        button_layout.addWidget(btn_continue)
    layout.addLayout(button_layout)
    result = dialog.exec_()
    return result == QDialog.Accepted



def show_error_popup(message, allow_continue=False):
    app = QApplication.instance() or QApplication(sys.argv)
    overlay_states = []
    for w in app.topLevelWidgets():
        if w.objectName().startswith("overlay_"):
            overlay_states.append((w, w.isVisible()))
            w.hide()
    if QThread.currentThread() == QCoreApplication.instance().thread():
        result = _show_dialog_direct(message, allow_continue)
    else:
        manager = _get_manager()
        event = threading.Event()
        event.result = False
        manager.showDialog.emit(message, allow_continue, event)
        event.wait()
        result = event.result
    if result:
        for w, was_visible in overlay_states:
            if was_visible:
                w.show()
    if not result:
        sys.exit(1)
    return True

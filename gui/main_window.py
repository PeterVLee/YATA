"""
Main window containing TOTP codes and kicks off other windows
like the password checker
"""

import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDial,
    QDoubleSpinBox,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QSlider,
    QSpinBox,
)

from password_checker import PasswordWindow

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("YATA")
        self.password = ''
        self.show_password_window()

    def show_password_window(self):
        self.password_window = PasswordWindow()
        self.password_window.signal_password.connect(self.password_signal_handler)
        self.password_window.show()

    def password_signal_handler(self, password:str):
        self.password = password
        print(f"main says {password}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec()

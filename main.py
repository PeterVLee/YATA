from PySide6.QtWidgets import QApplication

from gui.password_checker import PasswordWindow

if __name__ == "__main__":
    app = QApplication([])
    window = PasswordWindow()
    window.show()
    app.exec()

import sys

from PySide6.QtCore import Signal, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QLineEdit,
    QMainWindow,
    QVBoxLayout,
    QWidget
)

import utils.locked_handler

class PasswordWindow(QMainWindow):

    # signal used to emit password to main window
    signal_password = Signal(str)

    def __init__(self):
        super().__init__()

        self.check_default_password()

        self.setWindowTitle("Enter Password")

        layout = QVBoxLayout()

        self.lbl_password_prompt = QLabel("Enter password to unlock")
        font = self.lbl_password_prompt.font()
        font.setPointSize(12)
        self.lbl_password_prompt.setFont(font)

        self.txt_password_input = QLineEdit()
        self.txt_password_input.setPlaceholderText("Enter password")
        self.txt_password_input.setEchoMode(QLineEdit.Password)
        self.txt_password_input.returnPressed.connect(self.returnPressed)

        layout.addWidget(self.lbl_password_prompt)
        layout.addWidget(self.txt_password_input)

        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

    def returnPressed(self):
        pass_attempt = self.txt_password_input.text()
        print(pass_attempt)

        try:
            utils.locked_handler.decrypt_file_with_password(pass_attempt)
            self.lbl_password_prompt.setText("Unlocking...")
            print("good")
            self.signal_password.emit(pass_attempt)
            self.close()
        except:
            self.lbl_password_prompt.setText("Wrong password")
            print("wrong")

    def check_default_password(self):
        """Check if default password works on file first
        """
        try:
            utils.locked_handler.decrypt_file_with_password()
            self.signal_password.emit('')
            # using singleShot to let init completely create window first
            print("Default works")
            QTimer.singleShot(0, self.close)
        except:
            print("Default doesn't work")

#debugging
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordWindow()
    window.show()
    app.exec()

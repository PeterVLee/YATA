import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QLineEdit,
    QMainWindow,
    QVBoxLayout,
    QWidget
)

import file_utils.locked_handler

class PasswordWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        if self.check_default_password():
            ...
            # this is where you tell the main window the default password works
            print("default workd")
        else:
            print("defaulyt no work")

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
            file_utils.locked_handler.decrypt_file_with_password(pass_attempt)
            self.lbl_password_prompt.setText("Unlocking...")
            print("good")
        except:
            self.lbl_password_prompt.setText("Wrong password")
            print("wrong")

    def check_default_password(self) -> bool:
        """Check if default password works on file first

        Returns:
            bool: If default works, True
        """
        try:
            file_utils.locked_handler.decrypt_file_with_password()
            return True
        except:
            print("Default doesn't work")
            return False

#debugging
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordWindow()
    window.show()
    app.exec()

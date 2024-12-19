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
    QVBoxLayout,
    QWidget
)

import file_utils.locked_handler

class PasswordWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("YATA")

        self.lbl_password_prompt = QLabel("Enter password to unlock")
        font = self.lbl_password_prompt.font()
        font.setPointSize(12)
        self.lbl_password_prompt.setFont(font)

        self.txt_password_input = QLineEdit()
        self.txt_password_input.setPlaceholderText("Enter password")
        self.txt_password_input.setEchoMode(QLineEdit.Password)

        self.lbl_status = QLabel("")
        font = self.lbl_status.font()
        font.setPointSize(12)
        self.lbl_status.setFont(font)

        self.txt_password_input.returnPressed.connect(self.returnPressed)

        # layout no worky, learn harder
        central_widget = QWidget()
        self.setCentralWidget(self.txt_password_input)

        layout = QVBoxLayout(central_widget)

        layout.addWidget(self.lbl_password_prompt)
        layout.addWidget(self.lbl_status)

    def returnPressed(self):
        pass_attempt = self.txt_password_input.text()
        print(pass_attempt)
        df_secrets = file_utils.locked_handler.decrypt_file_with_password(pass_attempt)

        # TODO no worky
        if df_secrets.empty == True:
            self.lbl_status.setText("Wrong password")
        else:
            self.lbl_status.setText("Unlocking...")

#debugging
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordWindow()
    window.show()
    app.exec()

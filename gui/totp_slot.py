"""Widget to show TOTP info like codes, times, etc.

Planned to look something like this:

   v icon
|---------------------|
| xxx  Google         |   <- service
| xxx  123456  109539 |   <- current and next OTP
| xxx  :26            |   <- time left
|---------------------|

planned features:
- clicking on widget copies current code
- resizing widget changes layout and font size
"""

import time

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
   QApplication,
   QMainWindow,
   QLabel,
   QHBoxLayout,
   QVBoxLayout,
   QWidget
)
from PySide6.QtGui import QGuiApplication

from totp.totp_generator import get_totp_offset
from utils.locked_handler import decrypt_file_with_password

class TotpSlotWidget(QWidget):

   def __init__(self, services: dict):
      """Currently designed such that this widget has to be called every second to work.

      Might change have it independently update itself.

      Args:
          service (dict): Dictionary containing service info, currently
            only deals with 'name' and 'secret' keys
          time_left (int): Time left until next OTP i.e. 30 - current_time % 30
      """
      super().__init__()

      self.services = services

      h_layout = QHBoxLayout()
      v_layout_service_and_time = QVBoxLayout()
      v_layout_otp = QVBoxLayout()

      # icon/image label
      self.lbl_icon = QLabel("icon")
      #self.lbl_icon.setPixmap("icon.png")

      self.lbl_service_name = QLabel(services['name'])

      current_otp = get_totp_offset(services['secret'])
      next_otp = get_totp_offset(services['secret'], 30)

      self.lbl_current_otp = QLabel(current_otp)
      self.lbl_next_otp = QLabel(next_otp)

      self.lbl_time_left = QLabel()

      h_layout.addWidget(self.lbl_icon)
      h_layout.addLayout(v_layout_service_and_time)
      h_layout.addLayout(v_layout_otp)

      v_layout_service_and_time.addWidget(self.lbl_service_name)
      v_layout_service_and_time.addWidget(self.lbl_time_left)

      v_layout_otp.addWidget(self.lbl_current_otp)
      v_layout_otp.addWidget(self.lbl_next_otp)

      self.setLayout(h_layout)

      # timer to update widget
      self.timer = QTimer(self)
      self.timer.timeout.connect(self.update_widget)

      milliseconds_left = round(time.time() * 1000) % 1000
      self.timer.start(1000 - milliseconds_left) # we do 500ms to make it smoother, 1000ms causes a weird delay effect

      # set up styles
      self.lbl_service_name.setObjectName("serviceName")
      self.lbl_current_otp.setObjectName("currentOtp")
      self.lbl_next_otp.setObjectName("nextOtp")
      self.lbl_time_left.setObjectName("timeLeft")
      self.setObjectName("totpSlotWidget")

      self.setStyleSheet("""
         QLabel {
            font-size: 14px;
         }
         QLabel#serviceName {
            font-weight: bold;
            font-size: 16px;
         }
         QLabel#currentOtp {
            color: green;
         }
         QLabel#nextOtp {
            color: red;
         }
         QLabel#timeLeft {
            font-style: italic;
         }
      """)

   def update_widget(self):
      time_left = 30 - int(time.time()) % 30
      self.lbl_time_left.setText(f":{time_left}")

      self.lbl_current_otp.setText(get_totp_offset(self.services['secret']))
      self.lbl_next_otp.setText(get_totp_offset(self.services['secret'], 30))

   def mousePressEvent(self, event):
      clipboard = QGuiApplication.clipboard()
      self.lbl_current_otp.text


# debugging --------------------------------------------------

class MainWindow(QMainWindow):
   def __init__(self):
      super().__init__()

      self.setWindowTitle("YATA")

      central_widget = QWidget()
      self.setCentralWidget(central_widget)

      layout = QVBoxLayout(central_widget)

      services = decrypt_file_with_password()['services']

      for service in services:
         totp_widget = TotpSlotWidget(service)
         layout.addWidget(totp_widget)

if __name__ == "__main__":
    app = QApplication([])

    window = MainWindow()
    window.show()

    app.exec()

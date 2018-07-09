# Creates a GUI with a toolbar, menubar, statusbar, central widget

import sys
import base64
from Crypto.Cipher import AES
from Crypto import Random
from numpy.random import choice
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QLineEdit, QPushButton, QLabel, QCheckBox,
                             QMessageBox, QTextEdit)
from PyQt5.QtGui import QIcon


class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, msg):
        msg = base64.b64decode(msg)
        iv = msg[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return cipher.decrypt(msg[AES.block_size:])

class MessageWindow(QWidget):
    def __init__(self):
        super(MessageWindow, self).__init__()
        self.iconfilepath1 = '/home/justin/Pictures/Icons/quit.png'
        self.iconfilepath2 = '/home/justin/Python/labplot.png'
        self.left = 300
        self.top = 200
        self.width = 1200
        self.height = 400
        self.key = 'ABCDEFGHIJKLMNOPQRSTUVWXYZQWERTY' # MUST be 16, 24, or 32 characters long
        self.cypher = AESCipher(self.key)
        self.initUI()

    def encrypt(self):
        raw = self.encrypt_box.toPlainText()
        encoded = self.cypher.encrypt(raw)
        self.decrypt_box.setText(encoded)


    def decrypt(self):
        encoded = self.decrypt_box.toPlainText()
        msg = self.cypher.decrypt(encoded)
        self.encrypt_box.setText(msg)


    def initUI(self):
        # Set window title, icon
        self.setWindowTitle('AES Messaging')
        self.setWindowIcon(QIcon(self.iconfilepath2))

        # Set window size and move it on screen
        self.resize(self.width,self.height)
        self.move(self.left,self.top)

        self.window = QHBoxLayout()

        self.vbox1 = QVBoxLayout()
        self.enc_title_box = QHBoxLayout()
        self.enc_box = QHBoxLayout()

        self.vbox2 = QVBoxLayout()
        self.buttons_box = QVBoxLayout()


        self.vbox3 = QVBoxLayout()
        self.dec_title_box = QHBoxLayout()
        self.dec_box = QHBoxLayout()


        self.window.addLayout(self.vbox1)
        self.window.addLayout(self.vbox2)
        self.window.addLayout(self.vbox3)

        self.vbox1.addLayout(self.enc_title_box)
        self.vbox1.addLayout(self.enc_box)

        self.vbox2.addLayout(self.buttons_box)

        self.vbox3.addLayout(self.dec_title_box)
        self.vbox3.addLayout(self.dec_box)


        # Create input lines
        self.encrypt_box = QTextEdit()
        self.decrypt_box = QTextEdit()

        # Labels
        self.encrypt_title = QLabel('Enter a message to encrypt: ')
        self.decrypt_title = QLabel('Enter a message to decrypt: ')

        # Buttons that call encrypt/decrypt methods
        self.encrypt_button = QPushButton('Encrypt')
        self.encrypt_button.clicked.connect(self.encrypt)
        self.decrypt_button = QPushButton('Decrypt')
        self.decrypt_button.clicked.connect(self.decrypt)

        self.enc_title_box.addWidget(self.encrypt_title)
        self.enc_box.addWidget(self.encrypt_box)

        self.buttons_box.addWidget(self.encrypt_button)
        self.buttons_box.addWidget(self.decrypt_button)

        self.dec_title_box.addWidget(self.decrypt_title)
        self.dec_box.addWidget(self.decrypt_box)
        #self.dec_box.addWidget(self.decrypt_button)

        self.setLayout(self.window)
        self.show()

        """
        # Layout boxes
        self.vbox = QVBoxLayout()
        self.hbox = QHBoxLayout()
        self.vbox1 = QVBoxLayout()
        self.vbox2 = QVBoxLayout()
        self.box1 = QHBoxLayout()
        self.box2 = QHBoxLayout()
        self.box3 = QHBoxLayout()
        self.box4 = QHBoxLayout()

        # Place widgets in layout boxes and space them out
        self.vbox.addLayout(self.box1)
        self.box1.addWidget(self.encrypt_title)
        self.box1.addWidget(self.encrypt_box)
        self.box1.addWidget(self.encrypt_button)

        self.vbox.addLayout(self.box2)
        self.box2.addWidget(self.encrypted_title)
        self.box2.addWidget(self.encrypted_box)

        self.vbox.addLayout(self.box3)
        self.box3.addWidget(self.decrypt_title)
        self.box3.addWidget(self.decrypt_box)
        self.box3.addWidget(self.decrypt_button)

        self.vbox.addLayout(self.box4)
        self.box4.addWidget(self.decrypted_title)
        self.box4.addWidget(self.decrypted_box)

        # Set it all and show it
        self.setLayout(self.vbox)
        self.show()
        """
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = MessageWindow()
    sys.exit(app.exec_())

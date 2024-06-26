import sys
import os
import hashlib
import hmac
import base64
import numpy as np
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QHBoxLayout, QTextEdit, QLabel, QLineEdit, QSpinBox, QProgressBar, QStatusBar
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# S-Box Definition
S_BOX = [
    [0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D],
    [0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1],
    [0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F],
    [0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F],
    [0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC],
    [0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87],
    [0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1],
    [0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57],
    [0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03],
    [0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A],
    [0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9B, 0x41, 0x20],
    [0x55, 0x49, 0x6C, 0xC2, 0xDB, 0xA3, 0x17, 0x26, 0xA6, 0xD9, 0x69, 0x59, 0x2F, 0x6B, 0x3F, 0xAF],
    [0x3B, 0xF4, 0x9F, 0xFB, 0x7D, 0x1B, 0x69, 0x83, 0x58, 0x9C, 0x6D, 0xDD, 0x67, 0xE4, 0x9D, 0xC1],
    [0x23, 0x3E, 0xE3, 0x39, 0x8B, 0xB4, 0x41, 0x61, 0x93, 0x7F, 0xDE, 0x42, 0xF1, 0x0E, 0x2C, 0xDF],
    [0x3C, 0x5D, 0x95, 0x4C, 0xC5, 0x0F, 0x76, 0x30, 0xA9, 0x92, 0x91, 0x40, 0xE1, 0x0A, 0x6F, 0x77],
    [0xD2, 0x5F, 0x53, 0x7B, 0x37, 0xA5, 0xCD, 0xB3, 0xE6, 0xB0, 0xE9, 0x87, 0xB7, 0x9B, 0xC4, 0x64]
]

def pbkdf2_hmac_sha256(password, salt, iterations, dklen):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen)

def derive_parameters(key1, key2):
    salt = hashlib.sha256(key1.encode('utf-8')).digest()
    dk = pbkdf2_hmac_sha256(key2, salt, 100000, 32)
    x0 = int.from_bytes(dk[:16], byteorder='big') / (1 << 128)
    mu = 1.5 + (int.from_bytes(dk[16:], byteorder='big') / (1 << 128)) * 0.5
    return x0, mu

def tent_map(x, mu):
    return mu * x if x < 0.5 else mu * (1 - x)

def logistic_map(x):
    r = 3.99
    return r * x * (1 - x)

def generate_chaotic_sequence(length, x0, mu):
    sequence = np.zeros(length)
    x = x0
    for i in range(length):
        x = logistic_map(tent_map(x, mu))
        sequence[i] = x
    return sequence

def apply_s_box(byte):
    return S_BOX[byte >> 4][byte & 0x0F]

def key_influence(sequence, key1, key2):
    key1_bytes = np.frombuffer(key1.encode('utf-8'), dtype=np.uint8)
    key2_bytes = np.frombuffer(key2.encode('utf-8'), dtype=np.uint8)
    max_len = max(len(key1_bytes), len(key2_bytes))
    key1_bytes = np.tile(key1_bytes, max_len // len(key1_bytes) + 1)[:max_len]
    key2_bytes = np.tile(key2_bytes, max_len // len(key2_bytes) + 1)[:max_len]
    combined_key_bytes = (key1_bytes + key2_bytes) % 256
    key_sequence = np.repeat(combined_key_bytes, len(sequence) // len(combined_key_bytes) + 1)[:len(sequence)]
    influenced_sequence = (sequence * 255 + key_sequence) % 256
    influenced_sequence = np.vectorize(apply_s_box)(influenced_sequence.astype(np.uint8))
    return influenced_sequence

def encrypt_round(data, key1, key2):
    x0, mu = derive_parameters(key1, key2)
    iv = os.urandom(16)
    chaotic_sequence = generate_chaotic_sequence(len(data), x0, mu)
    influenced_sequence = key_influence(chaotic_sequence, key1, key2)
    ciphertext_bytes = np.bitwise_xor(np.frombuffer(data, dtype=np.uint8), influenced_sequence.astype(np.uint8))
    hmac_key = pbkdf2_hmac_sha256(key2, iv, 100000, 32)
    hmac_digest = hmac.new(hmac_key, iv + ciphertext_bytes.tobytes(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(iv + ciphertext_bytes.tobytes() + hmac_digest)

def encrypt(plaintext, key1, key2, rounds=2, progress_callback=None):
    total_length = len(plaintext)
    ciphertext = plaintext
    for i in range(rounds):
        ciphertext = encrypt_round(ciphertext, key1, key2)
        if progress_callback:
            progress_callback(int((i + 1) / rounds * 100))
    return ciphertext

def decrypt_round(ciphertext, key1, key2):
    ciphertext_bytes = base64.urlsafe_b64decode(ciphertext)
    iv = ciphertext_bytes[:16]
    hmac_digest_received = ciphertext_bytes[-32:]
    encrypted_data = ciphertext_bytes[16:-32]
    hmac_key = pbkdf2_hmac_sha256(key2, iv, 100000, 32)
    hmac_digest_calculated = hmac.new(hmac_key, iv + encrypted_data, hashlib.sha256).digest()
    if not hmac.compare_digest(hmac_digest_received, hmac_digest_calculated):
        raise ValueError("HMAC verification failed, data may have been tampered with")
    x0, mu = derive_parameters(key1, key2)
    chaotic_sequence = generate_chaotic_sequence(len(encrypted_data), x0, mu)
    influenced_sequence = key_influence(chaotic_sequence, key1, key2)
    decrypted_data = np.bitwise_xor(np.frombuffer(encrypted_data, dtype=np.uint8), influenced_sequence.astype(np.uint8))
    return decrypted_data.tobytes()

def decrypt(ciphertext, key1, key2, rounds=2, progress_callback=None):
    decrypted_text = ciphertext
    for i in range(rounds):
        decrypted_text = decrypt_round(decrypted_text, key1, key2)
        if progress_callback:
            progress_callback(int((i + 1) / rounds * 100))
    return decrypted_text

def encrypt_string(plaintext, key1, key2, rounds=2, progress_callback=None):
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext_bytes = encrypt(plaintext_bytes, key1, key2, rounds, progress_callback)
    return base64.urlsafe_b64encode(ciphertext_bytes).decode('utf-8')

def decrypt_string(ciphertext, key1, key2, rounds=2, progress_callback=None):
    ciphertext_bytes = base64.urlsafe_b64decode(ciphertext)
    decrypted_bytes = decrypt(ciphertext_bytes, key1, key2, rounds, progress_callback)
    return decrypted_bytes.decode('utf-8')

class CryptoWorker(QThread):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)

    def __init__(self, mode, text, key1, key2, rounds, file_path=''):
        super().__init__()
        self.mode = mode
        self.text = text
        self.key1 = key1
        self.key2 = key2
        self.rounds = rounds
        self.file_path = file_path

    def run(self):
        try:
            if self.mode == 'encrypt':
                if self.file_path:
                    self.status.emit("🧮 Encrypting file...")
                    if not os.path.isfile(self.file_path):
                        raise ValueError("❌ Invalid file path.")
                    with open(self.file_path, 'rb') as f:
                        plaintext = f.read()
                    total_length = len(plaintext)
                    ciphertext = encrypt(plaintext, self.key1, self.key2, rounds=self.rounds, progress_callback=self.report_progress)
                    enc_file_path = self.file_path + ".UCenc"
                    with open(enc_file_path, 'wb') as f:
                        f.write(ciphertext)
                    self.status.emit(f"😃 File encrypted and saved to {enc_file_path}")
                else:
                    self.status.emit("🧮 Encrypting text...")
                    ciphertext = encrypt_string(self.text, self.key1, self.key2, rounds=self.rounds, progress_callback=self.report_progress)
                    self.status.emit("😃 Text encrypted.")
                    self.text = ciphertext

            elif self.mode == 'decrypt':
                if self.file_path:
                    self.status.emit("🧮 Decrypting file...")
                    if not os.path.isfile(self.file_path):
                        raise ValueError("❌ Invalid file path.")
                    with open(self.file_path, 'rb') as f:
                        ciphertext = f.read()
                    total_length = len(ciphertext)
                    decrypted_text = decrypt(ciphertext, self.key1, self.key2, rounds=self.rounds, progress_callback=self.report_progress)
                    dec_file_path = self.file_path.replace(".UCenc", "")
                    with open(dec_file_path, 'wb') as f:
                        f.write(decrypted_text)
                    self.status.emit(f"😃 File decrypted and saved to {dec_file_path}")
                else:
                    self.status.emit("🧮 Decrypting text...")
                    decrypted_text = decrypt_string(self.text, self.key1, self.key2, rounds=self.rounds, progress_callback=self.report_progress)
                    self.status.emit("😃 Text decrypted.")
                    self.text = decrypted_text
        except Exception as e:
            self.status.emit(f"🥲 Operation failed: {e}")

    def report_progress(self, value):
        self.progress.emit(value)

class CryptoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Ultimate Chaos Enc')
        self.setGeometry(100, 100, 800, 600)
        self.setAcceptDrops(True)

        # Set colors and styles
        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: #00FF00;
                font-family: Arial;
            }
            QPushButton {
                background-color: #1E1E1E;
                border: 1px solid #00FF00;
                color: #00FF00;
                font-weight: bold;
                padding: 10px;
            }
            QLineEdit, QTextEdit {
                background-color: #1E1E1E;
                border: 1px solid #00FF00;
                color: #00FF00;
                font-weight: bold;
            }
            QLabel {
                color: #00FF00;
            }
            QSpinBox {
                background-color: #1E1E1E;
                border: 1px solid #00FF00;
                color: #00FF00;
                font-weight: bold;
                max-width: 100px;
            }
            QProgressBar {
                background-color: #1E1E1E;
                border: 1px solid #00FF00;
                color: #00FF00;
            }
            QStatusBar {
                background: transparent;
                color: #FF0000;
                border: 1px solid #FF0000;
                text-align: center;
            }
        """)

        # Layout
        vbox = QVBoxLayout()

        # Status bar and progress bar
        self.status_bar = QStatusBar(self)
        self.status_bar.setStyleSheet("QStatusBar::item {border: none;}")  # Remove the border around the text
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setTextVisible(False)
        vbox.addWidget(self.progress_bar)
        vbox.addWidget(self.status_bar)

        # Key input
        key_hbox = QHBoxLayout()
        self.key1_input = QLineEdit(self)
        self.key1_input.setPlaceholderText("Enter Key 1")
        self.key2_input = QLineEdit(self)
        self.key2_input.setPlaceholderText("Enter Key 2")
        key_hbox.addWidget(QLabel("🔑【Key 1】"))
        key_hbox.addWidget(self.key1_input)
        key_hbox.addWidget(QLabel("🔑【Key 2】"))
        key_hbox.addWidget(self.key2_input)
        vbox.addLayout(key_hbox)

        # File path input
        self.file_path_input = QLineEdit(self)
        self.file_path_input.setPlaceholderText("Enter file path or drag and drop a file here")
        vbox.addWidget(QLabel("📃【File Path】:"))
        vbox.addWidget(self.file_path_input)

        # Rounds input
        self.rounds_input = QSpinBox(self)
        self.rounds_input.setRange(1, 1000)
        self.rounds_input.setValue(2)
        vbox.addWidget(QLabel("🔢【Encryption/Decryption Rounds】:"))
        vbox.addWidget(self.rounds_input)

        # Plaintext and ciphertext areas
        self.plaintext_edit = QTextEdit(self)
        self.ciphertext_edit = QTextEdit(self)
        vbox.addWidget(QLabel("🟩【Plaintext】 🔓"))
        vbox.addWidget(self.plaintext_edit)
        vbox.addWidget(QLabel("🟥【Ciphertext】 🔒"))
        vbox.addWidget(self.ciphertext_edit)

        # Buttons
        self.encrypt_button = QPushButton("🔒 Encrypt", self)
        self.decrypt_button = QPushButton("🔓 Decrypt", self)
        self.encrypt_button.clicked.connect(self.encrypt_data)
        self.decrypt_button.clicked.connect(self.decrypt_data)

        hbox = QHBoxLayout()
        hbox.addWidget(self.encrypt_button)
        hbox.addWidget(self.decrypt_button)
        vbox.addLayout(hbox)

        # Bottom info label
        self.info_label = QLabel("This software is created by LaoChou, using the UltimateChaos algorithm designed by LaoChou.", self)
        self.info_label.setStyleSheet("color: #AAAAAA;")
        vbox.addWidget(self.info_label, alignment=Qt.AlignCenter)

        self.setLayout(vbox)
        self.status_bar.showMessage("✅ Ready - The program is ready to perform encryption and decryption tasks.")

    def encrypt_data(self):
        key1 = self.key1_input.text()
        key2 = self.key2_input.text()
        file_path = self.file_path_input.text()
        rounds = self.rounds_input.value()
        plaintext = self.plaintext_edit.toPlainText()

        self.progress_bar.setValue(0)
        self.status_bar.showMessage("🧮 Starting encryption...")

        if file_path:
            self.worker = CryptoWorker('encrypt', '', key1, key2, rounds, file_path)
        else:
            self.worker = CryptoWorker('encrypt', plaintext, key1, key2, rounds)

        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.status.connect(self.status_bar.showMessage)
        self.worker.finished.connect(self.on_encrypt_complete)
        self.worker.start()

    def on_encrypt_complete(self):
        if not self.file_path_input.text():
            self.ciphertext_edit.setText(self.worker.text)
        self.progress_bar.setValue(100)
        self.status_bar.showMessage("😃 Encryption complete")

    def decrypt_data(self):
        key1 = self.key1_input.text()
        key2 = self.key2_input.text()
        file_path = self.file_path_input.text()
        rounds = self.rounds_input.value()
        ciphertext = self.ciphertext_edit.toPlainText()

        self.progress_bar.setValue(0)
        self.status_bar.showMessage("🧮 Starting decryption...")

        if file_path:
            self.worker = CryptoWorker('decrypt', '', key1, key2, rounds, file_path)
        else:
            self.worker = CryptoWorker('decrypt', ciphertext, key1, key2, rounds)

        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.status.connect(self.status_bar.showMessage)
        self.worker.finished.connect(self.on_decrypt_complete)
        self.worker.start()

    def on_decrypt_complete(self):
        if not self.file_path_input.text():
            self.plaintext_edit.setText(self.worker.text)
        self.progress_bar.setValue(100)
        self.status_bar.showMessage("😃 Decryption complete")

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.file_path_input.setText(file_path)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    crypto_app = CryptoApp()
    crypto_app.show()
    sys.exit(app.exec_())

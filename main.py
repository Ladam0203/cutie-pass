import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget, QMessageBox

from repository import Repository
from security import Security


class CutiePass(QMainWindow):
    def __init__(self, repository, security):
        super().__init__()
        self.repository = repository
        self.security = security

        self.initUI()

    def initUI(self):
        self.setWindowTitle("Password Manager")
        self.setGeometry(300, 300, 400, 200)

        # Layout and widgets
        self.layout = QVBoxLayout()

        # Label for instructions
        self.label = QLabel()
        is_master_password_set = self.repository.is_master_password_set()
        if is_master_password_set:
            self.label.setText("Enter your master password:")
        else:
            self.label.setText("Set your master password:")
        self.layout.addWidget(self.label)

        # Input field for master password
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)  # Hide the password input
        self.layout.addWidget(self.password_input)

        # Submit button
        self.submit_button = QPushButton()
        self.layout.addWidget(self.submit_button)
        if is_master_password_set:
            self.submit_button.setText("Unlock")
            self.submit_button.clicked.connect(self.verify_master_password)
        else:
            self.submit_button.setText("Set")
            self.submit_button.clicked.connect(self.set_master_password)

        # Setting the main widget
        self.main_widget = QWidget()
        self.main_widget.setLayout(self.layout)
        self.setCentralWidget(self.main_widget)

    def set_master_password(self):
        password = self.password_input.text()

        # Generate the hashed password, salt, encrypted token, and nonce
        encrypted_token, salt, nonce = self.security.generate_master_password_data(password)

        # Save the hashed password, salt, encrypted token, and nonce in the settings table
        self.repository.save_master_password_data(encrypted_token, salt, nonce)
        print("Master password set")

    def verify_master_password(self):
        entered_password = self.password_input.text()

        result = self.repository.get_master_password_data()

        if result:
            encrypted_token, salt, nonce = result
            can_decrypt = self.security.can_decrypt_master_password_data(encrypted_token, salt, nonce, entered_password)

            print("Password is correct" if can_decrypt else "Password is incorrect")
            return can_decrypt

        print("No master password set")
        return False

def main():
    repository = Repository()
    security = Security()

    app = QApplication(sys.argv)
    window = CutiePass(repository, security)
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()

# add_credential_dialog.py

from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLineEdit, QPushButton, QLabel, QMessageBox


class AddCredentialDialog(QDialog):
    def __init__(self, repository, security, master_password, parent=None):
        super().__init__(parent)
        self.repository = repository
        self.security = security
        self.master_password = master_password
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Add New Credential")
        self.setGeometry(300, 300, 300, 200)

        # Layout for the dialog
        self.layout = QVBoxLayout()

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Name")
        self.layout.addWidget(self.name_input)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.layout.addWidget(self.password_input)

        self.save_button = QPushButton("Save Credential")
        self.save_button.clicked.connect(self.save_credential)
        self.layout.addWidget(self.save_button)

        self.setLayout(self.layout)

    def save_credential(self):
        # Get the credentials from input fields
        name = self.name_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        if name and username and password:
            # Fetch the stored master password data
            result = self.repository.get_master_password_data()

            if result:
                encrypted_token, salt, nonce = result

                # Derive encryption key from the master password
                encryption_key = self.security.derive_key(self.master_password, salt)

                # Encrypt the username and password using the encryption key
                encrypted_username = self.security.encrypt_data(username, encryption_key, nonce)
                encrypted_password = self.security.encrypt_data(password, encryption_key, nonce)

                # Save the encrypted data to the repository
                self.repository.save_credential(name, encrypted_username, encrypted_password)
                print(f"Credential for {name} saved and encrypted.")

                # Close the dialog
                self.accept()
            else:
                print("Unable to fetch master password data.")
                QMessageBox.warning(self, "Error", "Unable to fetch master password data.")
        else:
            QMessageBox.warning(self, "Input Error", "Please fill out all fields.")


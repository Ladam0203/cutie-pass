from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QFormLayout, QMessageBox

class EditCredentialDialog(QDialog):
    def __init__(self, repository, security, master_password, credential_id, name, username, password, parent=None):
        super().__init__(parent)
        self.repository = repository
        self.security = security
        self.master_password = master_password
        self.credential_id = credential_id  # Store the credential ID
        self.credential_name = name

        self.initUI(username, password)

    def initUI(self, username, password):
        self.setWindowTitle("Edit Credential")
        self.setGeometry(350, 350, 300, 200)

        layout = QVBoxLayout()

        form_layout = QFormLayout()
        self.name_input = QLineEdit(self.credential_name)
        self.username_input = QLineEdit(username)
        self.password_input = QLineEdit(password)
        form_layout.addRow(QLabel("Name:"), self.name_input)
        form_layout.addRow(QLabel("Username:"), self.username_input)
        form_layout.addRow(QLabel("Password:"), self.password_input)

        layout.addLayout(form_layout)

        # Buttons for Save and Delete
        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_credential)
        self.delete_button = QPushButton("Delete")
        self.delete_button.clicked.connect(self.delete_credential)

        layout.addWidget(self.save_button)
        layout.addWidget(self.delete_button)

        self.setLayout(layout)

    def save_credential(self):
        new_name = self.name_input.text().strip()
        new_username = self.username_input.text().strip()
        new_password = self.password_input.text().strip()

        if not new_name or not new_username or not new_password:
            QMessageBox.warning(self, "Error", "All fields must be filled.")
            return

        # Encrypt the new username and password
        result = self.repository.get_master_password_data()
        if result:
            encrypted_token, salt, nonce = result
            encryption_key = self.security.derive_key(self.master_password, salt)

            encrypted_username = self.security.encrypt_data(new_username, encryption_key, nonce)
            encrypted_password = self.security.encrypt_data(new_password, encryption_key, nonce)

            # Update the credential in the repository using the credential ID
            self.repository.update_credential(self.credential_id, new_name, encrypted_username, encrypted_password)
            self.accept()  # Close the dialog with success
        else:
            QMessageBox.warning(self, "Error", "Unable to fetch master password data.")

    def delete_credential(self):
        confirmation = QMessageBox.question(self, "Confirm Delete", "Are you sure you want to delete this credential?",
                                             QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if confirmation == QMessageBox.StandardButton.Yes:
            self.repository.delete_credential(self.credential_id)  # Use the credential ID for deletion
            self.accept()  # Close the dialog with success

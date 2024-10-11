from PyQt6.QtWidgets import QMainWindow, QVBoxLayout, QListWidget, QListWidgetItem, QPushButton, QMessageBox, QWidget, QDialog
from ui.add_credential_dialog import AddCredentialDialog  # Import the dialog
from ui.edit_credential_dialog import EditCredentialDialog  # Import the edit dialog


class CredentialsPage(QMainWindow):
    def __init__(self, repository, security, master_password):
        super().__init__()
        self.repository = repository
        self.security = security
        self.master_password = master_password  # Store the master password
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Manage Credentials")
        self.setGeometry(300, 300, 500, 400)

        # Main layout
        self.main_layout = QVBoxLayout()

        # Button to open the add credential dialog
        self.add_button = QPushButton("Add Credential")
        self.add_button.clicked.connect(self.open_add_credential_dialog)
        self.main_layout.addWidget(self.add_button)

        # List widget to display the credentials
        self.credentials_list = QListWidget()
        self.credentials_list.itemDoubleClicked.connect(self.reveal_credentials_from_list)
        self.main_layout.addWidget(self.credentials_list)

        # Setting the main widget
        self.main_widget = QWidget()
        self.main_widget.setLayout(self.main_layout)
        self.setCentralWidget(self.main_widget)

        # Update the credentials view (load existing credentials)
        self.update_credentials_view()

    def open_add_credential_dialog(self):
        dialog = AddCredentialDialog(self.repository, self.security, self.master_password, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # If the dialog was accepted, refresh the credentials list
            self.update_credentials_view()

    def update_credentials_view(self):
        # Clear the existing list
        self.credentials_list.clear()

        # Fetch the credentials from the repository
        credentials = self.repository.get_all_credentials()  # Assuming this returns a list of tuples: (id, name, encrypted_username, encrypted_password)

        if credentials:
            for id, name, encrypted_username, username_salt, username_nonce, encrypted_password, password_salt, password_nonce in credentials:
                # Create a QListWidgetItem for each credential
                item = QListWidgetItem(name)
                item.setData(1, (id))  # Store the credential ID and name in the item
                self.credentials_list.addItem(item)
        else:
            self.credentials_list.addItem("No credentials added yet.")

    def reveal_credentials_from_list(self, item):
        # Get the credential ID from the item
        id = item.data(1)

        # Fetch the encrypted username and password from the repository
        result = self.repository.get_credential_by_id(id)
        if result:
            id, name, encrypted_username, username_salt, username_nonce, encrypted_password, password_salt, password_nonce = result

            # Decrypt the username and password
            username_decryption_key, _ = self.security.derive_key(self.master_password, username_salt)
            decrypted_username = self.security.decrypt_data(encrypted_username, username_decryption_key, username_nonce)

            password_decryption_key, _ = self.security.derive_key(self.master_password, password_salt)
            decrypted_password = self.security.decrypt_data(encrypted_password, password_decryption_key, password_nonce)

            # Open the edit credential dialog with decrypted credentials
            edit_dialog = EditCredentialDialog(self.repository, self.security, self.master_password,
                                                id, name, decrypted_username, decrypted_password, self)
            if edit_dialog.exec() == QDialog.DialogCode.Accepted:
                # If the dialog was accepted, refresh the credentials list
                self.update_credentials_view()
        else:
            QMessageBox.warning(self, "Error", "Unable to fetch master password data.")

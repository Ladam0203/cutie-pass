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

        print(credentials)

        if credentials:
            for id, name, encrypted_username, encrypted_password in credentials:
                # Create a QListWidgetItem for each credential
                item = QListWidgetItem(name)
                item.setData(1, (id, encrypted_username, encrypted_password))  # Store the ID and encrypted credentials as user data
                self.credentials_list.addItem(item)
        else:
            self.credentials_list.addItem("No credentials added yet.")

    def reveal_credentials_from_list(self, item):
        # Get the ID, encrypted username, and password from the item
        credential_id, encrypted_username, encrypted_password = item.data(1)

        # Fetch the stored master password data
        result = self.repository.get_master_password_data()

        if result:
            encrypted_token, salt, nonce = result

            # Derive encryption key from the master password
            encryption_key = self.security.derive_key(self.master_password, salt)

            # Decrypt the username and password
            decrypted_username = self.security.decrypt_data(encrypted_username, encryption_key, nonce)
            decrypted_password = self.security.decrypt_data(encrypted_password, encryption_key, nonce)

            # Open the edit credential dialog with decrypted credentials
            edit_dialog = EditCredentialDialog(self.repository, self.security, self.master_password,
                                                credential_id, item.text(), decrypted_username, decrypted_password, self)
            if edit_dialog.exec() == QDialog.DialogCode.Accepted:
                # If the dialog was accepted, refresh the credentials list
                self.update_credentials_view()
        else:
            QMessageBox.warning(self, "Error", "Unable to fetch master password data.")

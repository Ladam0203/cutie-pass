import secrets
import string
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QLineEdit, QPushButton, QLabel, QMessageBox,
    QHBoxLayout, QSpinBox, QCheckBox, QFormLayout
)
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import QSize


class AddCredentialDialog(QDialog):
    def __init__(self, repository, security, master_password, parent=None):
        super().__init__(parent)
        self.repository = repository
        self.security = security
        self.master_password = master_password

        # Default password generation settings
        self.password_length = 12
        self.include_lowercase = True
        self.include_uppercase = True
        self.include_digits = True
        self.include_symbols = True

        # Track whether the password is revealed or hidden
        self.password_revealed = False

        self.initUI()

    def initUI(self):
        self.setWindowTitle("Add New Credential")
        self.setGeometry(300, 300, 300, 200)

        # Layout for the dialog
        self.layout = QVBoxLayout()

        # Name input field with label
        name_label = QLabel("Name")
        self.layout.addWidget(name_label)

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Enter your name")
        self.layout.addWidget(self.name_input)

        # Username input field with label
        username_label = QLabel("Username")
        self.layout.addWidget(username_label)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        self.layout.addWidget(self.username_input)

        # Password label with buttons
        password_label = QLabel("Password")
        self.layout.addWidget(password_label)

        # Horizontal layout for password input
        self.password_layout = QHBoxLayout()

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_layout.addWidget(self.password_input)

        # Button to toggle password visibility
        self.toggle_visibility_button = QPushButton()
        self.toggle_visibility_button.setIcon(QIcon.fromTheme("view-reveal-symbolic"))  # Icon for showing the password
        self.toggle_visibility_button.setIconSize(QSize(16, 16))
        self.toggle_visibility_button.clicked.connect(self.toggle_password_visibility)
        self.password_layout.addWidget(self.toggle_visibility_button)

        # Add the password input layout to the main layout
        self.layout.addLayout(self.password_layout)

        # Create a new horizontal layout for the generate and settings buttons
        self.button_layout = QHBoxLayout()

        # Button to generate password
        self.generate_button = QPushButton("Generate")
        self.generate_button.clicked.connect(self.generate_password)
        self.button_layout.addWidget(self.generate_button)

        # Add settings button
        self.settings_button = QPushButton()
        self.settings_button.setIcon(QIcon.fromTheme("preferences-system"))  # Add icon from theme
        self.settings_button.setIconSize(QSize(16, 16))
        self.settings_button.clicked.connect(self.open_password_settings)
        self.button_layout.addWidget(self.settings_button)

        # Align the buttons to the right
        self.button_layout.addStretch()  # Add stretchable space to push the buttons to the right
        self.layout.addLayout(self.button_layout)

        # Save button
        self.save_button = QPushButton("Save Credential")
        self.save_button.clicked.connect(self.save_credential)
        self.layout.addWidget(self.save_button)

        self.setLayout(self.layout)

    def generate_password(self):
        # Build the character pool based on user preferences
        char_pool = ''
        if self.include_lowercase:
            char_pool += string.ascii_lowercase
        if self.include_uppercase:
            char_pool += string.ascii_uppercase
        if self.include_digits:
            char_pool += string.digits
        if self.include_symbols:
            char_pool += string.punctuation

        if not char_pool:
            QMessageBox.warning(self, "Input Error", "You must select at least one character set.")
            return

        # Generate a secure random password
        secure_password = ''.join(secrets.choice(char_pool) for _ in range(self.password_length))

        # Set the generated password in the password input field
        self.password_input.setText(secure_password)

    def open_password_settings(self):
        settings_dialog = PasswordSettingsDialog(self)
        settings_dialog.exec()

    def save_credential(self):
        name = self.name_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        if name and username and password:
            result = self.repository.get_master_password_data()

            if result:
                encrypted_token, salt, nonce = result
                encryption_key = self.security.derive_key(self.master_password, salt)

                encrypted_username = self.security.encrypt_data(username, encryption_key, nonce)
                encrypted_password = self.security.encrypt_data(password, encryption_key, nonce)

                self.repository.save_credential(name, encrypted_username, encrypted_password)
                print(f"Credential for {name} saved and encrypted.")

                self.accept()
            else:
                QMessageBox.warning(self, "Error", "Unable to fetch master password data.")
        else:
            QMessageBox.warning(self, "Input Error", "Please fill out all fields.")

    def toggle_password_visibility(self):
        if self.password_revealed:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_visibility_button.setIcon(QIcon.fromTheme("view-reveal-symbolic"))  # Update icon to 'show' state
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_visibility_button.setIcon(QIcon.fromTheme("view-conceal-symbolic"))  # Update icon to 'hide' state

        self.password_revealed = not self.password_revealed


class PasswordSettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_dialog = parent
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Password Generation Settings")
        self.setGeometry(350, 350, 300, 200)

        # Layout for the settings dialog
        self.layout = QFormLayout()

        # Password length input
        self.length_input = QSpinBox()
        self.length_input.setRange(8, 64)  # Allow lengths between 8 and 64
        self.length_input.setValue(self.parent_dialog.password_length)
        self.layout.addRow("Password Length:", self.length_input)

        # Checkboxes for character sets
        self.lowercase_checkbox = QCheckBox("Include Lowercase")
        self.lowercase_checkbox.setChecked(self.parent_dialog.include_lowercase)
        self.layout.addRow(self.lowercase_checkbox)

        self.uppercase_checkbox = QCheckBox("Include Uppercase")
        self.uppercase_checkbox.setChecked(self.parent_dialog.include_uppercase)
        self.layout.addRow(self.uppercase_checkbox)

        self.digits_checkbox = QCheckBox("Include Digits")
        self.digits_checkbox.setChecked(self.parent_dialog.include_digits)
        self.layout.addRow(self.digits_checkbox)

        self.symbols_checkbox = QCheckBox("Include Symbols")
        self.symbols_checkbox.setChecked(self.parent_dialog.include_symbols)
        self.layout.addRow(self.symbols_checkbox)

        # Save button
        self.save_button = QPushButton("Save Settings")
        self.save_button.clicked.connect(self.save_settings)
        self.layout.addRow(self.save_button)

        self.setLayout(self.layout)

    def save_settings(self):
        # Save the settings to the parent dialog
        self.parent_dialog.password_length = self.length_input.value()
        self.parent_dialog.include_lowercase = self.lowercase_checkbox.isChecked()
        self.parent_dialog.include_uppercase = self.uppercase_checkbox.isChecked()
        self.parent_dialog.include_digits = self.digits_checkbox.isChecked()
        self.parent_dialog.include_symbols = self.symbols_checkbox.isChecked()

        # Close the settings dialog
        self.accept()

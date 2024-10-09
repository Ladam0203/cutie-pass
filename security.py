import os
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class Security:
    def derive_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)

        # Derive a key from the password using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key, salt

    def generate_master_password_data(self, password, salt = None):
        # Derive a key from the password using the salt
        key, salt = self.derive_key(password, salt)

        # Generate a token: timestamp + 'verification' text
        timestamp = str(int(time.time() * 1000))  # Millisecond accuracy
        token = (timestamp + "::verification").encode()  # Delimiter between timestamp and verification text
        aesgcm = AESGCM(key)

        # Generate nonce
        nonce = os.urandom(12)

        # Encrypt the token
        encrypted_token = aesgcm.encrypt(nonce, token, None)

        return encrypted_token, salt, nonce

    def can_decrypt_master_password_data(self, encrypted_token, salt, nonce, entered_password):
        # Derive a key from the entered password using the stored salt
        key, salt = self.derive_key(entered_password, salt)

        # Try to decrypt the token using the derived key
        aesgcm = AESGCM(key)
        try:
            decrypted_token = aesgcm.decrypt(nonce, encrypted_token, None).decode()

            # Split the decrypted token by the delimiter
            timestamp, verification = decrypted_token.split("::")

            if verification == 'verification':
                return True  # Password is correct
        except Exception as e:
            pass

        return False

    def encrypt_data(self, data, encryption_key, nonce = None):
        if nonce is None:
            nonce = os.urandom(12)
        aesgcm = AESGCM(encryption_key)
        encrypted_data = aesgcm.encrypt(nonce, data.encode(), None)
        return encrypted_data, nonce

    def decrypt_data(self, encrypted_data, decryption_key, nonce):
        aesgcm = AESGCM(decryption_key)
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
        return decrypted_data.decode()

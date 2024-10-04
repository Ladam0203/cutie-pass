import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class Security:
    def derive_key(self, password, salt):
        # Derive a key from the password using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key

    def generate_master_password_data(self, password):
        # Generate a salt
        salt = os.urandom(16)

        # Derive a key from the password using the salt
        key = self.derive_key(password, salt)

        # Generate a token to encrypt for verification purposes
        token = b'verification'
        aesgcm = AESGCM(key)

        # Generate nonce
        nonce = os.urandom(12)

        # Encrypt the token
        encrypted_token = aesgcm.encrypt(nonce, token, None)

        return encrypted_token, salt, nonce

    def can_decrypt_master_password_data(self, encrypted_token, salt, nonce, entered_password):
        # Derive a key from the entered password using the stored salt
        key = self.derive_key(entered_password, salt)

        # Try to decrypt the token using the derived key
        aesgcm = AESGCM(key)
        try:
            decrypted_token = aesgcm.decrypt(nonce, encrypted_token, None)

            if decrypted_token == b'verification':
                return True  # Password is correct
        except Exception as e:
            pass

        return False

    def encrypt_data(self, data, key, nonce):
        aesgcm = AESGCM(key)
        encrypted_data = aesgcm.encrypt(nonce, data.encode(), None)
        return encrypted_data

    def decrypt_data(self, encrypted_data, key, nonce):
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
        return decrypted_data.decode()
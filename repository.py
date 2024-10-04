import sqlite3

class Repository:
    def __init__(self):
        self.conn = sqlite3.connect('vault.db')
        self.cursor = self.conn.cursor()
        self.create_settings_table()
        self.create_credentials_table()

    def create_settings_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_token TEXT,
                salt TEXT,
                nonce TEXT
            )
        ''')
        self.conn.commit()

    def create_credentials_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                encrypted_username TEXT,
                encrypted_password TEXT
            )
        ''')
        self.conn.commit()

    def is_master_password_set(self):
        self.cursor.execute('SELECT * FROM settings')
        return self.cursor.fetchone() is not None

    def save_master_password_data(self, encrypted_token, salt, nonce):
        self.cursor.execute('''
            INSERT INTO settings (encrypted_token, salt, nonce)
            VALUES (?, ?, ?)
        ''', (encrypted_token, salt, nonce))
        self.conn.commit()

    def get_master_password_data(self):
        self.cursor.execute('SELECT encrypted_token, salt, nonce FROM settings WHERE id = 1')
        return self.cursor.fetchone()

    def save_credential(self, name, username, password):
        self.cursor.execute('''
            INSERT INTO credentials (name, encrypted_username, encrypted_password)
            VALUES (?, ?, ?)
        ''', (name, username, password))
        self.conn.commit()

    def get_all_credentials(self):
        self.cursor.execute('SELECT name, encrypted_username, encrypted_password FROM credentials')
        # Return tuples of (name, encrypted_username, encrypted_password)
        return self.cursor.fetchall()


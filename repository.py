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
                username_salt TEXT,
                username_nonce TEXT,
                encrypted_password TEXT,
                password_salt TEXT,
                password_nonce TEXT
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

    def save_credential(self, name, encrypted_username, username_salt, username_nonce, encrypted_password, password_salt, password_nonce):
        self.cursor.execute('''
            INSERT INTO credentials (name, encrypted_username, username_salt, username_nonce, encrypted_password, password_salt, password_nonce)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (name, encrypted_username, username_salt, username_nonce, encrypted_password, password_salt, password_nonce))
        self.conn.commit()

    def update_credential(self, id, name, encrypted_username, username_salt, username_nonce, encrypted_password, password_salt, password_nonce):
        self.cursor.execute('''
            UPDATE credentials
            SET name = ?, encrypted_username = ?, username_salt = ?, username_nonce = ?, encrypted_password = ?, password_salt = ?, password_nonce = ?
            WHERE id = ?
        ''', (name, encrypted_username, username_salt, username_nonce, encrypted_password, password_salt, password_nonce, id))
        self.conn.commit()

    def delete_credential(self, id):
        self.cursor.execute('''
            DELETE FROM credentials
            WHERE id = ?
        ''', (id,))
        self.conn.commit()

    def get_all_credentials(self):
        self.cursor.execute('SELECT id, name, encrypted_username, username_salt, username_nonce, encrypted_password, password_salt, password_nonce FROM credentials')
        return self.cursor.fetchall()

    def get_credential_by_id(self, id):
        self.cursor.execute(
            'SELECT id, name, encrypted_username, username_salt, username_nonce, encrypted_password, password_salt, password_nonce FROM credentials WHERE id = ?',
            (id,))
        return self.cursor.fetchone()



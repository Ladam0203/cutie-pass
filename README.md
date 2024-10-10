
# Introduction

CutiePass is a local password manager created using Python, PyQt 6 and SQLite. It helps the user keep track of credentials locally on a device. It uses a master password to unlock the vault in which the credentials are stored. A mechanism to generate a password is also implemented.

# Setup 

## Prerequisites

- Python 3.12 or higher

## Installation

1. Clone the repository
2. Install the dependencies using the following command (from requirements.txt)
```bash
pip install -r requirements.txt
```

## Running the application

To run the application, execute the following command:
```bash
python main.py
```

# Security Model

## Master Password

Upon the first start, the user asked to provide a master password. Fromt this master password a key is derived via PBKDF2 to encrypt a predefined data ([timestamp]::verification), via AESGCM to save whether a master password has been set already for the application. Each time the user would like to unlock the vault, they have to provide their master password. The data in the settings table is then attempted to be decrypted with the password. If the password is right, then the data can be decrypted and the vault unlocks.

## Managing credentials

The user can add credentials to the vault via clicking the "Add Credential" button.
The credentials are encrypted using the master password as a key. 
The credentials are stored in the database in an encrypted form. 
Each credential and its corresponding data are encrypted and salted separately and uniquely. 
The user may generate a password for a credential with a cryptographically secure random generator.
The user may modify the character set, length, and whether to include special characters in the generated password but is provided with a safe default.

The data is decrypted when the user wants to view the credentials. (The name of the credential is stored in plain text, as it is not deemed as sensitive information.)

# Pitfalls

- Upon setting the master password, the user is not asked to confirm the password. This may lead to the user setting a password that they did not intend to.
- The master password is stored in memory in plain text. This is a security risk as it can be accessed by other applications.
- The user has unlimited attempts to enter the master password. This may lead to brute force attacks.
- There is no mechanism to recover the master password if the user forgets it. This may lead to the user losing access to their credentials.

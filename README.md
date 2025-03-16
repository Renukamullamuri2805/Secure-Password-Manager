# SecretVault - Password Manager 🔒

SecretVault is a secure and user-friendly password manager built using Flask. It helps users store, manage, and access their passwords safely by utilizing AES encryption to protect sensitive information. This application allows users to add, view, edit, and delete passwords, all while keeping them encrypted until they’re needed.

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Usage](#usage)
6. [How Password Encryption Works](#how-password-encryption-works)
   - [About AES Encryption](#about-aes-encryption)
7. [Explanation of Terms](#explanation-of-terms)
   - [Master Password](#master-password)
   - [Encryption Password](#encryption-password)
8. [File Structure](#file-structure)
9. [Contributing](#contributing)

---

## Project Overview

SecretVault is a secure, Flask-based web application designed for managing and encrypting passwords. It provides users with control over their credentials, ensuring sensitive data is accessible only with a unique master and encryption password. By implementing Advanced Encryption Standard (AES) encryption, SecretVault secures user data, making it a reliable tool for password management.

## Features

- **User Registration & Authentication**: Secure user registration with a master password and secret key.
- **Password Encryption**: All passwords are encrypted using AES encryption.
- **Secure Password Storage**: Store credentials by website, with options to view, edit, or delete them.
- **Master & Encryption Passwords**: Separate master and encryption passwords for added security.
- **UI/UX Enhancements**: Glassmorphism styling for a modern and sleek user experience.

## Prerequisites

- **Python 3.8+**
- **Flask**: For backend server and routing
- **SQLAlchemy** or SQLite: For database management
- **pycryptodome**: For AES encryption
- HTML,CSS,JS,BootStrap : for styling

To install the required packages, you can use:
```bash
pip install -r requirements.txt

## Installation
1)Clone the repository:
git clone https://github.com/yourusername/SecretVault.git
cd SecretVault

2)Install dependencies:
pip install -r requirements.txt

3)Set up the database:
flask db init
flask db migrate
flask db upgrade

4)Run the application:
flask run

5)Access the app:
Open your browser and go to http://127.0.0.1:5000.

## Usage:
Register: Create an account with a username, master password, and secret key.
Login: Use your username and master password to log in.
Add Passwords: Enter website information and password. SecretVault will encrypt and store this information.
View or Edit Passwords: To view or edit a password, enter the encryption password to decrypt the information.
Settings: Change the master password, encryption password, and secret key as needed.
How Password Encryption Works
SecretVault uses AES (Advanced Encryption Standard) encryption to secure passwords. AES is a symmetric encryption algorithm known for its robustness and reliability, widely used in sensitive data protection.

About AES Encryption:
AES encryption works by transforming plaintext (your passwords) into encrypted text (ciphertext) through a series of complex calculations and substitutions, based on a secret key (your encryption password). Only someone who knows this key can decrypt the information, which ensures that only authorized users can access sensitive data.

Explanation of Terms:
Master Password:
The master password is the main password used to log into SecretVault. It is required for authenticating the user but does not directly encrypt or decrypt passwords. It can be updated from the settings, and updating it does not affect stored data.

Encryption Password:
The encryption password is used specifically for encrypting and decrypting stored passwords using the AES algorithm. Users will need to enter this password whenever they want to view or edit a saved password. Note: Changing the encryption password will delete all stored passwords as a security measure.

## File Structure:
Below is the file structure of the project:


SecretVault/
├── password-manager-app
|   └── _pycache_
│       ├── app.cpython-312.pyc        
│   └── static
│       ├── glassmorphism.css
|       ├──style.css
|       ├──styles.css
|       ├──bg.jpg
|       ├─pagebg.jpg
|       ├─homebg.jpg   
│       └── script.js
│   └── templates
│       ├── add_password.html
│       ├── home.html      # Home page
│       ├── login.html     # Login page
│       ├── register.html  # Registration page 
|       ├─settings.html    #settings page
│       └── view_password.html # Password viewing page
│   └── instance
│       ├── password_manager.db
│   └── app.py
├── requirements.txt       # Project dependencies
└── README.md              # Project readme file

Contributing
Feel free to open issues and submit pull requests to help make SecretVault even better!

Contribution Guidelines:
1)Fork the repository.
2)Create a new branch (git checkout -b feature/YourFeature).
3)Commit your changes (git commit -m 'Add some feature').
4)Push to the branch (git push origin feature/YourFeature).
5)Open a pull request.

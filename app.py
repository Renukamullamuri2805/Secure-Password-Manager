from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import ForeignKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import os
import base64
from base64 import b64decode

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Replace this with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    master_password = db.Column(db.String(200), nullable=False)
    encryption_password = db.Column(db.String(200), nullable=False)

    def __init__(self, username, email, master_password, encryption_password):
        self.username = username
        self.email = email
        self.master_password = generate_password_hash(master_password)
        self.encryption_password = generate_password_hash(encryption_password) 

# Model for storing passwords
class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('user.id'), nullable=False)
    website = db.Column(db.String(150), nullable=False)
    encrypted_password = db.Column(db.String(500), nullable=False)

# Encryption setup
def generate_key(master_password):
    return hashlib.sha256(master_password.encode()).digest()

def encrypt_password(password: str, encryption_password: str):
    key = generate_key(encryption_password)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(password.encode()) + encryptor.finalize()
    return iv.hex() + encrypted_password.hex()


def decrypt_password(encrypted_password: str, encryption_password: str):
    key = generate_key(encryption_password)
    iv = bytes.fromhex(encrypted_password[:32])
    encrypted = bytes.fromhex(encrypted_password[32:])
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_bytes = decryptor.update(encrypted) + decryptor.finalize()

    # Try to decode the decrypted bytes as UTF-8 text
    try:
        return decrypted_bytes.decode('utf-8')  # Return as plain text
    except UnicodeDecodeError:
        # If the decryption is not valid UTF-8, return the raw bytes or another error handling
        return "Decryption error: Non-UTF-8 data"



@app.route('/')
def home():
    if 'current_user_id' not in session:
        return redirect(url_for('login'))
    # Fetch the current user based on session ID
    user = User.query.get(session['current_user_id'])
    passwords = Password.query.filter_by(user_id=session['current_user_id']).all()
    return render_template('home.html', passwords=passwords, username=user.username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        master_password = request.form['master_password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.master_password, master_password):
            session['current_user_id'] = user.id
            session['encryption_key'] = generate_key(master_password)
            flash("Login successful!")
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password. Please try again.")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        master_password = request.form['master_password']
        encryption_password = request.form['encryption_password']
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists. Please choose a different one.")
            return redirect(url_for('register'))
        
        # Create new user with provided encryption password
        new_user = User(username=username, email=email, master_password=master_password, encryption_password=encryption_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please log in.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if 'encryption_key' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        website = request.form['website']
        password = request.form['password']
        user = User.query.get(session['current_user_id'])
        encrypted = encrypt_password(password, user.encryption_password)

        new_password = Password(website=website, encrypted_password=encrypted, user_id=session['current_user_id'])
        db.session.add(new_password)
        db.session.commit()

        flash('Password added successfully!', 'success')

        # Instead of redirecting, re-render the add_password.html template to stay on the same page
        return render_template('add_password.html', success_message='Password added successfully!')
    
    return render_template('add_password.html')


@app.route('/edit_password/<int:id>', methods=['POST'])
def edit_password(id):
    if 'encryption_key' not in session:
        return redirect(url_for('login'))
    data = request.get_json()
    secret_password = data.get('secret_password')
    website = data.get('website')
    password = data.get('password')
    
    user = User.query.get(session['current_user_id'])
    if not check_password_hash(user.encryption_password, secret_password):
        return jsonify({"error": "Incorrect Secret Password."}), 403
    
    password_entry = Password.query.get_or_404(id)
    password_entry.website = website
    password_entry.encrypted_password = encrypt_password(password, user.encryption_password)
    db.session.commit()
    return jsonify({"message": "Password updated successfully!"}), 200


@app.route('/delete_password/<int:id>', methods=['POST'])
def delete_password(id):
    if 'encryption_key' not in session:
        return redirect(url_for('login'))
    password_entry = Password.query.get_or_404(id)
    db.session.delete(password_entry)
    db.session.commit()
    flash('Password deleted successfully!', 'success')
    return redirect(url_for('view_password'))


@app.route('/delete_all_passwords', methods=['POST'])
def delete_all_passwords():
    if 'current_user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401
    
    data = request.get_json()
    secret_password = data.get('secret_password')

    user = User.query.get(session['current_user_id'])
    if not check_password_hash(user.encryption_password, secret_password):
        return jsonify({"error": "Incorrect Secret Password"}), 403

    Password.query.filter_by(user_id=session['current_user_id']).delete()
    db.session.commit()

    return jsonify({"success": True}), 200




@app.route('/view_password', methods=['GET'])
def view_password():
    if 'current_user_id' not in session:
        return redirect(url_for('login'))
    
    passwords = Password.query.filter_by(user_id=session['current_user_id']).all()
    return render_template('view_password.html', passwords=passwords)


@app.route('/decrypt_password/<int:password_id>', methods=['POST'])
def decrypt_password_route(password_id):
    if 'current_user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401
    
    data = request.form
    encryption_password = data.get('encryption_password')

    # Fetch user and verify encryption password
    user = User.query.get(session['current_user_id'])
    if not check_password_hash(user.encryption_password, encryption_password):
        return jsonify({"error": "Incorrect encryption password"}), 403

    # Fetch password entry
    password_entry = Password.query.get_or_404(password_id)
    decrypted_password = decrypt_password(password_entry.encrypted_password, user.encryption_password)
    
    return jsonify({"decrypted_password": decrypted_password}), 200

@app.route('/decrypt_all_passwords', methods=['POST'])
def decrypt_all_passwords():
    if 'current_user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401
    
    encryption_password = request.form.get('encryption_password')
    user = User.query.get(session['current_user_id'])
    
    if not check_password_hash(user.encryption_password, encryption_password):
        return jsonify({"error": "Incorrect encryption password"}), 403

    # Decrypt each password
    passwords = Password.query.filter_by(user_id=session['current_user_id']).all()
    decrypted_passwords = [
        {"id": p.id, "decrypted_password": decrypt_password(p.encrypted_password, user.encryption_password)}
        for p in passwords
    ]

    return jsonify({"success": True, "passwords": decrypted_passwords}), 200

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    # Get the current user based on session ID
    user = User.query.get(session['current_user_id'])
    if request.method == 'POST':
        # Retrieve form data
        current_password = request.form['current_password']
        new_master_password = request.form.get('new_master_password')
        current_encryption_password = request.form.get('current_encryption_password')
        new_encryption_password = request.form.get('encryption_password')

        # Verify current master password
        if not check_password_hash(user.master_password, current_password):
            flash("Master password entered is wrong.", "danger")
            return redirect(url_for('settings'))

        # Update master password if a new one is provided
        if new_master_password:
            user.master_password = generate_password_hash(new_master_password)
            db.session.commit()  # Commit the update to the database
            flash("Master password updated successfully.", "success")
            return redirect(url_for('settings'))

        # Update encryption password if a new one is provided
        if new_encryption_password:
            if check_password_hash(user.encryption_password, current_encryption_password):
                db.session.query(Password).filter_by(user_id=session['current_user_id']).delete()
                user.encryption_password = generate_password_hash(new_encryption_password)
                flash("Encryption password updated successfully!", "success")
            else:
                flash("Wrong encryption password.", "danger")
                return redirect(url_for('settings'))

        # Update username
        user.username = request.form['username']
        db.session.commit()  # Commit any changes to the database
        flash("Settings updated successfully!", "success")
        return redirect(url_for('settings'))

    return render_template('settings.html', user=user)


@app.route('/logout', methods=['GET', 'POST'])  # Allow both GET and POST
def logout():
    session.pop('current_user_id', None)  # Remove the user ID from the session
    session.pop('encryption_key', None)    # Remove the encryption key from the session
    flash("You have been logged out successfully.", "success")
    return redirect(url_for('login'))


# Create the database tables
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)

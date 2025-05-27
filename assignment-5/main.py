import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Setup key and cipher (in production, save key securely)
if "key" not in st.session_state:
    st.session_state.key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.key)

# In-memory store
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

# Failed attempts counter
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt
def encrypt_data(text):
    return st.session_state.cipher.encrypt(text.encode()).decode()

# Function to decrypt
def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    for record in st.session_state.stored_data.values():
        if record["encrypted_text"] == encrypted_text:
            if record["passkey"] == hashed:
                st.session_state.failed_attempts = 0
                return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# App UI
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Navigation", menu)

# Home Page
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Store and retrieve your private data using secure encryption.")

# Store Data
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter data to encrypt:")
    passkey = st.text_input("Create a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted, language='text')
        else:
            st.error("⚠️ Both fields are required.")

# Retrieve Data
elif choice == "Retrieve Data":
    if st.session_state.failed_attempts >= 3:
        st.warning("🔒 Too many failed attempts. Redirecting to Login.")
        st.rerun()

    st.subheader("🔍 Retrieve Encrypted Data")
    encrypted_input = st.text_area("Paste your encrypted data:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success("✅ Data decrypted successfully:")
                st.code(result)
            else:
                st.error(f"❌ Incorrect passkey! Attempts left: {3 - st.session_state.failed_attempts}")
        else:
            st.error("⚠️ Please fill both fields.")

# Login Page (after 3 failed attempts)
elif choice == "Login":
    st.subheader("🔑 Reauthorize Access")
    admin_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if admin_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Access restored. You can try decrypting again.")
            st.rerun()
        else:
            st.error("❌ Incorrect master password.")

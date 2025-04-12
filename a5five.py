# 🔐 Develop a Streamlit-based secure data storage and retrieval system 
# 👩‍🏫 Instructor: Nazia Siraj

import streamlit as st   
import hashlib 
import json 
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# 📁 === Data information of user ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# 🔄 === Session logic details === 
if "authenticated" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# 📤 === Load data if available ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}        

# 💾 Save data to file
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# 🔑 Generate encryption key
def generate_key(password):
    key = pbkdf2_hmac('sha256', password.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

# 🔒 Hash password
def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# 🔐 Encrypt and decrypt data
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()    
    except: 
        return None

stored_data = load_data()

# 🏠 === Login section ===
st.title("🔐 Secure Data Encryption System")
menu = ["🏠 Home", "🔑 Login", "📝 Register", "💼 Store Data", "📂 Retieve Data"]
choice = st.sidebar.selectbox("📋 Navigation", menu) 

if choice == "🏠 Home":
    st.subheader("👋 Welcome to My Data Encryption System Using Streamlit!")
    st.markdown("""
    🔒 Develop a Streamlit-based secure data storage and retrieval system where:  
    ✅ Users store data with a unique passkey  
    ✅ Users decrypt data by providing the correct passkey  
    🚫 Multiple failed attempts results in a forced reauthorization (login page)  
    💻 The system operates entirely in memory without external databases.
    """)

# 👤 === User registration ===
elif choice == "📝 Register":
    st.subheader("🆕 Register New User")
    username = st.text_input("🧑‍💻 Choose Username")
    password = st.text_input("🔐 Choose Password", type="password")
    
    if st.button("✅ Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists!")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("🎉 User registered successfully!")
        else:
            st.error("❗ Both fields are required!")  

# 🔓 === Login ===
elif choice == "🔑 Login": 
    st.subheader("🔓 User Login")
    
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"🚫 Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()
        
    username = st.text_input("👤 Username")      
    password = st.text_input("🔐 Password", type="password")

    if st.button("🔑Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"🎉Welcome {username}!")
        else:
            st.session_state.failed_attempts += 1    
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials! Attempts left: {remaining}")
            
            
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("To many failed attempts. Locked for 60 seconds.")
                st.stop()
        
        
    # 🔒 data store section ===
    elif choice == "💼 Store Data":
        if not st.session_state.authenticated_user:
            st.warning("🔒Please login first.")
            
            
    else:
        st.subheader("🔒Store Encrypted Data") 
        data = st.text_area("📄Enter data to encrpty")  
        passkey = st.text_input("🔑Encryption key (passphrase)", type="password")    
        
        if st.button("💾Encrypt And Save"):  
            if data and passkey:
                encrypted_data = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted_data)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully!")   
            
                
            else:
                st.error("❗All fields are required to fill!")
                
                
    # === data retieve data  section ===  
        elif choice == "📈Retieve Data":
            if not st.session_state.authenticated_user:
                st.warning("🔒Pleas login first")
            else:
                st.subheader("📂Retieve data")
                user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])
                
                if not user_data:
                    st.info("No Data Found!")
                    
                else:
                    st.write("🔑Encrypted Data Enteries:")
                    for i, item in enumerate(user_data):
                        st.code(item, language="text")
                        
                encrypted_input = st.text_area("📄Enter encrypted Text")
                passkey = st.text_input("🔑Enter passkey T Decrypt", type="password")
                
                
                if st.button("🔑Decryp"):
                    result = decrypt_text(encrypted_input, passkey)
                    if result:
                        st.success(f"✅ Decrypted Data: {result}")
                else:
                    st.error("❌incorrect passkey or corrupted data.")        

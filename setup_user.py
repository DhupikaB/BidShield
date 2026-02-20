import os
import base64
from ecdsa import SigningKey, SECP256k1
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ==========================================
# FOLDER SETUP
# ==========================================
# We define exactly where we want these files to go
KEY_DIRECTORY = "data/keys"


# ==========================================
# PASSWORD LOCKING SYSTEM
# ==========================================
def lock_with_password(password, data_to_lock):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'cseps_project_salt',
        iterations=100000,
    )
    strong_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    fernet = Fernet(strong_key)
    return fernet.encrypt(data_to_lock)


# ==========================================
# GENERATE AND SAVE KEYS TO FOLDER
# ==========================================
def register_secure_user(user_id, password):
    print(f"Generating cryptographic identity for {user_id}...")

    # --- NEW: CREATE THE DIRECTORY ---
    # exist_ok=True means Python won't crash if the folder already exists!
    os.makedirs(KEY_DIRECTORY, exist_ok=True)

    # 1. Create the keys
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()

    # 2. Scramble the private key using the password
    raw_private_text = private_key.to_pem()
    locked_private_key = lock_with_password(password, raw_private_text)

    # --- NEW: SET UP THE EXACT FILE PATHS ---
    # os.path.join safely connects the folder name and the file name
    private_filepath = os.path.join(KEY_DIRECTORY, f"{user_id}_private.pem")
    public_filepath = os.path.join(KEY_DIRECTORY, f"{user_id}_public.pem")

    # 3. Save the locked PRIVATE key into the new folder
    with open(private_filepath, "wb") as f:
        f.write(locked_private_key)

    # 4. Save the PUBLIC key into the new folder
    with open(public_filepath, "wb") as f:
        f.write(public_key.to_pem())

    print(f"✅ Success! Keys securely saved inside the '{KEY_DIRECTORY}' folder.")
    print(f"   -> {private_filepath} (Locked)")
    print(f"   -> {public_filepath} (Public)")


# ==========================================
# RUNNING THE SETUP
# ==========================================
if __name__ == "__main__":
    print("--- CSePS Secure Registration ---")

    # Let's say you type in S20335 here
    my_id = input("Enter your Student/Company ID (e.g., S20335): ")
    my_password = input("Create a strong password to lock your private key: ")

    register_secure_user(my_id, my_password)
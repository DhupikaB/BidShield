# 1. Import the tools we need from the ecdsa library
from ecdsa import SigningKey, SECP256k1


# ==========================================
# STEP 1: CREATE THE KEYS
# ==========================================
def create_keys():
    # Make a highly secure, random Private Key (Keep this secret!)
    my_private_key = SigningKey.generate(curve=SECP256k1)

    # Create the Public Key from that Private Key (Share this with everyone)
    my_public_key = my_private_key.get_verifying_key()

    return my_private_key, my_public_key


# ==========================================
# STEP 2: SIGN THE BID
# ==========================================
def sign_message(private_key, message_text):
    # Computers need text converted to "bytes" (1s and 0s) before doing math on it
    message_bytes = message_text.encode('utf-8')

    # Use the secret private key to mathematically "stamp" the message
    digital_signature = private_key.sign(message_bytes)

    return digital_signature


# ==========================================
# STEP 3: VERIFY THE SIGNATURE
# ==========================================
def check_signature(public_key, signature, message_text):
    # Convert the message to bytes again
    message_bytes = message_text.encode('utf-8')

    try:
        # The server uses the Public Key to check if the stamp matches the text
        # If it matches perfectly, it returns True
        return public_key.verify(signature, message_bytes)
    except:
        # If the text was changed, or the wrong key was used, it crashes.
        # We catch the crash (except) and just return False
        return False


# ==========================================
# LET'S TEST IT OUT (MAIN PROGRAM)
# ==========================================
if __name__ == "__main__":

    print("--- 1. SETTING UP ---")
    alice_private, alice_public = create_keys()
    print("Alice's keys have been created.")

    print("\n--- 2. BIDDING ---")
    my_bid = "Rs. 50 Million"
    print(f"Alice's Bid: {my_bid}")

    # Alice signs her bid before sending it to the government
    alice_signature = sign_message(alice_private, my_bid)
    print("Alice has mathematically signed the bid.")

    print("\n--- 3. GOVERNMENT VERIFICATION ---")
    # The government server receives the bid, the signature, and Alice's public key.
    # It checks if everything is honest.
    is_honest = check_signature(alice_public, alice_signature, my_bid)

    if is_honest == True:
        print("✅ SUCCESS: The signature is real! Alice sent this, and nobody changed it.")
    else:
        print("❌ FAILED: Someone tampered with the bid!")
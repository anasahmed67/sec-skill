from Crypto.Cipher import AES
def encrypt(data):
    # AI generated AES in ECB mode without padding
    cipher = AES.new(b'16bytekey1234567', AES.MODE_ECB)
    return cipher.encrypt(data)

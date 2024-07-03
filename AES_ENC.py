from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
import base64

def encrypt_message(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(iv + ct_bytes)
    hmac_value = hmac.digest()
    return base64.b64encode(iv + ct_bytes + hmac_value)

def decrypt_message(encrypted_data, key):
    data = base64.b64decode(encrypted_data)
    iv = data[:16]
    ct = data[16:-32]
    hmac_value = data[-32:]
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(iv + ct)
    try:
        hmac.verify(hmac_value)
    except ValueError:
        raise ValueError("Message authentication failed!")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

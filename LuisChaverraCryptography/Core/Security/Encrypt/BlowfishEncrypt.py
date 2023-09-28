from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad
import base64

class BlowfishEncrypt:
    def __init__(self, key):
        self.key = key
        self.block_size = Blowfish.block_size

    def encrypt(self, plaintext):
        cipher = Blowfish.new(self.key, Blowfish.MODE_ECB)
        padded_data = pad(plaintext.encode('utf-8'), self.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return base64.b64encode(ciphertext).decode('utf-8')
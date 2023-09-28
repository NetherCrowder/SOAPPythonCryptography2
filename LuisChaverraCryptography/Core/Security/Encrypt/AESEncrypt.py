#Importación de las librerias Pycryptodome y Base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

class AESEncrypt:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_ECB)
        plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(plaintext)
        return base64.b64encode(ciphertext).decode('utf-8')
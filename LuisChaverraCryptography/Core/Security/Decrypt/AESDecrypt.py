#Importación de las librerias Pycryptodome y Base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

class AESDecrypt:
    def __init__(self, key):
        self.key = key

    def decrypt(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_ECB)
        ciphertext = base64.b64decode(ciphertext)
        plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(plaintext, AES.block_size)
        return plaintext.decode('utf-8')
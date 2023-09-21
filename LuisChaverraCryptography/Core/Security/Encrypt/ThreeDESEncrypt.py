from Crypto.Cipher import DES3 #Importación de la libreria Pycryptodome para utilizar el cifrado 3DES
import base64 #Importación de libreria Base64

class ThreeDESEncrypt:
    def __init__(self, key):
        self.key = key

    def _pad(self, data):
        padding_length = 8 - (len(data) % 8)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def encrypt(self, plaintext):
        cipher = DES3.new(self.key, DES3.MODE_ECB)
        padded_plaintext = self._pad(plaintext)
        ciphertext = cipher.encrypt(padded_plaintext)
        # Codificar el texto cifrado en Base64
        ciphertext_base64 = base64.b64encode(ciphertext)
        return ciphertext_base64
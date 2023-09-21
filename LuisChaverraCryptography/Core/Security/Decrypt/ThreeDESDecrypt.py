from Crypto.Cipher import DES3 #Importación de la libreria Pycryptodome para utilizar el cifrado 3DES
import base64 #Importación de libreria Base64

class ThreeDESDecrypt:
    def __init__(self, key):
        self.key = key

    def _unpad(self, data):
        padding_length = data[-1]
        return data[:-padding_length]

    def decrypt(self, ciphertext_base64):
        # Decodificar el texto cifrado en Base64
        ciphertext = base64.b64decode(ciphertext_base64)
        cipher = DES3.new(self.key, DES3.MODE_ECB)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = self._unpad(padded_plaintext)
        return plaintext
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import unpad
import base64

class BlowfishDecrypt:
    def __init__(self, key):
        self.key = key
        self.block_size = Blowfish.block_size

    def decrypt(self, ciphertext):
        cipher = Blowfish.new(self.key, Blowfish.MODE_ECB)
        ciphertext = base64.b64decode(ciphertext)
        decrypted_data = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_data, self.block_size).decode('utf-8')
        return plaintext
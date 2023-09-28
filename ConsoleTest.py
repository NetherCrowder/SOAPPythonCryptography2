from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
import base64

class BlowfishECBEncryptor:
    def __init__(self, key):
        self.key = key
        self.block_size = Blowfish.block_size

    def encrypt(self, plaintext):
        cipher = Blowfish.new(self.key, Blowfish.MODE_ECB)
        padded_data = pad(plaintext.encode('utf-8'), self.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt(self, ciphertext):
        cipher = Blowfish.new(self.key, Blowfish.MODE_ECB)
        ciphertext = base64.b64decode(ciphertext)
        decrypted_data = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_data, self.block_size).decode('utf-8')
        return plaintext

if __name__ == "__main__":
    # Obtén la clave del usuario
    key = input("Ingresa la clave (debe ser de 8 a 56 bytes): ").encode('utf-8')

    # Crea una instancia del cifrador
    encryptor = BlowfishECBEncryptor(key)

    # Ingresa el texto a cifrar
    plaintext = input("Ingresa el texto a cifrar: ")

    # Cifra el texto
    ciphertext = encryptor.encrypt(plaintext)

    print("Texto cifrado (Base64):", ciphertext)

    # Descifra el texto cifrado
    decrypted_text = encryptor.decrypt(ciphertext)
    print("Texto descifrado:", decrypted_text)

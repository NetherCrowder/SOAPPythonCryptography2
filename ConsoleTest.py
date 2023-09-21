from Crypto.Cipher import DES3
import base64

class TripleDESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        cipher = DES3.new(self.key, DES3.MODE_ECB)
        padded_plaintext = self._pad(plaintext)
        ciphertext = cipher.encrypt(padded_plaintext)
        # Codificar el texto cifrado en Base64
        ciphertext_base64 = base64.b64encode(ciphertext)
        return ciphertext_base64

    def decrypt(self, ciphertext_base64):
        # Decodificar el texto cifrado en Base64
        ciphertext = base64.b64decode(ciphertext_base64)
        cipher = DES3.new(self.key, DES3.MODE_ECB)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = self._unpad(padded_plaintext)
        return plaintext

    def _pad(self, data):
        padding_length = 8 - (len(data) % 8)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _unpad(self, data):
        padding_length = data[-1]
        return data[:-padding_length]

# Obtener la clave manualmente (asegúrate de que tenga 24 bytes)
key = input("Clave de 24 bytes: ")

# Crear una instancia del cifrador
cipher = TripleDESCipher(key.encode())

# Texto sin cifrar
plaintext = input("Texto original: ")

# Cifrar el mensaje y codificar en Base64
ciphertext_base64 = cipher.encrypt(plaintext.encode())

# Descifrar el mensaje
decrypted_text = cipher.decrypt(ciphertext_base64)

print("Texto cifrado en Base64:", ciphertext_base64.decode('utf-8'))
print("Texto descifrado:", decrypted_text.decode('utf-8'))

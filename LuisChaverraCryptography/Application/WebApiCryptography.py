# Creación de la API Web del proyecto
# Importación de la librería Fastapi

from fastapi import FastAPI #Importación de la librería FastApi
import base64 #Importación de la libreria de Base64

#Importación de los clases de DES
from LuisChaverraCryptography.Core.Security.Encrypt.DESEncrypt import DESEncrypt
from LuisChaverraCryptography.Core.Security.Decrypt.DESDecrypt import DESDecrypt

#Importación de las clases de 3DES
from LuisChaverraCryptography.Core.Security.Encrypt.ThreeDESEncrypt import ThreeDESEncrypt
from LuisChaverraCryptography.Core.Security.Decrypt.ThreeDESDecrypt import ThreeDESDecrypt

#Importación de las clases de AES
from LuisChaverraCryptography.Core.Security.Encrypt.AESEncrypt import AESEncrypt
from LuisChaverraCryptography.Core.Security.Decrypt.AESDecrypt import AESDecrypt

#Importación de las clases de Blowfish
from LuisChaverraCryptography.Core.Security.Encrypt.BlowfishEncrypt import BlowfishEncrypt
from LuisChaverraCryptography.Core.Security.Decrypt.BlowfishDecrypt import BlowfishDecrypt

app: FastAPI = FastAPI(title='SOAP Python Cryptography', description='USBSI 2023-02')

@app.get("/DESEncrypt", summary="DES Encrypt", description="Codificado en DES", tags=["DES"])
async def DESEncode(Data: str | None = None, key: str | None = None):
    encrypted_data: str | None = None
    try:
        if len(key) != 8:
            encrypted_data = "Codificación interrumpida, la clave debe tener 8 caracteres"
        else:
            desencrypt = DESEncrypt(key.encode('utf-8'))
            plaintText = Data.encode('utf-8')
            cipherText = desencrypt.encrypt(plaintText)
            encrypted_data = base64.b64encode(cipherText).decode('utf-8')
    except:
        encrypted_data = "Codificación fallida"
    return encrypted_data

@app.get("/DESDecrypt", summary="DES Decrypt", description="Decodificado en DES",tags=["DES"])
async def DESDecode(Data: str | None = None, key: str | None = None):
    plaint_data: str | None = None
    try:
        if len(key) != 8:
            plaint_data = "Decodificación interrumpida, la clave debe tener 8 caracteres"
        else:
            desDecrypt = DESDecrypt(key.encode('utf-8'))
            descipherText = desDecrypt.decrypt(base64.b64decode(Data))
            plaint_data = descipherText.decode('utf-8')
    except:
        plaint_data = "Decodificación fallida"
    return plaint_data

#########################################################################################################

@app.get("/3DESEncrypt", summary="3DES Encrypt", description="Codificado en 3DES", tags=["3DES"])
async def ThreeDESEncode(Data: str | None = None, key: str | None = None):
    encrypted_data: str | None = None
    try:
        if len(key) != 24:
            encrypted_data = "Codificación interrumpida, la clave debe tener 24 caracteres"
        else:
            threedesEncrypt = ThreeDESEncrypt(key.encode('utf-8'))
            cipherText = threedesEncrypt.encrypt(Data.encode('utf-8'))
            encrypted_data = cipherText.decode('utf-8')
    except:
        encrypted_data = "Codificación fallida"
    return encrypted_data

@app.get("/3DESDecrypt", summary="3DES Decrypt", description="Decodificado en 3DES",tags=["3DES"])
async def ThreeDESDecode(Data: str | None = None, key: str | None = None):
    plaint_data: str | None = None
    try:
        if len(key) != 24:
            plaint_data = "Decodificación interrumpida, la clave debe tener 8 caracteres"
        else:
            threedesDecrypt = ThreeDESDecrypt(key.encode('utf-8'))
            descipherText = threedesDecrypt.decrypt(Data.encode('utf-8'))
            plaint_data = descipherText.decode('utf-8')
    except:
        plaint_data = "Decodificación fallida"
    return plaint_data

#########################################################################################################

@app.get("/AESEncrypt", summary="AES Encrypt", description="Codificado en AES", tags=["AES"])
async def AESEncode(Data: str | None = None, key: str | None = None):
    encrypted_data: str | None = None
    try:
        if len(key) != 16:
            encrypted_data = "Codificación interrumpida, la clave debe tener 16 caracteres"
        else:
            aesEncrypt = AESEncrypt(key.encode('utf-8'))
            cipherText = aesEncrypt.encrypt(Data)
            encrypted_data = cipherText
    except:
        encrypted_data = "Codificación fallida"
    return encrypted_data

@app.get("/AESDecrypt", summary="AES Decrypt", description="Decodificado en AES",tags=["AES"])
async def AESDecode(Data: str | None = None, key: str | None = None):
    plaint_data: str | None = None
    try:
        if len(key) != 16:
            plaint_data = "Decodificación interrumpida, la clave debe tener 8 caracteres"
        else:
            aesDecrypt = AESDecrypt(key.encode('utf-8'))
            descipherText = aesDecrypt.decrypt(Data)
            plaint_data = descipherText
    except:
        plaint_data = "Decodificación fallida"
    return plaint_data

#########################################################################################################

@app.get("/BlowfishEncrypt", summary="Blowfish Encrypt", description="Codificado en Blowfish", tags=["Blowfish"])
async def BlowfishEncode(Data: str | None = None, key: str | None = None):
    encrypted_data: str | None = None
    try:
        if len(key) < 8 or len(key) > 56:
            encrypted_data = "Codificación interrumpida, la clave debe tener entre 8 y 56 caracteres"
        else:
            blowfishEncrypt = BlowfishEncrypt(key.encode('utf-8'))
            cipherText = blowfishEncrypt.encrypt(Data)
            encrypted_data = cipherText
    except:
        encrypted_data = "Codificación fallida"
    return encrypted_data

@app.get("/BlowfishDecrypt", summary="Blowfish Decrypt", description="Decodificado en Blowfish",tags=["Blowfish"])
async def BlowfishDecode(Data: str | None = None, key: str | None = None):
    plaint_data: str | None = None
    try:
        if len(key) < 8 or len(key) > 56:
            plaint_data = "Codificación interrumpida, la clave debe tener entre 8 y 56 caracteres"
        else:
            blowfishDecrypt = BlowfishDecrypt(key.encode('utf-8'))
            descipherText = blowfishDecrypt.decrypt(Data)
            plaint_data = descipherText
    except:
        plaint_data = "Decodificación fallida"
    return plaint_data
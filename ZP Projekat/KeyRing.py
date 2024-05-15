import datetime
import hashlib
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.ciphers import modes, algorithms, Cipher


class KeyRing:
    def __init__(self):
        self.keys = []

    def getAllKeys(self):
        return self.keys

    def getKey(self, keyId):
        for key in self.keys:
            if key.keyId == keyId:
                return key

        # key not found
        return -1

    def getKeyByUserId(self, userId):
        for key in self.keys:
            if key.userId == userId:
                return key

        return -1

    def removeKey(self, keyId):
        for key in self.keys:
            if key.keyId == keyId:
                self.keys.remove(key)
                return

        # Error - key with that id not found!
        print("key with that id not found!")


class PublicKeyRing(KeyRing):
    def __init__(self):
        super().__init__()

    def addKey(self, publicKey, ownerTrust, userId, signatureTrust):
        # check if key id is already in key ring
        keyId = publicKey.public_numbers().n % (2 ** 64)
        if keyId not in self.keys:
            self.keys.append(PublicKeyRow(publicKey, ownerTrust, userId, signatureTrust))
            return

        # Error - key with that id already exists!
        print("key with that id already exists!")


class PrivateKeyRing(KeyRing):
    def __init__(self):
        super().__init__()

    def addKey(self, publicKey, privateKey, userId, passcode):
        # check if key id is already in key ring
        keyId = publicKey.public_numbers().n % (2 ** 64)
        if keyId not in self.keys:
            self.keys.append(PrivateKeyRow(publicKey, privateKey, userId, passcode))
            return

        # Error - key with that id already exists!
        print("key with that id already exists!")


class KeyRow:
    def __init__(self, publicKey, userId):
        self.timestamp = datetime.datetime.now()
        self.keyId = publicKey.public_numbers().n % (2 ** 64)
        self.publicKey = publicKey
        # print("///\n" + str(self.publicKey.public_numbers().n) + "\n" + str(self.keyId))
        self.userId = userId


# 1 row in PrivateKeyRing
class PrivateKeyRow(KeyRow):
    def __init__(self, publicKey, privateKey, userId, passcode):
        super().__init__(publicKey, userId)

        print("Before encryption: n = " + str(publicKey.public_numbers().n))

        # encrypt private key
        self.encryptedPrivateKey = self.encrypt(privateKey, passcode)

    def hashPasscode(self, passcode):
        value = passcode.encode()
        sha1_hash = hashlib.sha1()
        sha1_hash.update(value)
        hashed_value = sha1_hash.hexdigest()

        # Truncate the SHA-1 hash to 128 bits (16 bytes)
        truncated_hash = hashed_value[:16]
        hashKey = truncated_hash.encode()

        return hashKey

    def encrypt(self, privateKey, passcode):
        hashKey = self.hashPasscode(passcode)

        iv = os.urandom(8)  # For CAST-128, IV length is 64 bits (8 bytes)

        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(privateKey.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )) + padder.finalize()

        # Create a Cipher object
        cipher = Cipher(algorithms.CAST5(hashKey), modes.CBC(iv), backend=default_backend())

        # Perform encryption
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # print("Encryption: " + str(int.from_bytes(ciphertext, byteorder='big')))
        # return int.from_bytes(iv, byteorder='big') + int.from_bytes(ciphertext, byteorder='big')

        return iv + ciphertext

    def decrypt(self, passcode):
        hashKey = self.hashPasscode(passcode)
        iv_bytes = self.encryptedPrivateKey[:8]
        ciphertext_bytes = self.encryptedPrivateKey[8:]

        try:
            # Create a Cipher object
            cipher = Cipher(algorithms.CAST5(hashKey), modes.CBC(iv_bytes), backend=default_backend())

            # Perform decryption
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext_bytes) + decryptor.finalize()

            # Deserialize the decrypted data into an RSA private key object
            # privateKey = serialization.load_pem_private_key(unpadded_data, password=None, backend=default_backend())
            privateKey = serialization.load_der_private_key(decrypted_data, password=None, backend=default_backend())

            print("After decryption: n = " + str(privateKey.private_numbers().p * privateKey.private_numbers().q))

            return privateKey

        except:
            print("Incorrect passcode!")
            return -1


class PublicKeyRow(KeyRow):
    def __init__(self, publicKey, ownerTrust, userId, signatureTrust):
        super().__init__(publicKey, userId)

        self.ownerTrust = int(ownerTrust)
        self.signatureTrust = signatureTrust

        # get all signature values and put them in self.signatures
        self.signatures = ""
        self.keyLegitimacy = 0

        currLegitimacy = 0
        signatureIterate = self.signatureTrust.split(",")

        for signature in signatureIterate:
            key = privateKeyRing.getKeyByUserId(signature)
            if key == -1:  # key not found in private keyring
                key = publicKeyRing.getKeyByUserId(signature)

                if key == -1:  # error - user does not exist!
                    print("key with id:" + signature + " not found!")
                    continue

                # key found in public keyring

                self.signatures += str(key.ownerTrust) + " "
                currLegitimacy += key.ownerTrust

                continue

            # key found in private keyring

            self.signatures += str(100) + " "
            currLegitimacy += 100

        self.keyLegitimacy = currLegitimacy
        if self.keyLegitimacy > 100:
            self.keyLegitimacy = 100


privateKeyRing = PrivateKeyRing()
publicKeyRing = PublicKeyRing()

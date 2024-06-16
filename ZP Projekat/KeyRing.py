import base64
import hashlib
import json
import os
import pickle
import uuid
from abc import abstractmethod
from tkinter import messagebox
from typing import List

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.ciphers import modes, algorithms, Cipher

from datetime import datetime


class KeyRing:
    def __init__(self):
        self.keys = []

    def getAllKeys(self) -> List["KeyRow"]:
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

    @abstractmethod
    def save2Disk(self, filename: str):
        pass

    @abstractmethod
    def tryLoadFromDisk(self, filename: str):
        pass


class PublicKeyRing(KeyRing):
    def __init__(self):
        super().__init__()

        self.keys: List[PublicKeyRow] = []

    def addKey(self, publicKey, ownerTrust, userId, signatureTrust):
        # check if key id is already in key ring
        keyId = publicKey.public_numbers().n % (2 ** 64)
        if keyId not in [x.keyId for x in self.keys]:
            self.keys.append(PublicKeyRow(publicKey=publicKey, ownerTrust=ownerTrust, userId=userId, signatureTrust=signatureTrust))
            return

        # Error - key with that id already exists!
        print("key with that id already exists!")

    def loadKey(self, timestamp, publicKey, ownerTrust, userId, keyLegitimacy, signatures, signatureTrust):
        # check if key id is already in key ring
        keyId = publicKey.public_numbers().n % (2 ** 64)
        if keyId not in [x.keyId for x in self.keys]:
            self.keys.append(
                PublicKeyRow(timestamp=timestamp, publicKey=publicKey, ownerTrust=ownerTrust, userId=userId, keyLegitimacy=keyLegitimacy,
                              signatures=signatures, signatureTrust=signatureTrust))
            return

        # Error - key with that id already exists!
        print("Key with that id already exists!")

    def save2Disk(self, filename: str):
        if len(self.keys) == 0:
            return

        currentDirectory = os.getcwd()
        print(f"Current directory: {currentDirectory}")

        path = os.path.join(currentDirectory, "KeyRings", filename)

        directory = os.path.dirname(path)
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
                print(f"Directory created: {directory}")
            except Exception as e:
                print(f"Failed to create directory: {directory}")
                print(e)
                return

        jsonFile = {}

        for keyRow in self.keys:
            public_key_pem = keyRow.publicKey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            jsonFile[keyRow.keyId] = {}

            jsonFile[keyRow.keyId]["Timestamp"] = keyRow.timestamp.isoformat()
            jsonFile[keyRow.keyId]["PublicKey"] = public_key_pem.decode('utf-8')

            jsonFile[keyRow.keyId]["OwnerTrust"] = keyRow.ownerTrust
            jsonFile[keyRow.keyId]["UserId"] = keyRow.userId
            jsonFile[keyRow.keyId]["KeyLegitimacy"] = keyRow.keyLegitimacy
            jsonFile[keyRow.keyId]["Signatures"] = keyRow.signatures
            jsonFile[keyRow.keyId]["SignatureTrust"] = keyRow.signatureTrust

        try:
            with open(path, 'w') as file:
                json.dump(jsonFile, file, indent=4)
                print(f"KeyRing saved to: {path}")
        except PermissionError as e:
            print(f"Permission error while writing to file: {path}")
            print(e)
        except Exception as e:
            print(f"An error occurred while writing to file: {path}")
            print(e)

    def tryLoadFromDisk(self, filename: str):
        currentDirectory = os.getcwd()
        # print(f"Current directory: {currentDirectory}")

        path = os.path.join(currentDirectory, "KeyRings", filename)

        try:
            print(f"Loading from Disk: {path}")

            with open(path, 'r') as file:
                jsonData = json.load(file)

                for keyId in jsonData:
                    self.loadKey(
                        timestamp=datetime.fromisoformat(jsonData[keyId]["Timestamp"]),
                        publicKey=serialization.load_pem_public_key(jsonData[keyId]["PublicKey"].encode('utf-8')),
                        ownerTrust=jsonData[keyId]["OwnerTrust"],
                        userId=jsonData[keyId]["UserId"],
                        keyLegitimacy=jsonData[keyId]["KeyLegitimacy"],
                        signatures=jsonData[keyId]["Signatures"],
                        signatureTrust=jsonData[keyId]["SignatureTrust"]
                        )

        except FileNotFoundError:
            print(f"KeyRing not found on disk for user. Creating a new one...")
            return None
        except:
            return None


class PrivateKeyRing(KeyRing):
    def __init__(self):
        super().__init__()

        self.keys: List[PrivateKeyRow] = []

    def addKey(self, publicKey, privateKey, userId, passcode):
        # check if key id is already in key ring
        keyId = publicKey.public_numbers().n % (2 ** 64)
        if keyId not in [x.keyId for x in self.keys]:
            self.keys.append(PrivateKeyRow(publicKey=publicKey, privateKey=privateKey, userId=userId, passcode=passcode,
                                           timestamp=None, encryptedPrivateKey=None))
            return

        # Error - key with that id already exists!
        print("Key with that id already exists!")

    # used for leading row with encrypted private key
    def loadKey(self, timestamp, publicKey, encryptedPrivateKey, userId):
        # check if key id is already in key ring
        keyId = publicKey.public_numbers().n % (2 ** 64)
        if keyId not in [x.keyId for x in self.keys]:
            self.keys.append(
                PrivateKeyRow(publicKey=publicKey, privateKey=None, userId=userId, passcode=None, timestamp=timestamp,
                              encryptedPrivateKey=encryptedPrivateKey))
            return False

        # Error - key with that id already exists!
        print("Key with that id already exists!")

    def save2Disk(self, filename: str):
        if len(self.keys) == 0:
            return

        currentDirectory = os.getcwd()
        print(f"Current directory: {currentDirectory}")

        path = os.path.join(currentDirectory, "KeyRings", filename)

        directory = os.path.dirname(path)
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
                print(f"Directory created: {directory}")
            except Exception as e:
                print(f"Failed to create directory: {directory}")
                print(e)
                return

        jsonFile = {}

        for keyRow in self.keys:
            public_key_pem = keyRow.publicKey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            jsonFile[keyRow.keyId] = {}
            jsonFile[keyRow.keyId]["Timestamp"] = keyRow.timestamp.isoformat()
            jsonFile[keyRow.keyId]["UserId"] = keyRow.userId

            jsonFile[keyRow.keyId]["PublicKey"] = public_key_pem.decode('utf-8')
            jsonFile[keyRow.keyId]["EncryptedPrivateKey"] = base64.b64encode(keyRow.encryptedPrivateKey).decode('utf-8')

        try:
            with open(path, 'w') as file:
                json.dump(jsonFile, file, indent=4)
                print(f"KeyRing saved to: {path}")
        except PermissionError as e:
            print(f"Permission error while writing to file: {path}")
            print(e)
        except Exception as e:
            print(f"An error occurred while writing to file: {path}")
            print(e)

    def tryLoadFromDisk(self, filename: str):
        currentDirectory = os.getcwd()
        # print(f"Current directory: {currentDirectory}")

        path = os.path.join(currentDirectory, "KeyRings", filename)

        try:
            print(f"Loading from Disk: {path}")

            with open(path, 'r') as file:
                jsonData = json.load(file)

                for keyId in jsonData:
                    self.loadKey(
                        publicKey=serialization.load_pem_public_key(jsonData[keyId]["PublicKey"].encode('utf-8')),
                        encryptedPrivateKey=base64.b64decode(jsonData[keyId]["EncryptedPrivateKey"]),
                        userId=jsonData[keyId]["UserId"],
                        timestamp=datetime.fromisoformat(jsonData[keyId]["Timestamp"]))

        except FileNotFoundError:
            print(f"KeyRing not found on disk for user. Creating a new one...")
            return None
        except:
            return None


class KeyRow:
    def __init__(self, publicKey, userId):
        self.timestamp = datetime.now()
        self.keyId = publicKey.public_numbers().n % (2 ** 64)
        self.publicKey = publicKey
        self.userId = userId


# 1 row in PrivateKeyRing
class PrivateKeyRow(KeyRow):
    def __init__(self, publicKey, privateKey=None, userId=None, passcode=None, timestamp=None,
                 encryptedPrivateKey=None):
        super().__init__(publicKey, userId)

        print("Before encryption: n = " + str(publicKey.public_numbers().n))

        # check if new user id was already mentioned somewhere before, find the ? and replace with owner trust value
        # recalculate keyLegitimacy
        # fuj kod
        if privateKey and passcode:
            # encrypt private key
            self.encryptedPrivateKey = self.encrypt(privateKey, passcode)
        elif encryptedPrivateKey and timestamp:
            self.timestamp = timestamp
            self.encryptedPrivateKey = encryptedPrivateKey
        else:
            raise ValueError("Invalid arguments provided for KeyRow initialization")

        for row in publicKeyRing.getAllKeys():
            for i in range(0, len(row.signatureTrust.split(", "))):
                signature = row.signatureTrust.split(", ")[i]
                signature = signature.strip(' ')

                if signature != userId:
                    continue

                # find the ? in string and change it to self.ownerTrust value
                newSignatureString = ""
                newSignatures = 0
                for j in range(0, len(row.signatures.split(" ")) - 1):
                    if row.signatures.split(" ")[j] == "":
                        continue

                    if i == j and row.signatures.split(" ")[i] == "?":
                        newSignatureString += str(100) + " "
                        newSignatures += 100
                    elif row.signatures.split(" ")[j] == "?":
                        newSignatureString += "? "
                        continue
                    else:
                        newSignatureString += row.signatures.split(" ")[j] + " "
                        newSignatures += int(row.signatures.split(" ")[j])

                row.signatures = newSignatureString
                row.keyLegitimacy = min(newSignatures, 100)

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
            privateKey = serialization.load_der_private_key(decrypted_data, password=None, backend=default_backend())

            print("After decryption: n = " + str(privateKey.private_numbers().p * privateKey.private_numbers().q))

            return privateKey

        except:
            messagebox.showerror("Error", "Incorrect passcode provided!")
            # print("Incorrect passcode!")
            return -1


class PublicKeyRow(KeyRow):
    def __init__(self, publicKey, ownerTrust, userId, signatureTrust, signatures=None, timestamp=None, keyLegitimacy=None):
        super().__init__(publicKey, userId)

        self.ownerTrust = int(ownerTrust)
        self.signatureTrust = signatureTrust

        if timestamp:
            self.timestamp = timestamp

        if signatures and keyLegitimacy:
            self.keyLegitimacy = keyLegitimacy
            self.signatures = signatures
            return

        # check if there are duplicate signatureTrust values inserted
        tempSignaturesList = self.signatureTrust.split(", ")
        tempSignaturesList = [x.strip(' ') for x in tempSignaturesList]
        if len(tempSignaturesList) != len(set(tempSignaturesList)):
            # this is called when there are atleast 2 signatures, so it wont break
            self.signatureTrust = ""
            for signature in set(tempSignaturesList):
                self.signatureTrust += signature + ", "
            self.signatureTrust = self.signatureTrust[:-2]

            messagebox.showwarning("Warning", "Removing duplicate signatures!")


        # get all signature values and put them in self.signatures
        self.signatures = ""
        self.keyLegitimacy = 0

        currLegitimacy = 0
        signatureIterate = self.signatureTrust.split(",")

        for signature in signatureIterate:
            signature = signature.strip(' ')

            if signature == "":
                continue

            key = privateKeyRing.getKeyByUserId(signature)
            if key == -1:  # key not found in private keyring
                key = publicKeyRing.getKeyByUserId(signature)

                if key == -1:  # error - user does not exist!
                    self.signatures += "? "
                    # messagebox.showwarning("Warning", "Signature with id: " + signature + " not found!")
                    print("Signature with id:" + signature + " not found!")
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


        # check if new user id was already mentioned somewhere before, find the ? and replace with owner trust value
        # recalculate keyLegitimacy
        # fuj kod
        for row in publicKeyRing.getAllKeys():
            for i in range(0, len(row.signatureTrust.split(", "))):
                signature = row.signatureTrust.split(", ")[i]
                signature = signature.strip(' ')

                if signature != userId:
                    continue

                # find the ? in string and change it to self.ownerTrust value
                newSignatureString = ""
                newSignatures = 0
                for j in range(0, len(row.signatures.split(" ")) - 1):
                    # print(row.signatures.split(" ")[j])
                    if row.signatures.split(" ")[j] == "":
                        continue

                    if i == j and row.signatures.split(" ")[i] == "?":
                        newSignatureString += str(self.ownerTrust) + " "
                        newSignatures += self.ownerTrust
                    elif row.signatures.split(" ")[j] == "?":
                        newSignatureString += "? "
                        continue
                    else:
                        newSignatureString += row.signatures.split(" ")[j] + " "
                        newSignatures += int(row.signatures.split(" ")[j])

                row.signatures = newSignatureString
                row.keyLegitimacy = min(newSignatures, 100)


privateKeyRing = PrivateKeyRing()
publicKeyRing = PublicKeyRing()

privateKeyRingName = "PrivateKeyRing"
publicKeyRingName = "PublicKeyRing"

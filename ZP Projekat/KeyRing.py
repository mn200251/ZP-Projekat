import datetime
import time


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

    def removeKey(self, keyId):
        for key in self.keys:
            if key.keyId == keyId:
                self.keys.remove(key)
                return

        # Error - key with that id not found!


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


class PrivateKeyRing(KeyRing):
    def __init__(self):
        super().__init__()

    def addKey(self, publicKey, privateKey, userId):
        # check if key id is already in key ring
        keyId = publicKey.public_numbers().n % (2 ** 64)
        if keyId not in self.keys:
            self.keys.append(PrivateKeyRow(publicKey, privateKey, userId))
            return

        # Error - key with that id already exists!


class KeyRow:
    def __init__(self, publicKey, userId):
        self.timestamp = datetime.datetime.now()
        self.keyId = publicKey.public_numbers().n % (2 ** 64)
        self.publicKey = publicKey
        print("///\n" + str(self.publicKey.public_numbers().n) + "\n" + str(self.keyId))
        self.userId = userId


# 1 row in PrivateKeyRing
class PrivateKeyRow(KeyRow):
    def __init__(self, publicKey, privateKey, userId):
        super().__init__(publicKey, userId)

        # encrypt private key
        self.encryptedPrivateKey = self.encrypt(privateKey)

    def decrypt(self, passcode):
        pass

    def encrypt(self, privateKey):
        return "Hashed value here..."


class PublicKeyRow(KeyRow):
    def __init__(self, publicKey, ownerTrust, userId, signatureTrust):
        super().__init__(publicKey, userId)

        self.ownerTrust = ownerTrust
        self.signatureTrust = signatureTrust

        # get all signature values and put them in self.signatures
        self.signatures = []
        self.keyLegitimacy = 0
        for signature in self.signatureTrust:
            self.keyLegitimacy += signature

        # calculate key legitimacy value (0-100), 100 - trust
        self.keyLegitimacy = 0
        if self.keyLegitimacy > 100:
            self.keyLegitimacy = 100

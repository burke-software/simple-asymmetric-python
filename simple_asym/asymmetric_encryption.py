from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import hashlib
import base64
import random
import string
from .aes import AESCipher


class AsymCrypt():
    def __init__(self, aes_key=None, public_key=None, private_key=None):
        if aes_key:
            self.set_aes_key(aes_key)
        self.set_public_key(public_key)
        self.set_private_key(private_key)

    def _get_rsa_cipher(self):
        if self.private_key:
            return PKCS1_OAEP.new(self.private_key)
        return PKCS1_OAEP.new(self.public_key)

    def _random_string(self, N):
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(N))

    def _generate_key(self, N=255):
        key = self._random_string(N)
        return hashlib.sha256(key.encode()).digest()

    def _generate_passphrase(self, N=255):
        return self._random_string(N)

    def _force_bytes(self, text):
        try:  # Encode if not already done
            text = text.encode()
        except AttributeError:
            pass
        return text

    def make_rsa_keys(self, passphrase=None, bits=4096):
        """ Create new rsa private and public keys
        passphrase: Optional RSA private key passphrase. Returns encrypted
        version if set
        bits: Bits for pycrypto's generate function. Safe to ignore.
        return tuple of string version of keys (private, public) """
        self.private_key = RSA.generate(bits)
        self.public_key = self.private_key.publickey()
        private = self.private_key.exportKey(passphrase=passphrase)
        public = self.public_key.exportKey()
        return private, public

    def make_rsa_keys_with_passphrase(self, bits=4096):
        """ Wrapper around make_rsa_keys that also generates a passphrase
        Returns (private, public, passphrase) """
        passphrase = self._generate_passphrase()
        private, public = self.make_rsa_keys(passphrase=passphrase, bits=bits)
        return private, public, passphrase

    def rsa_encrypt(self, text, use_base64=False):
        """ Return ciphertext of plain text
        use_base64: set True to return a base64 encoded unicode string (just for
        convenience)
        """
        text = self._force_bytes(text)
        cipher = self._get_rsa_cipher()
        ciphertext = cipher.encrypt(text)
        if use_base64 is True:
            ciphertext = base64.b64encode(ciphertext).decode()
        return ciphertext

    def rsa_decrypt(self, ciphertext, use_base64=False):
        cipher = self._get_rsa_cipher()
        if use_base64 is True:
            ciphertext = base64.b64decode(ciphertext)
        return cipher.decrypt(ciphertext)

    def set_private_key(self, private_key, passphrase=None):
        """ Set private key
        private_key: String or RSA key object
        passphrase: Optional passphrase for encrpyting the RSA private key
        """
        if isinstance(private_key, str):
            self.private_key = RSA.importKey(private_key, passphrase=passphrase)
        else:
            self.private_key = private_key
        return self.private_key

    def set_public_key(self, public_key):
        """ Set public key
        public_key: String or RSA key object
        """
        if isinstance(public_key, str):
            self.public_key = RSA.importKey(public_key)
        else:
            self.public_key = public_key
        return self.public_key

    def set_aes_key(self, aes_key):
        self.aes_key = aes_key
        self.aes_cipher = AESCipher(aes_key)

    def set_aes_key_from_encrypted(self, ciphertext):
        aes_key = self.rsa_decrypt(ciphertext)
        self.set_aes_key(aes_key)

    def get_encrypted_aes_key(self, public_key):
        public_asym = AsymCrypt(public_key=public_key)
        return public_asym.rsa_encrypt(self.aes_key)

    def make_aes_key(self):
        """ Generate a new AES key and return it. """
        key = self._generate_key()
        self.set_aes_key(key)
        return key

    def encrypt(self, text):
        """ Encrypt text using combined RSA + AES encryption.
        Requires public_key and aes_key to be set. aes_key may be generated with
        AsymCrypt.make_aes_key if you do not already have one."""
        return self.aes_cipher.encrypt(text)

    def decrypt(self, text):
        """ Decrypt ciphertext using combined RSA + AES encrpytion.
        Requires private_key and aes_key to be set. aes_key may have been
        generated with
        AsymCrypt.make_aes_key which should have been done at time or
        encryption.
        """
        return self.aes_cipher.decrypt(text)

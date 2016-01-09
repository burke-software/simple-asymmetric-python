import base64
import random
import string

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from .exceptions import (
    MissingAESException, MissingRSAPrivateException, MissingRSAPublicException)


class AsymCrypt():
    aes_cipher = None

    def __init__(self, aes_key=None, public_key=None, private_key=None):
        """ A class to encrypt and decrypt using Asymmetrical encryption.
        All kwargs are optional.

        :param aes_key: AES key used for symmetric encryption
        :param public_key: Public RSA key used for asymmetric encryption
        "param private_key: Private RSA key used for asmmetric decryption
        """
        if aes_key:
            self.set_aes_key(aes_key)
        self.set_public_key(public_key)
        self.set_private_key(private_key)

    def _get_padding(self):
        return padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )

    def _random_string(self, N):
        return ''.join(random.SystemRandom().choice(
            string.ascii_uppercase + string.digits) for _ in range(N))

    def _generate_key(self):
        return Fernet.generate_key()

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

        :param passphrase: Optional RSA private key passphrase. Returns encrypted
        version if set
        :param bits: Bits for pycrypto's generate function. Safe to ignore.
        :rtype: tuple of string version of keys (private, public) """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

        if passphrase:
            encryption_alg = serialization.BestAvailableEncryption(
                passphrase.encode()
            )
        else:
            encryption_alg = serialization.NoEncryption()

        private = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_alg
        )

        public = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private, public

    def make_rsa_keys_with_passphrase(self, bits=4096):
        """ Wrapper around make_rsa_keys that also generates a passphrase

        :param bits: Bits for pycrypto's generate function. Safe to ignore.
        :rtype: tuple (private, public, passphrase) """
        passphrase = self._generate_passphrase()
        private, public = self.make_rsa_keys(passphrase=passphrase, bits=bits)
        return private, public, passphrase

    def rsa_encrypt(self, text, use_base64=False):
        """ Convert plain text to ciphertext

        :param text: Plaintext to encrypt
        :param use_base64: set True to return a base64 encoded unicode string
        (just for convenience)
        :type use_base64: Boolean
        :rtype: ciphertext string
        """
        text = self._force_bytes(text)
        if not self.public_key:
            raise MissingRSAPublicException
        ciphertext = self.public_key.encrypt(
            text,
            self._get_padding()
        )
        if use_base64 is True:
            ciphertext = base64.b64encode(ciphertext).decode()
        return ciphertext

    def rsa_decrypt(self, ciphertext, use_base64=False):
        """ Convert ciphertext into plaintext

        :param ciphertext: Ciphertext to decrypt
        :param use_base64: set True to return a base64 encoded unicode string
        (just for convenience)
        :type use_base64: Boolean
        :rtype: plaintext string
        """

        if use_base64 is True:
            ciphertext = base64.b64decode(ciphertext)
        if not self.private_key:
            raise MissingRSAPrivateException
        return self.private_key.decrypt(
            ciphertext,
            self._get_padding()
        )

    def set_private_key(self, private_key, passphrase=None):
        """ Set private key

        :param private_key: String or RSAPrivateKey object
        :param passphrase: Optional passphrase for encrpyting the RSA private key
        :rtype: private key
        """
        if isinstance(private_key, (bytes, str)):
            private_key = self._force_bytes(private_key)
            if passphrase:
                passphrase = self._force_bytes(passphrase)
            self.private_key = serialization.load_pem_private_key(
                private_key,
                password=passphrase,
                backend=default_backend()
            )
        else:
            self.private_key = private_key
        return self.private_key

    def set_public_key(self, public_key):
        """ Set public key

        :param public_key: String or RSAPublicKey object
        :rtype: public key
        """
        if isinstance(public_key, (bytes, str)):
            public_key = self._force_bytes(public_key)
            self.public_key = serialization.load_pem_public_key(
                public_key,
                backend=default_backend()
            )
        else:
            self.public_key = public_key
        return self.public_key

    def set_aes_key(self, aes_key):
        self.aes_key = aes_key
        self.aes_cipher = Fernet(self.aes_key)

    def set_aes_key_from_encrypted(self, ciphertext):
        aes_key = self.rsa_decrypt(ciphertext)
        self.set_aes_key(aes_key)

    def get_encrypted_aes_key(self, public_key):
        public_asym = AsymCrypt(public_key=public_key)
        return public_asym.rsa_encrypt(self.aes_key)

    def make_aes_key(self):
        """ Generate a new AES key

        :rtype: AES key string
        """
        key = self._generate_key()
        self.set_aes_key(key)
        return key

    def encrypt(self, text):
        """ Encrypt text using AES encryption.
        Requires public_key and aes_key to be set. aes_key may be generated with
        AsymCrypt.make_aes_key if you do not already have one.

        :param text: text to encrypt
        :rtype: ciphertext string
        """
        text = self._force_bytes(text)
        if not self.aes_cipher:
            raise MissingAESException
        return self.aes_cipher.encrypt(text)

    def decrypt(self, text):
        """ Decrypt ciphertext using AES encrpytion.
        Requires private_key and aes_key to be set. aes_key may have been
        generated with AsymCrypt.make_aes_key which should have been done at
        time or encryption.

        :param text: ciphertext to decrypt
        :rtype: decrypted text string
        """
        if not self.aes_cipher:
            raise MissingAESException
        return self.aes_cipher.decrypt(text)

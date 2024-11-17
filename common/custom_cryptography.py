import datetime
import hashlib
import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, final

from argon2 import PasswordHasher
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID


# ----------------------------------------
# Base error classes
# ----------------------------------------


class BaseError(ValueError):
    """Base class for all custom errors."""

    default_message = "An error occurred."

    def __init__(self, message=None):
        if message is None:
            message = self.default_message
        super().__init__(message)


# ----------------------------------------
# Serialization and Deserialization errors
# ----------------------------------------


class SerializationError(BaseError):
    """Raised when there is an error during serialization."""

    default_message = "An error occurred during serialization."


class DeserializationError(BaseError):
    """Raised when there is an error during deserialization."""

    default_message = "An error occurred during deserialization."


# ----------------------------------------
# Cryptographic errors
# ----------------------------------------


class CryptographyError(BaseError):
    """Base class for cryptographic-related errors."""

    default_message = "A cryptographic error occurred."


class KeyGenerationError(CryptographyError):
    """Raised when key generation fails."""

    default_message = "Key generation failed."


class KeyLoadingError(CryptographyError):
    """Raised when loading of a key fails."""

    default_message = "Failed to load the key."


class EncryptionError(CryptographyError):
    """Raised when encryption fails due to invalid parameters or other reasons."""

    default_message = "Encryption failed due to invalid parameters or other reasons."


class DecryptionError(CryptographyError):
    """Raised when decryption fails due to invalid parameters or other reasons."""

    default_message = "Decryption failed due to invalid parameters or other reasons."


class RSAEncryptionError(EncryptionError):
    """Raised when RSA encryption fails."""

    default_message = "RSA encryption failed."


class RSADecryptionError(DecryptionError):
    """Raised when RSA decryption fails."""

    default_message = "RSA decryption failed."


class FernetEncryptionError(EncryptionError):
    """Raised when Fernet encryption fails."""

    default_message = "Fernet encryption failed."


class FernetDecryptionError(DecryptionError):
    """Raised when Fernet decryption fails."""

    default_message = "Fernet decryption failed."


class SigningError(CryptographyError):
    """Raised when signing fails."""

    default_message = "Signing operation failed."


class InvalidSignatureError(CryptographyError):
    """Raised when signature verification fails."""

    default_message = "Signature verification failed."


class RecipientVerificationError(CryptographyError):
    """Base class for recipient verification errors."""

    default_message = "Recipient verification error."


class RecipientIdVerificationError(RecipientVerificationError):
    """Raised when the recipient ID cannot be verified."""

    default_message = "Recipient ID verification failed."


class NotForRecipientError(RecipientVerificationError):
    """Raised when the message is not intended for the recipient."""

    default_message = "The message is not intended for the recipient."


# ----------------------------------------
# Message errors
# ----------------------------------------


class MessageError(BaseError):
    """Base class for message-related errors."""

    default_message = "A message error occurred."


class UntrustedSender(MessageError):
    """Raised when the sender cannot be verified."""

    default_message = "The message is possibly sent by untrusted sender."


class MessageTimeOut(MessageError):
    """Raised when the current time is not between message specified values"""

    default_message = "Current time is out of range"


# ----------------------------------------
# Certificate errors
# ----------------------------------------


class CertificateError(BaseError):
    """Base class for certificate-related errors."""

    default_message = "A certificate-related error occurred."


class CertificateGenerationError(CertificateError):
    """Raised when certificate generation fails."""

    default_message = "Certificate generation failed."


class CertificateLoadingError(CertificateError):
    """Raised when loading of a certificate fails."""

    default_message = "Failed to load the certificate."


class CertificateValidationError(CertificateError):
    """Raised when certificate validation fails."""

    default_message = "Certificate validation failed."


class CertificateExpiredError(CertificateValidationError):
    """Raised when a certificate is expired."""

    default_message = "The certificate has expired."


class CertificateSelfSignedError(CertificateValidationError):
    """Raised when a certificate is self-signed and should not be accepted."""

    default_message = "The certificate is self-signed and should not be accepted."


class UnknownCA(CertificateValidationError):
    """Raised when the Certificate Authority (CA) is unknown."""

    default_message = "The Certificate Authority (CA) is unknown."


class CertificateMissing(CertificateError):
    """Raised when a required certificate is missing."""

    default_message = "A required certificate is missing."


# ----------------------------------------
# Argument errors
# ----------------------------------------


class ArgumentError(BaseError):
    """Base class for argument-related errors."""

    default_message = "An argument-related error occurred."


class InvalidArgumentError(ArgumentError):
    """Raised when a function or method receives an invalid argument."""

    default_message = "An invalid argument was provided."


class MissingArgumentError(ArgumentError):
    """Raised when a required argument is missing."""

    default_message = "A required argument is missing."


# ----------------------------------------
# Data validation errors
# ----------------------------------------


class DataValidationError(BaseError):
    """Raised when data validation fails."""

    default_message = "Data validation failed."


class DataIntegrityError(DataValidationError):
    """Raised when data integrity checks fail."""

    default_message = "Data integrity check failed."


class DataFormatError(DataValidationError):
    """Raised when data is in an incorrect or unexpected format."""

    default_message = "The data is in an incorrect or unexpected format."


# ----------------------------------------
# Miscellaneous errors
# ----------------------------------------


class KeyIDComputingError(BaseError):
    """Raised when get_key_id function occurred an error."""

    default_message = "get_key_id function occurred an error."

class CustomAESGCM:
    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, nonce_length=12) -> bytes:
        """
        Encrypts a message using AES-GCM.

        :param key: The key to use for encryption.
        :param plaintext: The plaintext message to encrypt.
        :param nonce_length: Length of the nonce (default 12 bytes)
        :return: A ciphertext package (combination of nonce, ciphertext and tag)
        """
        nonce = os.urandom(nonce_length)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        #print("key\t", key, "\tnonce\t", nonce, "\tciphertext\t", ciphertext, "\ttag\t", encryptor.tag)
        return nonce + ciphertext + encryptor.tag

    @staticmethod
    def decrypt(key: bytes, ciphertext_package: bytes, nonce_length=12, tag_length=16) -> bytes:
        """
        Decrypts a message using AES-GCM.

        :param key: The key to use for decryption.
        :param ciphertext_package: Combination of nonce, ciphertext and tag
        :param nonce_length: Length of the nonce (default 12 bytes)
        :param tag_length: Length of the tag (default 16 bytes)
        :return: The decrypted plaintext.
        """
        nonce = ciphertext_package[:nonce_length]
        tag = ciphertext_package[-tag_length:]
        ciphertext = ciphertext_package[nonce_length:-tag_length]
        #print("key\t", key, "\tnonce\t", nonce, "\tciphertext\t", ciphertext, "\ttag\t", tag)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext


@final
class CustomRSA:
    @staticmethod
    def generate_keypair(
        public_exponent: int = 65537,
        key_size: int = 4096,
        password: Optional[str] = None,
    ) -> Tuple[bytes, bytes]:
        """
        Generates an RSA key pair.

        :param public_exponent: The public exponent of the key.
        :param key_size: The size of the key in bits.
        :param password: The password to encrypt the private key.
        :return: A tuple containing the private key and public key in PEM format.
        """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=public_exponent,
                key_size=key_size,
                backend=default_backend(),
            )
            public_key = private_key.public_key()
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=(
                    serialization.BestAvailableEncryption(password.encode())
                    if password
                    else serialization.NoEncryption()
                ),
            )
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return private_pem, public_pem
        except Exception as e:
            raise KeyGenerationError(f"Failed to generate RSA keypair: {e}")

    @staticmethod
    def encrypt(public_key_pem: bytes, message: bytes) -> bytes:
        """
        Encrypts a message using an RSA public key.

        :param public_key_pem: The public key in PEM format.
        :param message: The message to encrypt.
        :return: The encrypted message as bytes.
        :raises ValueError: If encryption fails.
        """
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem, backend=default_backend()
            )
            ciphertext = public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None,
                ),
            )
            return ciphertext
        except Exception as e:
            raise RSAEncryptionError(f"Failed to encrypt message: {e}")

    @staticmethod
    def decrypt(
        private_key_pem: bytes, ciphertext: bytes, password: Optional[str] = None
    ) -> bytes:
        """
        Decrypts a message using an RSA private key.

        :param private_key_pem: The private key in PEM format.
        :param ciphertext: The encrypted message.
        :param password: The password for the private key.
        :return: The decrypted message as bytes.
        :raises ValueError: If decryption fails.
        """
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=password.encode() if password else None,
                backend=default_backend(),
            )
            decrypted_message = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None,
                ),
            )
            return decrypted_message
        except Exception as e:
            raise RSADecryptionError(f"Failed to decrypt message: {e}")

    @staticmethod
    def verify(public_key_pem: bytes, raw: bytes, signature: bytes):
        """
        Verifies a digital signature.

        :param public_key_pem: The public key in PEM format.
        :param raw: The original message.
        :param signature: The digital signature to verify.
        """
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem, backend=default_backend()
            )
        except Exception as e:
            raise KeyLoadingError(f"Failed to load PEM public key : {e}")
        public_key.verify(
            signature,
            raw,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA512(),
        )

    @staticmethod
    def sign(
        private_key_pem: bytes, raw: bytes, password: Optional[str] = None
    ) -> bytes:
        """
        Signs a message using an RSA private key.

        :param private_key_pem: The private key in PEM format.
        :param raw: The message to sign.
        :param password: The password for the private key.
        :return: The digital signature as bytes.
        :raises ValueError: If signing fails.
        """
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=password.encode() if password else None,
                backend=default_backend(),
            )
        except Exception as e:
            raise KeyLoadingError(f"Failed to load PEM private key : {e}")
        try:
            signature = private_key.sign(
                raw,
                padding.PSS(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA512(),
            )
            return signature
        except Exception as e:
            raise SigningError(f"Failed to sign message: {e}")


class Argon2Authentication:
    def __init__(self, password:str):
        self.challenge_to_send: bytes = os.urandom(16)
        self.password = password.encode()
        self.ph = PasswordHasher()

    def derive_challenge(self, challenge: bytes) -> str:
        return self.ph.hash(challenge + self.password)

    def authenticate(self, derived_challenge: str):
        try:
            self.ph.verify(derived_challenge, self.challenge_to_send + self.password)
            return True
        except:
            return False


@dataclass(frozen=True)
class x509info:
    version: int
    serial_number: int
    subject: str
    subject_pubkey: bytes
    issuer: str
    not_valid_before: datetime.datetime
    not_valid_after: datetime.datetime
    signature_algorithm: str
    extensions: x509.Extensions
    is_valid: bool
    expired: bool
    self_signed: bool
    authorized_issuer: bool
    current_ca: Optional[Dict[str, bytes]]
    issuer_info: Optional["x509info"] = None


@final
class Customx509:
    @staticmethod
    def sign_certificate(
        subject_name: str,
        issuer_name: str,
        issuer_private_key_pem: bytes,
        subject_public_key_pem: bytes,
        validity_days: int,
        serial_number: int = x509.random_serial_number(),
        issuer_pem_password: Optional[str] = None,
    ) -> bytes:
        """
        Generates an X.509 certificate.

        :param subject_name: The subject's common name.
        :param issuer_name: The issuer's common name.
        :param issuer_private_key_pem: The issuer's private key in PEM format.
        :param subject_public_key_pem: The subject's public key in PEM format.
        :param validity_days: The number of days the certificate is valid.
        :param serial_number: The serial number of the certificate.
        :param issuer_pem_password: The password for the issuer's private key.
        :return: The certificate in PEM format.
        :raises ValueError: If certificate generation fails.
        """
        try:
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
            issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])

            builder = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(
                    serialization.load_pem_public_key(
                        subject_public_key_pem, backend=default_backend()
                    )
                )
                .serial_number(serial_number)
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                .not_valid_after(
                    datetime.datetime.now(datetime.timezone.utc)
                    + datetime.timedelta(days=validity_days)
                )
            )

            issuer_private_key = serialization.load_pem_private_key(
                issuer_private_key_pem,
                password=issuer_pem_password.encode() if issuer_pem_password else None,
                backend=default_backend(),
            )

            certificate = builder.sign(
                private_key=issuer_private_key,
                algorithm=hashes.SHA512(),
                backend=default_backend(),
            )

            return certificate.public_bytes(encoding=serialization.Encoding.PEM)
        except Exception as e:
            raise CertificateGenerationError(f"Failed to generate certificate: {e}")

    @staticmethod
    def verify_certificate(
        certificate_pem: bytes, authorized_issuers: dict[str, bytes]
    ) -> x509info:
        """
        Verifies an X.509 certificate.

        :param certificate_pem: The certificate in PEM format.
        :param authorized_issuers: A dictionary of authorized issuers with their public keys.
        :raises ValueError: If certificate verification fails.
        """
        try:
            certificate = x509.load_pem_x509_certificate(
                certificate_pem, backend=default_backend()
            )

            issuer_cn = None
            subject_cn = None
            for attr in certificate.issuer:
                if attr.oid == NameOID.COMMON_NAME:
                    issuer_cn = attr.value
                    break

            for attr in certificate.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    subject_cn = attr.value
                    break

            self_signed = issuer_cn == subject_cn
            authorized_issuer = False
            expired = False
            issuer_info = None

            now = datetime.datetime.now(datetime.timezone.utc)
            if (
                now < certificate.not_valid_before_utc
                or now > certificate.not_valid_after_utc
            ):
                expired = True

            if issuer_cn in authorized_issuers:
                issuer_public_key_pem = authorized_issuers.get(issuer_cn)
                if issuer_public_key_pem:
                    try:
                        issuer_public_key = serialization.load_pem_public_key(
                            issuer_public_key_pem, backend=default_backend()
                        )
                        issuer_public_key.verify(
                            certificate.signature,
                            certificate.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            certificate.signature_hash_algorithm,
                        )
                        authorized_issuer = True
                        issuer_info = {
                            "Common Name": issuer_cn,
                            "Public Key PEM": issuer_public_key_pem,
                        }
                    except:
                        authorized_issuer = False
            else:
                authorized_issuer = False

            is_valid = all(
                [
                    not expired,
                    authorized_issuer,
                ]
            )

            return x509info(
                version=certificate.version.value,
                serial_number=certificate.serial_number,
                subject=subject_cn,
                subject_pubkey=certificate.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
                issuer=issuer_cn,
                not_valid_before=certificate.not_valid_before,
                not_valid_after=certificate.not_valid_after,
                signature_algorithm=certificate.signature_algorithm_oid._name,
                extensions=certificate.extensions,
                is_valid=is_valid,
                expired=expired,
                self_signed=self_signed,
                issuer_info=issuer_info if not self_signed else None,
                authorized_issuer=authorized_issuer,
                current_ca=authorized_issuers,
            )

        except Exception as e:
            raise CertificateValidationError(
                f"x509 certificate verification failed : {e}"
            )


def get_key_id(
    public_key_pem: bytes = None,
    private_key_pem: bytes = None,
    password: Optional[str] = None,
) -> str:
    """
    Computes a unique key ID based on the public key.

    :param public_key_pem: The public key in PEM format.
    :param private_key_pem: The private key in PEM format.
    :param password: The password for the private key.
    :return: The key ID as a string.
    :raises ValueError: If neither public_key_pem nor private_key_pem are provided.
    """
    try:
        if public_key_pem:
            public_key = serialization.load_pem_public_key(
                public_key_pem, backend=default_backend()
            )
            public_key_der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return hashlib.shake_256(public_key_der).hexdigest(16)
        elif private_key_pem:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=password.encode() if password else None,
                backend=default_backend(),
            )
            public_key_der = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return hashlib.shake_256(public_key_der).hexdigest(16)
        else:
            raise MissingArgumentError(
                "Missing arguments: either public_key_pem or private_key_pem must be provided."
            )
    except Exception as e:
        raise KeyIDComputingError(f"error: {e}")
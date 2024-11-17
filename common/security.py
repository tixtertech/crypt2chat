import base64
import os
from typing import Callable

import msgpack
import pyotp
from argon2 import PasswordHasher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey

from common.custom_cryptography import CustomRSA


class OneTimePassword:
    def __init__(
            self,
            secret: str = None
    ):
        self.totp = pyotp.TOTP(secret or pyotp.random_base32())

    @property
    def secret(self):
        return self.totp.secret

    @property
    def opt_code(self):
        return self.totp.now()

    def verify(
            self,
            otp_code:str,
    ):
        return self.totp.verify(otp_code)

class RSAChallenge:
    class UnauthorizedError(ValueError):
        pass

    class BadRequestError(ValueError):
        pass

    def __init__(self):
        self.challenges = {}

    def get_challenge(self, pubkey:bytes, function:Callable, args:list, kwargs:dict):
        challenge = os.urandom(16)
        self.challenges[challenge] = {"pubkey": pubkey, "function": function, "args": args, "kwargs": kwargs}
        return base64.b64encode(challenge).decode()

    def compute_challenge(self, challenge:str, privkey:bytes, password:str = None):
        return base64.b64encode(CustomRSA.sign(privkey, base64.b64decode(challenge.encode()), password=password)).decode()

    def verify_challenge(self, challenge:str, signed_challenge:str):
        try:
            challenge = base64.b64decode(challenge.encode())
            signed_challenge = base64.b64decode(signed_challenge.encode())

            infos_challenge = self.challenges.pop(challenge)
        except:
            raise self.BadRequestError

        if CustomRSA.verify(infos_challenge["pubkey"], challenge, signed_challenge):
            return infos_challenge["function"](*infos_challenge["args"], **infos_challenge["kwargs"])
        else:
            raise self.UnauthorizedError

class CryptoCurveChallenge:
    class UnauthorizedError(ValueError):
        pass

    class BadRequestError(ValueError):
        pass

    def __init__(self):
        self.challenges = {}

    def get_challenge(self, authentication_key:bytes, identity_key:bytes, function:Callable, args:list, kwargs:dict):
        authentication_key = serialization.load_pem_public_key(
            authentication_key,
            backend=default_backend()
        )
        identity_key = serialization.load_pem_public_key(
            identity_key,
            backend=default_backend()
        )

        temporary_key = X448PrivateKey.generate()
        pem_temporary_key = temporary_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        shared_secret = temporary_key.exchange(identity_key)
        challenge = msgpack.dumps((os.urandom(16), pem_temporary_key,))

        self.challenges[challenge] = {
            "authentication_key": authentication_key,
            "identity_key": identity_key,
            "shared_secret": shared_secret,
            "function": function,
            "args": args,
            "kwargs": kwargs
        }
        return challenge

    def compute_challenge(self, challenge:bytes, authentication_key:bytes, identity_key:bytes, password:bytes = None):
        challenge, temporary_key = msgpack.loads(challenge)
        authentication_key = serialization.load_pem_private_key(
            authentication_key,
            password=password,
            backend=default_backend()
        )
        identity_key = serialization.load_pem_private_key(
            identity_key,
            password=password,
            backend=default_backend()
        )
        temporary_key = serialization.load_pem_public_key(
            temporary_key,
            backend=default_backend()
        )
        signature = authentication_key.sign(challenge)
        shared_secret = identity_key.exchange(temporary_key)
        return msgpack.dumps((signature, shared_secret,))

    def verify_challenge(self, challenge: bytes, authenticated_challenge: bytes):
        try:
            challenge, _ = msgpack.loads(challenge)
            signature, shared_secret = msgpack.loads(authenticated_challenge)

            infos_challenge = self.challenges.pop(challenge)
        except:
            raise self.BadRequestError

        try:
            infos_challenge["authentication_key"].verify(signature, challenge)
        except:
            raise self.UnauthorizedError

        if infos_challenge["shared_secret"] != shared_secret:
            raise self.UnauthorizedError

        return infos_challenge["function"](*infos_challenge["args"], **infos_challenge["kwargs"])

class TokenManager:
    @staticmethod
    def new_session_key():
        return base64.urlsafe_b64encode(os.urandom(16)).decode()

    @staticmethod
    def encrypt_session_key(
           session_key: str,
           session_id: str,
           recipient_pubkey: bytes,
    ):
        return base64.urlsafe_b64encode(CustomRSA.encrypt(recipient_pubkey, msgpack.dumps(
            {"session_id": session_id, "session_key": session_key}))).decode()

    @staticmethod
    def decrypt_session_key(
            encrypted_session_key: str,
            private_key: bytes,
            password: str = None
    ):
        return msgpack.loads(
            CustomRSA.decrypt(private_key, base64.urlsafe_b64decode(encrypted_session_key.encode()), password))

    @staticmethod
    def compute_token(
            session_key: str,
            session_id: str
    ):
        derived_token = PasswordHasher().hash(session_key)
        return f"{session_id}.{derived_token}"

    @staticmethod
    def verify_token(
            token: str,
            replay_attack_detection: Callable[[str], None],
            get_session_key: Callable[[str], str]
    ) -> bool:
        try:
            replay_attack_detection(token)
            session_id, hashed_session_key = token.split(".")
            session_key = get_session_key(session_id)
            if PasswordHasher().verify(hashed_session_key, session_key):
                return True
            return False
        except:
            return False
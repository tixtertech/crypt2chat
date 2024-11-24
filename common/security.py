import base64
import hashlib
import json
import time
import traceback
from datetime import datetime, timezone, timedelta
import os
import uuid
from typing import Callable

import msgpack
import pyotp
from argon2 import PasswordHasher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

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
    class AccessForbiddenError(ValueError):
        pass

    class BadRequestError(ValueError):
        pass

    def __init__(self):
        self.challenges = {}

    def get_challenge(self, pubkey:bytes, function:Callable, args:list, kwargs:dict) -> str:
        challenge = os.urandom(16)
        self.challenges[challenge] = {"pubkey": pubkey, "function": function, "args": args, "kwargs": kwargs}
        return base64.b64encode(challenge).decode()

    def compute_challenge(self, challenge:str, privkey:bytes, password:str = None) -> str:
        decoded_challenge = base64.b64decode(challenge.encode())
        signature = CustomRSA.sign(privkey, decoded_challenge, password=password)
        return base64.b64encode(signature).decode()

    def verify_challenge(self, authenticated_challenge: str):
        try:
            challenge, signature = msgpack.loads(base64.b64decode(authenticated_challenge.encode()))
        except:
            raise self.BadRequestError("RSA Challenge: base64 decoding or msgpack loading failed")

        try:
            infos_challenge = self.challenges.pop(challenge)
        except:
            raise self.BadRequestError("RSA Challenge: challenge not found")

        if CustomRSA.verify(infos_challenge["pubkey"], challenge, signature):
            return infos_challenge["function"](*infos_challenge["args"], **infos_challenge["kwargs"])
        else:
            raise self.AccessForbiddenError("RSA Challenge: invalid digital signature")

class ECEChallenge:
    class AccessForbiddenError(ValueError):
        pass

    class BadRequestError(ValueError):
        pass

    def __init__(self):
        self.challenges = {}

    def get_challenge(self, authentication_key:bytes, identity_key:bytes, function:Callable, args:list, kwargs:dict) -> str:
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

        challenge = os.urandom(16)
        packed_challenge = msgpack.dumps((challenge, pem_temporary_key,))

        self.challenges[challenge] = {
            "authentication_key": authentication_key,
            "identity_key": identity_key,
            "shared_secret": shared_secret,
            "function": function,
            "args": args,
            "kwargs": kwargs
        }
        return base64.b64encode(packed_challenge).decode()

    def compute_challenge(self, challenge:str, authentication_key:bytes, identity_key:bytes, password:bytes = None) -> str:
        challenge, temporary_key = msgpack.loads(base64.b64decode(challenge.encode()))
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
        return base64.b64encode(msgpack.dumps((challenge, signature, shared_secret,))).decode()

    def verify_challenge(self, authenticated_challenge: str):
        try:
            challenge, signature, shared_secret = msgpack.loads(base64.b64decode(authenticated_challenge.encode()))
        except:
            raise self.BadRequestError("ECE Challenge: base64 decoding or msgpack loading failed")

        try:
            infos_challenge = self.challenges.pop(challenge)
        except:
            raise self.BadRequestError("ECE Challenge: challenge not found")

        try:
            infos_challenge["authentication_key"].verify(signature, challenge)
        except:
            raise self.AccessForbiddenError("ECE Challenge: invalid digital signature")

        if infos_challenge["shared_secret"] != shared_secret:
            raise self.AccessForbiddenError("ECE Challenge: shared secrets do not match")

        return infos_challenge["function"](*infos_challenge["args"], **infos_challenge["kwargs"])

class APIToken:
    class APITokenError(ValueError):
        pass

    class InvalidSharedKeyError(APITokenError):
        pass

    class InvalidSignatureError(APITokenError):
        pass

    class InvalidMethodError(APITokenError):
        pass

    class InvalidURLError(APITokenError):
        pass

    class InvalidBodyHashError(APITokenError):
        pass

    class NotValidBeforeError(APITokenError):
        pass

    class ExpiredError(APITokenError):
        pass

    class FormatError(APITokenError):
        pass

    class MissingKeysError(APITokenError):
        pass

    def __init__(self, user_id=None, user_ik=None, user_ak=None, server_ik_prv=None, server_ik_pub=None, password:bytes=None):
        self.user_id = user_id
        self.user_ik: X448PrivateKey = serialization.load_pem_private_key(user_ik, password=password, backend=default_backend()) if user_ik else None
        self.user_ak: Ed448PrivateKey = serialization.load_pem_private_key(user_ak, password=password, backend=default_backend()) if user_ak else None
        self.server_ik_prv: X448PrivateKey = serialization.load_pem_private_key(server_ik_prv, password=password, backend=default_backend()) if server_ik_prv else None
        self.server_ik_pub: X448PublicKey = serialization.load_pem_public_key(server_ik_pub, backend=default_backend()) if server_ik_pub else None

    def get_token(
            self,
            method:str,
            url:str,
            body:bytes,
            lifetime:int=60
    ):
        if not all([self.user_id, self.user_ik, self.user_ak, self.server_ik_pub]):
            raise self.MissingKeysError
        now = time.time()
        payload = base64.b64encode(json.dumps({
            "id": uuid.uuid4().hex,
            "sub": self.user_id,
            "method": method.upper(),
            "url": url,
            "body_hash": hashlib.sha256(body).hexdigest(),
            "nbf": now,
            "exp": now + lifetime,
        }).encode()).decode()
        shared_key = base64.b64encode(self.user_ik.exchange(self.server_ik_pub)).decode()
        hashed_shared_key = PasswordHasher().hash(payload + shared_key)
        ed448_signature = base64.b64encode(self.user_ak.sign(payload.encode())).decode()
        return f"{payload}.{hashed_shared_key}.{ed448_signature}"

    def verify_token(
            self,
            token:str,
            user_infos:Callable[[str], dict],
            method: str,
            url: str,
            body: bytes
    ):
        if not self.server_ik_prv:
            raise self.MissingKeysError

        try:
            payload, hashed_shared_key, ed448_signature = token.split(".")
            payload_dict = json.loads(base64.b64decode(payload))
        except:
            raise self.FormatError

        user_infos = user_infos(payload_dict.get("sub"))

        try:
            user_ik: X448PublicKey = serialization.load_pem_public_key(user_infos.get("identity_key"), backend=default_backend())
            user_ak: Ed448PublicKey = serialization.load_pem_public_key(user_infos.get("authentication_key"), backend=default_backend())
            decoded_ed448_signature = base64.b64decode(ed448_signature.encode())
            shared_key = base64.b64encode(self.server_ik_prv.exchange(user_ik)).decode()
        except:
            raise self.FormatError

        try:
            user_ak.verify(decoded_ed448_signature, payload.encode())
        except:
            raise self.InvalidSignatureError

        try:
            PasswordHasher().verify(hashed_shared_key, payload + shared_key)
        except:
            raise self.InvalidSharedKeyError

        if payload_dict.get("method") != method:
            raise self.InvalidMethodError

        if payload_dict.get("url") != url:
            raise self.InvalidURLError

        if payload_dict.get("body_hash") != hashlib.sha256(body).hexdigest():
            raise self.InvalidBodyHashError

        now = time.time()

        if payload_dict.get("nbf") > now:
            raise self.NotValidBeforeError

        if payload_dict.get("exp") < now:
            raise self.ExpiredError

        return payload_dict

import os
import sqlite3
from datetime import datetime, timezone
from typing import Callable

from fastapi import Response

from common.decorators import anti_code_injection
from common.security import APIToken, RSAChallenge, ECEChallenge
from server.exceptions import *
from server.users import UsersManager

users_manager = UsersManager(os.getenv("SERVER_USERS_DB"))

class UserChallenge(ECEChallenge):
    def get_challenge(self, authentication_key:bytes, identity_key:bytes, function:Callable, args:list, kwargs:dict):
        challenge = super().get_challenge(
                authentication_key=authentication_key,
                identity_key=identity_key,
                function=function,
                args=args,
                kwargs=kwargs
            )
        return Response(
            content=challenge,
            status_code=401,
            media_type="application/json",
            headers={
                "WWW-Authenticate": "user-challenge",
            }
        )

class AdminChallenge(RSAChallenge):
    def get_challenge(self, pubkey:bytes, function:Callable, args:list, kwargs:dict):
        challenge = super().get_challenge(
            pubkey=pubkey,
            function=function,
            args=args,
            kwargs=kwargs
        )
        return Response(
            content=challenge,
            status_code=401,
            media_type="application/json",
            headers={
                "WWW-Authenticate": "admin-challenge",
            }
        )


class TokenManager:

    def __init__(self, db_path: str):
        self.db_path = db_path
        with open(os.getenv("SERVER_X448_PRV"), "rb") as f:
            self.server_privkey = f.read()
        self.api_token = APIToken(
            server_ik_prv=self.server_privkey,
            password=None,
        )
        self._init_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS tokens (
                        id TEXT PRIMARY KEY,
                        sub TEXT,
                        exp DATETIME,
                        nbf DATETIME,
                        method TEXT,
                        url TEXT,
                        body_hash TEXT,
                        timestamp DATETIME
                    )
                ''')
                conn.commit()
        except sqlite3.Error as e:
            raise DataBaseError(f"Database initialization failed: {e}")

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def _store_token_metadata(
            self,
            id: str,
            sub: str,
            exp: datetime,
            nbf: datetime,
            method: str,
            url: str,
            body_hash: str
    ):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                        INSERT OR REPLACE INTO tokens (id, sub, exp, nbf, method, url, body_hash, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (id, sub, exp, nbf, method, url, body_hash, datetime.now(timezone.utc)))
                conn.commit()
        except sqlite3.Error as e:
            raise DataBaseError(f"Failed to store token metadata: {e}")

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def replay_attack(self, id: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT EXISTS(SELECT 1 FROM tokens WHERE id = ?)''', (id,))
            conn.commit()
            return bool(cursor.fetchone()[0])

    def verify_token(self, token: str, method: str, url: str, body: bytes):
        payload = self.api_token.verify_token(
            token=token,
            user_infos=lambda id: users_manager.get_details(user_id=id),
            method=method,
            url=url,
            body=body
        )
        if self.replay_attack(payload.get('id')):
            raise ReplayAttackError
        self._store_token_metadata(**payload)
        return payload


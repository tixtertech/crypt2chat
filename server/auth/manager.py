import base64
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable, Union

from fastapi.responses import JSONResponse
from jose import jwt

from common.decorators import anti_code_injection
from common.security import RSAChallenge, CryptoCurveChallenge
from server.exceptions import *


class UserChallenge(CryptoCurveChallenge):
    def get_challenge(self, authentication_key:bytes, identity_key:bytes, function:Callable, args:list, kwargs:dict):
        return JSONResponse(
            content=super().get_challenge(
                authentication_key=authentication_key,
                identity_key=identity_key,
                function=function,
                args=args,
                kwargs=kwargs
            ),
            headers={
                "WWW-Authenticate": "user-challenge",
            }
        )

class AdminChallenge(RSAChallenge):
    def get_challenge(self, pubkey:bytes, function:Callable, args:list, kwargs:dict):
        return JSONResponse(
            content=super().get_challenge(
                pubkey=pubkey,
                function=function,
                args=args,
                kwargs=kwargs
            ),
            headers={
                "WWW-Authenticate": "admin-challenge",
            }
        )

user_challenge = UserChallenge()
admin_challenge = AdminChallenge()


class TokenManager:

    def __init__(self, db_path: str, alg: str = "HS256", typ: str = "JWT"):
        """
        Initialize the TokenManager with a secret key, algorithm, and database path.

        :param db_path: The path to the SQLite database for storing token metadata.
        :param alg: The algorithm used for JWT signing, default is 'HS256'.
        :param typ: The type of the token (default is "JWT").
        """
        self.db_path = db_path
        self.alg = alg
        self.typ = typ
        self._init_db()

    def _init_db(self):
        """
        Initialize the SQLite database to store token metadata.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS tokens (
                        iss TEXT,
                        sub TEXT,
                        aud TEXT,
                        exp DATETIME,
                        nbf DATETIME,
                        iat DATETIME,
                        jti TEXT PRIMARY KEY
                    )
                ''')
                conn.commit()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS blacklist (
                        jti TEXT PRIMARY KEY
                    )
                ''')
                conn.commit()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key TEXT NOT NULL,
                        timestamp DATETIME NOT NULL
                    )
                ''')
                conn.commit()
        except sqlite3.Error as e:
            raise DataBaseError(f"Database initialization failed: {e}")

    def update_key(self):
        new_key = base64.b64encode(os.urandom(16)).decode()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO keys (key, timestamp) VALUES (?, ?)
            ''', (new_key, datetime.now(timezone.utc)))

            conn.execute('''
                DELETE FROM keys WHERE id NOT IN (
                    SELECT id FROM keys ORDER BY timestamp DESC LIMIT 2
                )
            ''')
            conn.commit()

    @property
    def secret_key(self):
        with sqlite3.connect(self.db_path) as conn:
            key = conn.execute('''
               SELECT key, timestamp FROM keys ORDER BY timestamp DESC LIMIT 1
           ''').fetchone()
            if key is None or (datetime.now(timezone.utc) - datetime.fromisoformat(key[1])) > timedelta(minutes=30):
                self.update_key()

        return key[0] if key else None

    @property
    def last_key(self):
        with sqlite3.connect(self.db_path) as conn:
            last_key = conn.execute('''
               SELECT key FROM keys ORDER BY timestamp DESC LIMIT 1 OFFSET 1
           ''').fetchone()
        return last_key[0] if last_key else None

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def _store_token_metadata(
            self,
            iss: Optional[str],
            sub: str,
            aud: Optional[str],
            exp: datetime,
            nbf: Optional[datetime],
            iat: datetime,
            jti: str
    ):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                        INSERT OR REPLACE INTO tokens (iss, sub, aud, exp, nbf, iat, jti)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (iss, sub, aud, exp, nbf, iat, jti))
                conn.commit()
        except sqlite3.Error as e:
            raise DataBaseError(f"Failed to store token metadata: {e}")

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def is_blacklisted(self, jti: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT EXISTS(SELECT 1 FROM blacklist WHERE jti = ?)''', (jti,))
            conn.commit()
            return bool(cursor.fetchone()[0])

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def get_token_metadata(self, jti: str) -> Optional[Dict[str, Union[str, datetime]]]:
        """
        Retrieve the token metadata associated with a specific JWT ID (jti) from the database.

        :param jti: The unique identifier of the token whose metadata is to be retrieved.
        :return: A dictionary containing token metadata.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT iss, sub, aud, exp, nbf, iat, jti
                    FROM tokens
                    WHERE jti = ?
                ''', (jti,))
                result = cursor.fetchone()

                if result:
                    return {
                        "iss": result[0],
                        "sub": result[1],
                        "aud": result[2],
                        "exp": result[3],
                        "nbf": result[4],
                        "iat": result[5],
                        "jti": result[6]
                    }
        except sqlite3.Error as e:
            raise DataBaseError(f"Failed to retrieve token metadata: {e}")


    def new_token(
            self,
            subject: str,
            issuer: Optional[str] = None,
            audience: Optional[str] = None,
            expires_delta: Optional[timedelta] = None,
            not_before: Optional[timedelta] = None,
            jti: Optional[str] = None,
    ) -> str:
        """
        Create a JWT access token with specified metadata and store token metadata in the database.

        :param subject: The subject of the token (usually user ID).
        :param issuer: The issuer of the token.
        :param audience: The intended audience for the token.
        :param expires_delta: The duration for which the token is valid.
        :param not_before: The time before which the token is not valid.
        :param jti: The unique identifier for the token.
        :return: Encoded JWT token.
        """
        if jti is None:
            jti = str(uuid.uuid4())  # Generate a unique identifier if not provided

        nbf = None
        to_encode = {
            "sub": subject,
            "jti": jti,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
        }

        if not_before:
            nbf = datetime.now(timezone.utc) + not_before
            to_encode["nbf"] = nbf
        if issuer:
            to_encode["iss"] = issuer
        if audience:
            to_encode["aud"] = audience

        encoded_jwt = jwt.encode(claims=to_encode, key=self.secret_key, algorithm=self.alg)

        # Store token metadata in the database
        self._store_token_metadata(
            issuer,
            subject,
            audience,
            to_encode["exp"],
            nbf,
            to_encode["iat"],
            jti
        )

        return encoded_jwt

    @anti_code_injection(in_case_raise=ValueError("sql_injection_suspicion"))
    def revoke_token(self, jti: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM tokens WHERE jti = ?
                ''', (jti,))
                rows_affected = cursor.rowcount
                conn.commit()
                return rows_affected > 0
        except sqlite3.Error as e:
            raise DataBaseError(f"Failed to revoke token: {e}")


    def verify_token(self, token: str) -> Optional[Dict[str, Union[str, datetime]]]:
        payload = jwt.decode(token, self.secret_key, algorithms=[self.alg])
        if self.is_blacklisted(payload["jti"]):
            raise BlacklistedTokenError
        return payload
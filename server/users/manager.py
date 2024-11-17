import sqlite3
import uuid
from datetime import datetime, timezone
from typing import List, Tuple

import msgpack

from common.decorators import anti_code_injection
from server.exceptions import *


class UsersManager:
    def __init__(self, db_path:str):
        self.db_path = db_path
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT,
                authentication_key BLOB,
                identity_key BLOB,
                identity_sig BLOB,
                signed_pre_keys BLOB,
                since DATETIME,
                frozen BOOL
            )
        ''')
        conn.commit()
        conn.close()

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def is_user_id_taken(self, user_id:str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT EXISTS (SELECT 1 FROM users WHERE user_id = ?)', (user_id,))
            result = cursor.fetchone()
        return result[0] == 1

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def is_username_taken(self, username:str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT EXISTS (SELECT 1 FROM users WHERE username = ?)', (username,))
            result = cursor.fetchone()
        return result[0] == 1

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def is_keys_taken(self, authentication_key:bytes, identity_key:bytes):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT EXISTS (SELECT 1 FROM users WHERE authentication_key = ? OR identity_key = ?)', (authentication_key, identity_key,))
            result = cursor.fetchone()
        return result[0] == 1

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def is_account_frozen(self, user_id:str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT frozen FROM users WHERE user_id= ?',
                           (user_id,))
            result = cursor.fetchone()
        return result[0] == 1


    @anti_code_injection(in_case_raise=CodeInjectionError)
    def register(self, username:str, authentication_key:bytes, identity_key:bytes, identity_sig:bytes, override:bool=False):
        if self.is_username_taken(username) or override:
            raise AlreadyTakenError("username already taken")
        if self.is_keys_taken(identity_key, authentication_key) or override:
            raise AlreadyTakenError("authentication or identity key already taken")

        user_id = uuid.uuid4().__str__()
        while self.is_user_id_taken(user_id):
            user_id = uuid.uuid4().__str__()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO users (user_id, username, authentication_key, identity_key, identity_sig, signed_pre_keys, since, frozen) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, username, authentication_key, identity_key, identity_sig, datetime.now(timezone.utc), False))
            conn.commit()
        return f"{username} registered"

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def change_username(self, user_id:str, username:str):
        if self.is_account_frozen(user_id):
            raise FrozenAccountError("This account has been frozen. Please contact support.")
        if not self.is_user_id_taken(user_id):
            raise NotFoundError(f"user {user_id} not found")
        if self.is_username_taken(username):
            raise AlreadyTakenError("username already taken")

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET username = ? WHERE user_id = ?', (username,user_id,))
            conn.commit()

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def renew_signed_pre_keys(self, user_id:str, signed_pre_keys:bytes):
        if self.is_account_frozen(user_id):
            raise FrozenAccountError("This account has been frozen. Please contact support.")
        if not self.is_user_id_taken(user_id):
            raise NotFoundError(f"user {user_id} not found")

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET signed_pre_keys = ? WHERE user_id = ?', (user_id,signed_pre_keys,))
            conn.commit()

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def get_signed_pre_key(self, user_id:str):
        if self.is_account_frozen(user_id):
            raise FrozenAccountError("This account has been frozen.")
        if not self.is_user_id_taken(user_id):
            raise NotFoundError(f"user {user_id} not found")

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT signed_pre_keys FROM users WHERE user_id = ?', (user_id,))
            signed_pre_keys = cursor.fetchone()[0]

        data = msgpack.loads(signed_pre_keys)
        now = datetime.now(timezone.utc)
        data.reverse()
        for key, signature, nvb, nva in data:
            if datetime.fromisoformat(nvb).replace(tzinfo=timezone.utc) <= now <= datetime.fromisoformat(
                    nva).replace(tzinfo=timezone.utc):
                return key, signature

        raise ValueError(f"user {user_id} have not signed_pre_keys anymore...")

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def delete_account(self, user_id:str):
        if self.is_account_frozen(user_id):
            raise FrozenAccountError("This account has been frozen. Please contact support.")
        if not self.is_user_id_taken(user_id):
            raise NotFoundError(f"user {user_id} not found")

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM users WHERE user_id = ?
            ''', (user_id,))

            conn.commit()

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def get_details(self, user_id:str=None, username:str=None):
        if not (user_id or username):
            raise Crypt2chatError("Unspecified user_id or username")
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if user_id:
                cursor.execute('SELECT username, authentication_key, identity_key, identity_sig, since FROM users WHERE user_id = ?', (user_id,))
                result = cursor.fetchone()
                if result is None:
                    raise NotFoundError
                username, authentication_key, identity_key, identity_sig, since = result

            elif username:
                cursor.execute('SELECT user_id, authentication_key, identity_key, identity_sig, since FROM users WHERE username = ?', (username,))
                result = cursor.fetchone()
                if result is None:
                    raise NotFoundError
                user_id, authentication_key, identity_key, identity_sig, since = result

            return {
                "user_id": user_id,
                "username": username,
                "authentication_key": authentication_key,
                "identity_key": identity_key,
                "identity_sig": identity_sig,
                "since":since,
            }

    @anti_code_injection()
    def fetch_db(self, search: Optional[str] = None, since: Optional[datetime] = None,
                 limit: Optional[int] = None) -> List[Tuple[str, bytes, bytes, datetime]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            query = """
                SELECT *
                FROM users
                WHERE 1=1
                """

            params = []

            if search:
                query += " AND username LIKE ?"
                params.append(f'%{search}%')

            if since:
                query += " AND since >= ?"
                params.append(since.isoformat())

            if limit is not None:
                query += " LIMIT ?"
                params.append(limit)

            cursor.execute(query, params)
            results = cursor.fetchall()

            return results

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def freeze_account(self, user_id:str):
        if not self.is_user_id_taken(user_id):
            raise NotFoundError(f"user {user_id} not found")

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET frozen = ? WHERE user_id = ?
            ''', (True, user_id,))

            conn.commit()

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def unfreeze_account(self, user_id:str):
        if not self.is_user_id_taken(user_id):
            raise NotFoundError(f"user {user_id} not found")

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET frozen = ? WHERE user_id = ?
            ''', (False, user_id,))

            conn.commit()
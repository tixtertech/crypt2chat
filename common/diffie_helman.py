import base64
import os
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta

import msgpack
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common.custom_cryptography import CustomAESGCM


class DiffieHelman:
    def __init__(self, password: bytes, db_path: str):
        self.db_path = db_path
        self.password = password
        self.init_db()

        self.backend = default_backend()
        self.ensure_master_keys()

        self.remove_old_signed_pre_keys()
        self.renew_signed_pre_keys()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ed448_authentication_key (
                    key BLOB,
                    type TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS x448_identity_key (
                    key BLOB,
                    type TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS x448_signed_pre_keys (
                    id INTEGER,
                    key BLOB,
                    type TEXT,
                    nvb DATETIME,
                    nva DATETIME
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS serial_numbers (
                    serial_number TEXT UNIQUE,
                    sending_date DATETIME,
                    receiving_date DATETIME
                )
            ''')
            conn.commit()

    def authentication_key_prv(self, pem=False):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT key FROM ed448_authentication_key WHERE type = ?", ("PRIVATE",))
            privkey_pem = cursor.fetchone()[0]

        if pem:
            return privkey_pem
        else:
            return serialization.load_pem_private_key(
                privkey_pem,
                backend=self.backend,
                password=self.password,
            )

    def authentication_key_pub(self, pem=True):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT key FROM ed448_authentication_key WHERE type = ?", ("PUBLIC",))
            pubkey_pem = cursor.fetchone()[0]

        if pem:
            return pubkey_pem
        else:
            return serialization.load_pem_public_key(
                pubkey_pem,
                backend=self.backend,
            )

    def _new_authentication_key(self):
        privkey = Ed448PrivateKey.generate()
        pubkey = privkey.public_key()

        privkey_pem = privkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=(serialization.BestAvailableEncryption(self.password)),
        )
        pubkey_pem = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM ed448_authentication_key")
            cursor.executemany("INSERT INTO ed448_authentication_key (key, type) VALUES (?, ?)", ([
                (privkey_pem, "PRIVATE"),
                (pubkey_pem, "PUBLIC")
            ]))
            conn.commit()


    def identity_key_prv(self, pem=False):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT key FROM x448_identity_key WHERE type = ?", ("PRIVATE",))
            privkey_pem = cursor.fetchone()[0]

        if pem:
            return privkey_pem
        else:
            return serialization.load_pem_private_key(
                privkey_pem,
                backend=self.backend,
                password=self.password,
            )

    def identity_key_pub(self, pem=True):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT key FROM x448_identity_key WHERE type = ?", ("PUBLIC",))
            pubkey_pem = cursor.fetchone()[0]

        if pem:
            return pubkey_pem
        else:
            return serialization.load_pem_public_key(
                pubkey_pem,
                backend=self.backend,
            )

    def identity_key_sig(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT key FROM x448_identity_key WHERE type = ?", ("SIGNATURE",))
            signature = cursor.fetchone()[0]

        return signature

    def _new_identity_key(self):
        privkey = X448PrivateKey.generate()
        pubkey = privkey.public_key()

        privkey_pem = privkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=(serialization.BestAvailableEncryption(self.password)),
        )
        pubkey_pem = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        signature = base64.b64encode(self.authentication_key_prv().sign(pubkey_pem))
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM x448_identity_key")
            cursor.executemany("INSERT INTO x448_identity_key (key, type) VALUES (?, ?)", ([
                (privkey_pem, "PRIVATE"),
                (pubkey_pem, "PUBLIC"),
                (signature, "SIGNATURE")
            ]))
            conn.commit()

    def ensure_master_keys(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT key, type FROM ed448_authentication_key")
            authentication_key = cursor.fetchone()

        if authentication_key is None or len(authentication_key) != 2:
            self._new_authentication_key()
            self._new_identity_key()
        else:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT key, type FROM x448_identity_key")
                identity_key = cursor.fetchone()
            if identity_key is None or len(identity_key) != 3:
                self._new_identity_key()

    def signed_pre_keys_pub(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT id, key, type, nvb, nva FROM x448_signed_pre_keys WHERE type IN (?, ?)", ("PUBLIC", "SIGNATURE"))
            rows = cursor.fetchall()

        public_keys = {}
        signatures = {}

        for row in rows:
            id_, key, type_, nvb, nva = row
            if type_ == "PUBLIC":
                public_keys[id_] = (key, nvb, nva)
            elif type_ == "SIGNATURE":
                signatures[id_] = (key, nvb, nva)

        keys = []
        for id_ in sorted(public_keys.keys()):
            if id_ in signatures:
                pub_key, nvb, nva = public_keys[id_]
                sig_key, _, _ = signatures[id_]
                keys.append((pub_key, sig_key, nvb, nva))

        return msgpack.dumps(keys)

    def signed_pre_key_prv(self, timestamp: datetime):
        """Retrieve the private key corresponding to the specified timestamp."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT id, nvb, nva FROM x448_signed_pre_keys WHERE type = ? ORDER BY id", ("PRIVATE",))
            data = cursor.fetchall()
            data.reverse()
            for id, nvb, nva in data:
                if datetime.fromisoformat(nvb).replace(tzinfo=timezone.utc) <= timestamp <= datetime.fromisoformat(
                        nva).replace(tzinfo=timezone.utc):

                        cursor.execute("SELECT key FROM x448_signed_pre_keys WHERE id = ? AND type = ?",
                                       (id,"PRIVATE",))
                        result = cursor.fetchone()

                        if result is not None:
                            return result[0]

            raise ValueError("No private key found for the given timestamp.")

    def _new_signed_pre_key(self):
        privkey = X448PrivateKey.generate()
        pubkey = privkey.public_key()

        privkey_pem = privkey.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=(serialization.BestAvailableEncryption(self.password)),
                )
        pubkey_pem = pubkey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        signature = self.authentication_key_prv().sign(pubkey_pem)
        return privkey_pem, pubkey_pem, signature

    def remove_old_signed_pre_keys(self):
        """Delete keys that have expired for more than 10 days."""
        threshold_date = datetime.now(timezone.utc) - timedelta(days=10)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute(f"DELETE FROM x448_signed_pre_keys WHERE nvb < ?", (threshold_date,))

            conn.commit()

    def renew_signed_pre_keys(self):
        now = datetime.now(timezone.utc)
        last_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
        if now < last_midnight:
            last_midnight -= timedelta(days=1)


        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, nvb FROM x448_signed_pre_keys ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                id, last_nvb = row[0], datetime.fromisoformat(row[1])
            else:
                id, last_nvb = 0, last_midnight

            if last_nvb < now + timedelta(days=30):
                while last_nvb < now + timedelta(days=50):

                    privkey, pubkey, signature = self._new_signed_pre_key()
                    id += 1
                    nvb = last_nvb + timedelta(days=1)
                    nva = nvb + timedelta(days=1)
                    cursor.execute('INSERT INTO x448_signed_pre_keys (id, key, type, nvb, nva) VALUES (?, ?, ?, ?, ?)',
                                   (id, privkey,"PRIVATE", nvb, nva))
                    cursor.execute('INSERT INTO x448_signed_pre_keys (id, key, type, nvb, nva) VALUES (?, ?, ?, ?, ?)',
                                   (id, pubkey, "PUBLIC", nvb, nva))
                    cursor.execute('INSERT INTO x448_signed_pre_keys (id, key, type, nvb, nva) VALUES (?, ?, ?, ?, ?)',
                                   (id, signature, "SIGNATURE", nvb, nva))
                    conn.commit()
                    last_nvb = nvb


    def a_shared_secret(self, ik_a_prv: X448PrivateKey, spk_b_pub: X448PublicKey, ek_a_prv: X448PrivateKey, ik_b_pub: X448PublicKey):
        dh1 = ik_a_prv.exchange(spk_b_pub)
        dh2 = ek_a_prv.exchange(ik_b_pub)
        dh3 = ek_a_prv.exchange(spk_b_pub)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"x3dh master secret",
            backend=default_backend()
        )
        return hkdf.derive(dh1 + dh2 + dh3)

    def b_shared_secret(self, ik_a_pub: X448PublicKey, spk_b_prv: X448PrivateKey, ek_a_pub: X448PublicKey, ik_b_prv: X448PrivateKey):
        dh1 = spk_b_prv.exchange(ik_a_pub)
        dh2 = ik_b_prv.exchange(ek_a_pub)
        dh3 = spk_b_prv.exchange(ek_a_pub)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"x3dh master secret",
            backend=default_backend()
        )
        return hkdf.derive(dh1 + dh2 + dh3)


    def send_message(self, message:bytes, recipients_keys: dict) -> bytes:
        e_privkey = X448PrivateKey.generate()

        e_pubkey_pem = e_privkey.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        common_key = os.urandom(32)

        encrypted_common_key = {}
        for ik_pem, spk_pem in recipients_keys.items():
            ik = serialization.load_pem_public_key(
                ik_pem,
                backend=self.backend
            )

            spk = serialization.load_pem_public_key(
                spk_pem,
                backend=self.backend
            )

            shared_secret = self.a_shared_secret(
                ik_a_prv=self.identity_key_prv(),
                spk_b_pub=spk,
                ek_a_prv=e_privkey,
                ik_b_pub=ik,
            )
            encrypted_common_key[ik_pem] = CustomAESGCM.encrypt(shared_secret, common_key)

        encrypted_message = CustomAESGCM.encrypt(common_key, message)

        packed_metadata = msgpack.dumps(
            {
                "serial_number": uuid.uuid4().hex,
                "sending_utc_timestamp": datetime.now(timezone.utc).timestamp(),
                "authentication_key": self.authentication_key_pub,
                "identity_key": self.identity_key_pub,
                "ephemeral_key": e_pubkey_pem,
                "encrypted_common_key": encrypted_common_key,
                "encrypted_message": encrypted_message
            })

        return msgpack.dumps((packed_metadata, self.authentication_key_prv().sign(packed_metadata)))

    def receive_message(self, packed_message: bytes):
        # Unpack the message
        packed_metadata, signature = msgpack.loads(packed_message)
        metadata = msgpack.loads(packed_metadata)
        encrypted_common_key = metadata['encrypted_common_key']
        encrypted_message = metadata['encrypted_message']
        sending_date = datetime.fromtimestamp(metadata["sending_utc_timestamp"], tz=timezone.utc)

        if not self.identity_key_pub in encrypted_common_key:
            raise ValueError("The message is not intended for you")

        if self.serial_number_exists(metadata["serial_number"]):
            raise ValueError('Replay Attack Detected')

        metadata['authentication_key'] = serialization.load_pem_public_key(
            metadata['authentication_key'],
            backend=self.backend
        )

        metadata['identity_key'] = serialization.load_pem_public_key(
            metadata['identity_key'],
            backend=self.backend
        )

        metadata['ephemeral_key'] = serialization.load_pem_public_key(
            metadata['ephemeral_key'],
            backend=self.backend
        )

        spk_b_prv = serialization.load_pem_private_key(
            self.signed_pre_key_prv(sending_date),
            backend=self.backend,
            password=self.password,
        )

        shared_secret = self.b_shared_secret(
            ik_a_pub=metadata['identity_key'],
            spk_b_prv=spk_b_prv,
            ek_a_pub=metadata['ephemeral_key'],
            ik_b_prv=self.identity_key_prv(),
        )
        common_key = CustomAESGCM.decrypt(shared_secret, encrypted_common_key[self.identity_key_pub])

        try:
            metadata["authentication_key"].verify(signature, packed_metadata)
        except:
            raise ValueError('InvalidSignature')

        decrypted_message = CustomAESGCM.decrypt(common_key, encrypted_message)

        self.add_serial_number(metadata["serial_number"], sending_date, datetime.now(timezone.utc))
        return decrypted_message, metadata

    def add_serial_number(self, serial_number: str, sending_date: datetime, receiving_date: datetime):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO serial_numbers (serial_number, sending_date, receiving_date)
                    VALUES (?, ?, ?)
                ''', (serial_number, sending_date, receiving_date))
                conn.commit()
            except sqlite3.IntegrityError:
                raise ValueError("Duplicate serial number detected.")

    def serial_number_exists(self, serial_number: str) -> bool:
        """Check if a serial number exists in the database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 1 FROM serial_numbers WHERE serial_number = ?
            ''', (serial_number,))
            return cursor.fetchone() is not None  # Returns True if exists, False otherwise
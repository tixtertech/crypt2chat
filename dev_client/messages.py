import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Callable
from dev_client.auth import Token, raise_for_status, API_URL, ssl_verification

class Messages:
    def __init__(self, password: bytes, db_path: str):
        self.db_path = db_path
        self.password = password

        with self:
            self.init_db()

    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
            self.conn.close()
            self.conn = None

    def destroy(self):
        self.conn.close()
        os.remove(self.db_path)
        del self

    @property
    def conn_(self):
        """Get the current connection or create a new one if none exists."""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path)
        return self.conn

    def init_db(self):
        cursor = (self.conn_.cursor())
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS conversations (
                conversation_id TEXT PRIMARY KEY,
                name TEXT,
                created_at TIMESTAMPTZ,
                members JSONB
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                message_id TEXT PRIMARY KEY,
                conversation_id TEXT,
                sender TEXT,
                timestamp TIMESTAMPTZ,
                content TEXT
            )
        ''')
        self.conn_.commit()

    def update_conversations(self, conversations_data: Dict[str, Dict[str, Any]]) -> None:
        cursor = self.conn_.cursor()

        try:
            # Start transaction
            cursor.execute('BEGIN TRANSACTION')

            # Get all current conversation IDs
            cursor.execute('SELECT conversation_id FROM conversations')
            existing_ids = set(row[0] for row in cursor.fetchall())

            # New conversation IDs from the update
            new_ids = set(conversations_data.keys())

            # Delete conversations that are not in the new data
            ids_to_delete = existing_ids - new_ids
            if ids_to_delete:
                cursor.execute(
                    'DELETE FROM conversations WHERE conversation_id IN ({})'.format(
                        ','.join('?' * len(ids_to_delete))
                    ),
                    tuple(ids_to_delete)
                )

            # Update or insert new conversations
            for conv_id, conv_data in conversations_data.items():
                try:
                    # Validate created_at format
                    datetime.fromisoformat(conv_data['created_at'])

                    # Prepare members data
                    members_json = json.dumps(conv_data['members'])

                    cursor.execute('''
                        INSERT OR REPLACE INTO conversations 
                        (conversation_id, name, created_at, members)
                        VALUES (?, ?, ?, ?)
                    ''', (
                        conv_id,
                        conv_data['name'],
                        conv_data['created_at'],
                        members_json
                    ))
                except (KeyError, ValueError) as e:
                    print(f"Error updating conversation {conv_id}: {str(e)}")
                    raise

            # Commit all changes
            self.conn_.commit()

        except Exception as e:
            # If any error occurs, rollback all changes
            self.conn_.rollback()
            print(f"Error during conversation update: {str(e)}")
            raise

    def add_conversation(self, conversation_id: str, name: str, members: List[str]) -> None:
        """Add a new conversation to the database."""
        cursor = self.conn_.cursor()
        cursor.execute('''
            INSERT OR IGNORE INTO conversations (conversation_id, name, created_at, members)
            VALUES (?, ?, ?, ?)
        ''', (conversation_id, name, datetime.now(timezone.utc).isoformat(), json.dumps(members)))

    def receive_messages(self, messages: Dict[str, List[Dict[str, Any]]], decryptor: Callable[[str], str]) -> None:
        cursor = self.conn_.cursor()

        for conversation_id, conv_messages in messages.items():
            cursor.execute('SELECT 1 FROM conversations WHERE conversation_id = ?', (conversation_id,))
            if not cursor.fetchone():
                self.add_conversation(
                    conversation_id=conversation_id,
                    name="unknown",
                    members=[],
                )

            for message in conv_messages:
                try:
                    decrypted_content = decryptor(message["content"])
                    cursor.execute('''
                        INSERT INTO messages (
                            message_id, conversation_id, sender, timestamp,
                            content, delivery_status
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        message["id"],
                        conversation_id,
                        message["sender"],
                        message["timestamp"],
                        decrypted_content,
                        json.dumps({"status": "received", "timestamp": datetime.now(timezone.utc).isoformat()})
                    ))
                except Exception as e:
                    print(f"Error processing message {message.get('id')}: {str(e)}")
                    continue

        self.conn_.commit()

    def get_conversation_messages(self, conversation_id: str) -> List[Dict[str, Any]]:
        """Retrieve all messages for a given conversation."""
        cursor = self.conn_.cursor()
        cursor.execute('''
            SELECT message_id, sender, timestamp, content
            FROM messages
            WHERE conversation_id = ?
            ORDER BY timestamp ASC
        ''', (conversation_id,))

        messages = []
        for row in cursor.fetchall():
            messages.append({
                "id": row[0],
                "sender": row[1],
                "timestamp": row[2],
                "content": row[3],
            })
        return messages

    def get_all(self):
        cursor = self.conn_.cursor()
        cursor.execute("SELECT * FROM messages ORDER BY timestamp ASC")
        return cursor.fetchall()

class FinalMessages(Messages):
    def update_conversations(self, token: Token) -> None:
        response = token.request("get", f"{API_URL}/messaging/conversations", verify=ssl_verification)
        raise_for_status(response)
        super().update_conversations(response.json())
        print(f"update done...")

    def add_conversation(self, name: str, members: List[str], token: Token) -> None:
        data = {
            "conversation_name": name,
            "members": members,
        }
        response = token.request("post", f"{API_URL}/messaging/conversation", json=data, verify=ssl_verification)
        raise_for_status(response)
        super().add_conversation(response.json(), name, members)
        print(f"conversation {response.json()} created")

    def add_members(self, conv_id, members: List[str], token: Token):
        data = {
          "conversation_id": conv_id,
          "users_to_add": [
            members
          ]
        }
        response = token.request("patch", f"{API_URL}/messaging/add", json=data, verify=ssl_verification)
        raise_for_status(response)
        self.update_conversations(token)

    def exclude_members(self, conv_id, members: List[str], token: Token):
        data = {
          "conversation_id": conv_id,
          "users_to_add": [
            members
          ]
        }
        response = token.request("patch", f"{API_URL}/messaging/remove", json=data, verify=ssl_verification)
        raise_for_status(response)
        self.update_conversations(token)

    def delete_conversation(self, conv_id: str, token: Token):
        data = {
            "conversation_id": conv_id,
        }
        response = token.request("delete", f"{API_URL}/messaging/conversation", json=data, verify=ssl_verification)
        raise_for_status(response)
        self.update_conversations(token)

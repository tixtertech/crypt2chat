import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import List, Union

from common.decorators import anti_code_injection
from server.exceptions import *
from server.users import UsersManager


class MessagesManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Create conversations table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS conversations (
                        conversation_id TEXT PRIMARY KEY,
                        name TEXT,
                        created_at TIMESTAMPTZ,
                        members JSONB
                    )
                ''')
                # Create messages table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS messages (
                        message_id TEXT PRIMARY KEY,
                        conversation_id TEXT,
                        sender TEXT,
                        timestamp TIMESTAMPTZ,
                        content BYTEA,
                        delivery_status JSONB,
                        FOREIGN KEY (conversation_id) REFERENCES conversations (conversation_id) ON DELETE CASCADE
                    )
                ''')
                conn.commit()
        except sqlite3.Error as e:
            raise DataBaseError(f"Database initialization failed: {e}")

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def create_conversation(self, creator_id: str, members: List[str], name: str) -> str:
        users_manager = UsersManager()
        if users_manager.is_account_frozen(creator_id):
            raise FrozenAccountError("This account has been frozen. Please contact support.")
        if creator_id not in members:
            members.append(creator_id)

        for member in members:
            if not users_manager.is_user_id_taken(member):
                raise NotFoundError(f"User {member} not found")

        conversation_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc)
        members_json = json.dumps(members)

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO conversations (conversation_id, name, created_at, members)
                    VALUES (%s, %s, %s, %s)
                ''', (conversation_id, name, created_at, members_json))
                conn.commit()
                return conversation_id
        except sqlite3.Error as e:
            raise DataBaseError(f"Failed to create conversation: {e}")

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def send_message(self, sender: str, conversation_id: str, content: bytes) -> str:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Check if conversation exists and sender is a member
                cursor.execute('SELECT members FROM conversations WHERE conversation_id = %s', (conversation_id,))
                result = cursor.fetchone()
                if not result:
                    raise NotFoundError("Conversation not found")

                members = json.loads(result[0])
                if sender not in members:
                    raise UnauthorizedError("User is not a member of this conversation")

                # Create delivery status dictionary
                delivery_status = {member: member == sender for member in members}

                message_id = str(uuid.uuid4())
                timestamp = datetime.now(timezone.utc)

                # Insert the new message in conversation's table
                cursor.execute('''
                    INSERT INTO messages (message_id, conversation_id, sender, timestamp, content, delivery_status)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (message_id, conversation_id, sender, timestamp, content, json.dumps(delivery_status)))
                conn.commit()
                return message_id
        except sqlite3.Error as e:
            raise DataBaseError(f"Failed to send message: {e}")

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def get_messages(self, user_id: str) -> Dict[str, List[Dict[str, Union[str, datetime, bytes]]]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Get all conversations where user is a member
                cursor.execute('''
                    SELECT conversation_id FROM conversations 
                    WHERE members @> %s::jsonb
                ''', (json.dumps([user_id]),))

                conversations = cursor.fetchall()
                result = {}

                for (conv_id,) in conversations:
                    # Get undelivered messages from this conversation's table
                    cursor.execute('''
                        SELECT message_id, sender, timestamp, content
                        FROM messages
                        WHERE conversation_id = %s AND delivery_status->>%s = 'false'
                    ''', (conv_id, user_id))

                    messages = cursor.fetchall()
                    if messages:
                        result[conv_id] = [
                            {
                                "id": msg_id,
                                "sender": sender,
                                "timestamp": timestamp,
                                "content": content
                            }
                            for msg_id, sender, timestamp, content in messages
                        ]
                return result
        except sqlite3.Error as e:
            raise DataBaseError(f"Failed to retrieve messages: {e}")

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def get_message_infos(self, user_id: str, message_id: str) -> Dict[str, Union[str, datetime, bytes, dict]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT conversation_id, sender, timestamp, content, delivery_status
                    FROM messages
                    WHERE message_id = %s
                ''', (message_id,))

                result = cursor.fetchone()
                if not result:
                    raise NotFoundError("Message not found")

                conversation_id, sender, timestamp, content, delivery_status = result

                cursor.execute('SELECT members FROM conversations WHERE conversation_id = %s', (conversation_id,))
                members_result = cursor.fetchone()
                if not members_result or user_id not in json.loads(members_result[0]):
                    raise UnauthorizedError("You do not have access to this message")

                return {
                    "message_id": message_id,
                    "conversation_id": conversation_id,
                    "sender": sender,
                    "timestamp": timestamp,
                    "content": content,
                    "delivery_status": json.loads(delivery_status)
                }
        except sqlite3.Error as e:
            raise DataBaseError(f"Failed to get message info: {e}")

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def delete_message(self, user_id: str, message_id: str) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                cursor.execute('''
                    SELECT sender FROM messages
                    WHERE message_id = %s
                ''', (message_id,))
                result = cursor.fetchone()

                if not result:
                    raise NotFoundError("Message not found")

                sender = result[0]

                if sender != user_id:
                    raise UnauthorizedError("User is not the sender of this message and cannot delete it")

                cursor.execute('''
                    DELETE FROM messages
                    WHERE message_id = %s
                ''', (message_id,))
                conn.commit()

        except sqlite3.Error as e:
            raise DataBaseError(f"Failed to delete message: {e}")

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def mark_messages_as_delivered(self, user_id: str, messages_ids: List[str]) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                for message_id in messages_ids:
                    cursor.execute('SELECT conversation_id FROM messages WHERE message_id = %s', (message_id,))
                    result = cursor.fetchone()
                    if not result:
                        raise NotFoundError(f"Message {message_id} not found")
                    conversation_id = result[0]

                    cursor.execute('SELECT members FROM conversations WHERE conversation_id = %s', (conversation_id,))
                    result = cursor.fetchone()
                    if not result:
                        raise NotFoundError(f"Message {message_id} -> Conversation {conversation_id} not found")

                    if user_id not in json.loads(result[0]):
                        raise UnauthorizedError(f"Message {message_id} -> User {user_id} are not member of conversation {conversation_id}")

                    cursor.execute('''
                        UPDATE messages
                        SET delivery_status = jsonb_set(delivery_status, %s, 'true')
                        WHERE message_id = %s
                    ''', (f'{{"{user_id}"}}', message_id))

                    # Check if message is fully delivered
                    cursor.execute('SELECT delivery_status FROM messages WHERE message_id = %s', (message_id,))
                    status_result = cursor.fetchone()
                    if status_result:
                        delivery_status = json.loads(status_result[0])
                        if all(delivery_status.values()):
                            cursor.execute('DELETE FROM messages WHERE message_id = %s', (message_id,))

                conn.commit()
        except sqlite3.Error as e:
            raise DataBaseError(f"Failed to mark messages as delivered: {e}")

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def update_conversation_name(self, user_id: str, conversation_id: str, new_name: str) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Check if conversation exists and sender is a member
                cursor.execute('SELECT members FROM conversations WHERE conversation_id = %s', (conversation_id,))
                result = cursor.fetchone()
                if not result:
                    raise NotFoundError("Conversation not found")

                members = json.loads(result[0])
                if user_id not in members:
                    raise UnauthorizedError(f"User {user_id} is not a member of this conversation")

                cursor.execute('''
                    UPDATE conversations
                    SET name = %s
                    WHERE conversation_id = %s
                ''', (new_name, conversation_id))
                conn.commit()
        except sqlite3.Error as e:
            raise DataBaseError(f"Failed to update conversation name: {e}")

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def remove_users(self, user_id: str, conversation_id: str, users_to_remove: List[str]) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Get current members
                cursor.execute('SELECT members FROM conversations WHERE conversation_id = %s', (conversation_id,))
                result = cursor.fetchone()
                if not result:
                    raise NotFoundError("Conversation not found")

                current_members = json.loads(result[0])
                if user_id not in current_members:
                    raise UnauthorizedError(f"User {user_id} is not a member of this conversation")

                new_members = [m for m in current_members if m not in users_to_remove]

                if len(new_members) == 0:
                    raise ValueError("Cannot remove all members from conversation")

                # Update members list
                cursor.execute('''
                    UPDATE conversations
                    SET members = %s
                    WHERE conversation_id = %s
                ''', (json.dumps(new_members), conversation_id))

                conn.commit()
        except sqlite3.Error as e:
            raise DataBaseError(f"Failed to remove users from conversation: {e}")

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def add_users(self, user_id:str, conversation_id: str, users_to_add: List[str]) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Verify all users exist
                users_manager = UsersManager()
                for user_id in users_to_add:
                    if not users_manager.is_user_id_taken(user_id):
                        raise NotFoundError(f"User {user_id} not found")

                # Get current members
                cursor.execute('SELECT members FROM conversations WHERE conversation_id = %s', (conversation_id,))
                result = cursor.fetchone()
                if not result:
                    raise NotFoundError("Conversation not found")

                current_members = json.loads(result[0])
                if user_id not in current_members:
                    raise UnauthorizedError(f"User {user_id} is not a member of this conversation")

                new_members = list(set(current_members + users_to_add))

                # Update members list
                cursor.execute('''
                    UPDATE conversations
                    SET members = %s
                    WHERE conversation_id = %s
                ''', (json.dumps(new_members), conversation_id))

                conn.commit()
        except sqlite3.Error as e:
            raise DataBaseError(f"Failed to add users to conversation: {e}")

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def get_conversation_infos(self, conversation_id: str) -> Dict[str, Union[str, datetime, List[str]]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT conversation_id, name, created_at, members
                    FROM conversations
                    WHERE conversation_id = %s
                ''', (conversation_id,))

                result = cursor.fetchone()
                if not result:
                    raise NotFoundError("Conversation not found")

                return {
                    "id": result[0],
                    "name": result[1],
                    "created_at": result[2],
                    "members": json.loads(result[3])
                }
        except sqlite3.Error as e:
            raise DataBaseError(f"Failed to get conversation info: {e}")

    @anti_code_injection(in_case_raise=CodeInjectionError)
    def delete_conversation(self, user_id: str, conversation_id: str) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Get current members
                cursor.execute('SELECT members FROM conversations WHERE conversation_id = %s', (conversation_id,))
                result = cursor.fetchone()
                if not result:
                    raise NotFoundError("Conversation not found")

                current_members = json.loads(result[0])
                if user_id not in current_members:
                    raise UnauthorizedError(f"User {user_id} is not a member of this conversation")

                cursor.execute('''
                       DELETE FROM conversation
                       WHERE conversation_id = %s
                   ''', (conversation_id,))
                conn.commit()
        except sqlite3.Error as e:
            raise DataBaseError(f"Failed to remove users from conversation: {e}")
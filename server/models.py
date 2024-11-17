from pydantic import BaseModel

class Register(BaseModel):
    username: str
    authentication_key: str
    identity_key: str
    identity_sig: str
    signed_pre_keys: str

class Verify(BaseModel):
    challenge: str
    signed_challenge: str

class ChangeUsername(BaseModel):
    user_id: str
    new_username: str
class SignedPreKeys(BaseModel):
    user_id: str
    signed_pre_keys: bytes

class SendMessage(BaseModel):
    conversation_id: str
    content: bytes

class Delivered(BaseModel):
    messages_ids: list

class CreateConversation(BaseModel):
    conversation_name: str
    members: list

class DeleteConversation(BaseModel):
    conversation_id: str


class RemoveUsers(BaseModel):
    conversation_id: str
    users_to_remove: list

class AddUsers(BaseModel):
    conversation_id: str
    users_to_add: list
from pydantic import BaseModel

class Register(BaseModel):
    username: str
    authentication_key: str
    identity_key: str
    identity_sig: str

class Verify(BaseModel):
    authenticated_challenge: str

class ChangeUsername(BaseModel):
    new_username: str

class SignedPreKeys(BaseModel):
    signed_pre_keys: str

class SendMessage(BaseModel):
    conversation_id: str
    content: str

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
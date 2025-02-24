from pydantic import BaseModel

class Register(BaseModel):
    username: str
    authentication_key: str
    identity_key: str
    identity_sig: str

class Verify(BaseModel):
    authChallenge: str

class Username(BaseModel):
    username: str

class SignedPreKeys(BaseModel):
    signed_pre_keys: str

class SendMessage(BaseModel):
    conv_id: str
    content: str

class Delivered(BaseModel):
    message_ids: list

class NewConv(BaseModel):
    conv_name: str
    user_ids: list

class UserIds(BaseModel):
    user_ids: list
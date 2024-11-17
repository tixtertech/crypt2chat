import os

from fastapi import APIRouter, Query, Depends

from server.auth import TokenManager, user_challenge
from server.exceptions import *
from server.fastapi_security import oauth2_scheme
from server.models import *
from server.users import UsersManager

router = APIRouter()
users_manager = UsersManager(os.getenv("SERVER_USERS_DB"))
auth_manager = TokenManager(os.getenv("SERVER_TOKENS_DB"))

@router.post("/register")
@http_error_handler()
async def register(base_model: Register):
    return user_challenge.get_challenge(
        authentication_key=base_model.authentication_key.encode(),
        identity_key=base_model.identity_key.encode(),
        function=users_manager.register,
        args=[],
        kwargs={
            'username': base_model.username,
            'authentication_key': base_model.authentication_key.encode(),
            'identity_key': base_model.identity_key.encode(),
            'identity_sig': base_model.identity_sig.encode(),
            'signed_pre_keys': base_model.signed_pre_keys.encode(),
            'override': False
        }
    )

@router.post("/login")
@http_error_handler()
async def login(user_id : str = Query(None, alias="user_id")):
    if users_manager.is_account_frozen(user_id):
        raise FrozenAccountError("This account has been frozen. Please contact support.")
    user = users_manager.get_details(user_id=user_id)
    return user_challenge.get_challenge(
        authentication_key=user.get("authentication_key"),
        identity_key= user.get("identity_key"),
        function=auth_manager.new_token,
        args=[],
        kwargs={
            'subject': user.get("user_id"),
            'issuer': "crypt2chat_server"
        }
    )

@router.post("/verify")
@http_error_handler({
    user_challenge.UnauthorizedError: status.HTTP_401_UNAUTHORIZED,
    user_challenge.BadRequestError: status.HTTP_400_BAD_REQUEST
})
async def verify(base_model: Verify):
    return user_challenge.verify_challenge(
        challenge=base_model.challenge,
        signed_challenge=base_model.signed_challenge
    )


@router.delete("/logout")
@http_error_handler()
async def logout(token: dict = Depends(oauth2_scheme)):
    auth_manager.revoke_token(jti=token.get('jti'))

@router.get("/me")
@http_error_handler()
async def me(token: dict = Depends(oauth2_scheme)):
    return {
        "user": users_manager.get_details(user_id=token.get('sub')),
        "token": token
    }

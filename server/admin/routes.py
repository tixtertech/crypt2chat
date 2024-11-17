import os

from fastapi import APIRouter, Query

from server.auth import admin_challenge
from server.exceptions import *
from server.models import *
from server.users.manager import UsersManager

router = APIRouter()
users_manager = UsersManager(os.getenv("SERVER_USERS_DB"))

@router.post("/verify")
@http_error_handler({
    admin_challenge.UnauthorizedError: status.HTTP_401_UNAUTHORIZED,
    admin_challenge.BadRequestError: status.HTTP_400_BAD_REQUEST
})
async def verify(base_model: Verify):
    return admin_challenge.verify_challenge(
        challenge=base_model.challenge,
        signed_challenge=base_model.signed_challenge
    )

@router.patch("/freeze-account")
@http_error_handler()
async def freeze(
    user_id : str = Query(None, alias="user_id"),
):
    with open(os.getenv('ADMIN_PUBKEY'), "rb") as file:
        pubkey = file.read()
    return admin_challenge.get_challenge(
        pubkey=pubkey,
        function=users_manager.freeze_account,
        args=[],
        kwargs={
            'user_id':user_id
        }
    )

@router.patch("/unfreeze-account")
@http_error_handler()
async def unfreeze(
    user_id : str = Query(None, alias="user_id"),
):
    with open(os.getenv('ADMIN_PUBKEY'), "rb") as file:
        pubkey = file.read()
    return admin_challenge.get_challenge(
        pubkey=pubkey,
        function=users_manager.unfreeze_account,
        args=[],
        kwargs={
            'user_id':user_id
        }
    )
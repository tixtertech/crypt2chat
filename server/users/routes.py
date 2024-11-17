import os
from datetime import datetime

from fastapi import APIRouter, Query

from server.auth import user_challenge
from server.exceptions import *
from server.models import ChangeUsername, SignedPreKeys
from server.users.manager import UsersManager

router = APIRouter()
users_manager = UsersManager(os.getenv("SERVER_USERS_DB"))

@router.get("/name/{username}", response_model=dict)
@http_error_handler()
async def get_details(username: str):
    return users_manager.get_details(username=username)

@router.get("/id/{user_id}", response_model=dict)
@http_error_handler()
async def get_details(user_id: str):
    return users_manager.get_details(user_id=user_id)

@router.get("")
@http_error_handler()
async def get_users(search: Optional[str] = Query(None, alias="search"),
              since: Optional[datetime] = Query(None, alias="since"),
              limit: Optional[int] = Query(None, alias="limit")):
    return users_manager.fetch_db(search=search, since=since, limit=limit)

@router.get("/signed-pre-key")
@http_error_handler()
async def get_signed_pre_key(
        user_id: str = Query(None, alias="user_id"),
):
    return users_manager.get_signed_pre_key(user_id=user_id)

@router.put("/signed-pre-key")
@http_error_handler()
async def renew_signed_pre_key(base_model: SignedPreKeys):
    user = users_manager.get_details(user_id=base_model.user_id)
    return user_challenge.get_challenge(
        authentication_key=user["authentication_key"],
        identity_key=user["identity_key"],
        function=users_manager.renew_signed_pre_keys,
        args=[],
        kwargs={
            'user_id': base_model.user_id,
            'signed_pre_keys': base_model.signed_pre_keys
        }
    )

@router.put("/change-username")
@http_error_handler()
async def change_username(base_model: ChangeUsername):
    user = users_manager.get_details(user_id=base_model.user_id)
    return user_challenge.get_challenge(
        authentication_key=user["authentication_key"],
        identity_key=user["identity_key"],
        function=users_manager.change_username,
        args=[],
        kwargs={
            'user_id': base_model.user_id,
            'new_username': base_model.new_username
        }
    )


@router.delete("/delete-account")
@http_error_handler()
async def delete_account(
        user_id: str = Query(None, alias="user_id"),
):
    user = users_manager.get_details(user_id=user_id)
    return user_challenge.get_challenge(
        authentication_key=user["authentication_key"],
        identity_key=user["identity_key"],
        function=users_manager.delete_account,
        args=[],
        kwargs={'user_id': user_id}
    )
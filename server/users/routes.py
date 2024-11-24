import os
from datetime import datetime

from fastapi import APIRouter, Query, Depends

from server.exceptions import *
from server.fastapi_security import oauth2_scheme
from server.models import *
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
async def renew_signed_pre_key(base_model: SignedPreKeys, token: dict = Depends(oauth2_scheme)):
    return users_manager.renew_signed_pre_keys(
            user_id=token.get("sub"),
            signed_pre_keys=base_model.signed_pre_keys
    )

@router.put("/change-username")
@http_error_handler()
async def change_username(base_model: ChangeUsername, token: dict = Depends(oauth2_scheme)):
    return users_manager.change_username(
        user_id=token.get("sub"),
        new_username=base_model.new_username
    )


@router.delete("/delete-account")
@http_error_handler()
async def delete_account(token: dict = Depends(oauth2_scheme)):
    return users_manager.delete_account(user_id=token.get("sub"))
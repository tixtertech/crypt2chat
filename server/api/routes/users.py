from server.api.dependencies import *

router = APIRouter()

@router.get("")
@http_error_handler()
async def download_db(search: Optional[str] = Query(None, alias="search"),
              since: Optional[datetime] = Query(None, alias="since"),
              limit: Optional[int] = Query(None, alias="limit")):
    return users_.fetch_db(search=search, since=since, limit=limit)

@router.get("/name/{username}", response_model=dict)
@http_error_handler()
async def get_details_name(username: str):
    return users_.get_details(username=username)

@router.get("/{user_id}", response_model=dict)
@http_error_handler()
async def get_details_id(user_id: str):
    return users_.get_details(user_id=user_id)

@router.get("/{user_id}/signed-pre-key")
@http_error_handler()
async def get_signed_pre_key(
        user_id: str,
):
    return users_.get_signed_pre_key(user_id=user_id)

@router.put("/signed-pre-key")
@http_error_handler()
async def renew_signed_pre_key(base_model: SignedPreKeys, token: dict = Depends(oauth2_scheme)):
    return users_.renew_signed_pre_keys(
            user_id=token.get("sub"),
            signed_pre_keys=base_model.signed_pre_keys
    )

@router.put("/change-username")
@http_error_handler()
async def change_username(base_model: Username, token: dict = Depends(oauth2_scheme)):
    return users_.change_username(
        user_id=token.get("sub"),
        new_username=base_model.username
    )


@router.delete("/delete-account")
@http_error_handler()
async def delete_account(token: dict = Depends(oauth2_scheme)):
    return users_.delete_account(user_id=token.get("sub"))
from server.api.dependencies import *

router = APIRouter()

@router.post("")
@http_error_handler()
async def new_conversation(
        base_model: NewConv,
        token: dict = Depends(oauth2_scheme)
):
    return messages_.create_conversation(
        creator_id=token.get('sub'),
        members=base_model.user_ids,
        name=base_model.conv_name,
    )


@router.delete("/{conv_id}")
@http_error_handler()
async def delete_conversation(
        conv_id: str,
        token: dict = Depends(oauth2_scheme)
):
    messages_.delete_conversation(
        user_id=token.get('sub'),
        conversation_id=conv_id,
    )

@router.get("/update")
@http_error_handler()
async def get_update(
        token: dict = Depends(oauth2_scheme)
):
    return messages_.get_update(user_id=token.get('sub'))

@router.delete("/{conv_id}/users")
@http_error_handler()
async def exclude_users(
        conv_id: str,
        base_model: UserIds,
        token: dict = Depends(oauth2_scheme)
):
    messages_.remove_users(
        user_id=token.get('sub'),
        conversation_id=conv_id,
        users_to_remove=base_model.user_ids,
    )

@router.post("/{conv_id}/users")
@http_error_handler()
async def exclude_users(
        conv_id: str,
        base_model: UserIds,
        token: dict = Depends(oauth2_scheme)
):
    messages_.remove_users(
        user_id=token.get('sub'),
        conversation_id=conv_id,
        users_to_remove=base_model.user_ids,
    )
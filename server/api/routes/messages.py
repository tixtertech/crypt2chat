from server.api.dependencies import *

router = APIRouter()


@router.post("")
@http_error_handler()
async def send_message(base_model: SendMessage, token: dict = Depends(oauth2_scheme)):
    return {"message_id": messages_.send_message(
        sender=token.get('sub'),
        conversation_id=base_model.conv_id,
        content=base_model.content,
    )}

@router.get("")
@http_error_handler()
async def get_messages(token: dict = Depends(oauth2_scheme)):
    return messages_.get_messages(
        user_id=token.get('sub')
    )

@router.patch("/delivered")
@http_error_handler()
async def mark_as_delivered(base_model: Delivered, token: dict = Depends(oauth2_scheme)):
    messages_.mark_messages_as_delivered(
        user_id=token.get('sub'),
        messages_ids=base_model.message_ids,
    )

@router.get("/{message_id}")
@http_error_handler()
async def get_message(
        message_id: str,
        token: dict = Depends(oauth2_scheme)
):
    return messages_.get_message_infos(
        user_id=token.get('sub'),
        message_id=message_id,
    )

@router.delete("/{message_id}")
@http_error_handler()
async def delete_message(
        message_id: str,
        token: dict = Depends(oauth2_scheme)
):
    messages_.delete_message(
        user_id=token.get('sub'),
        message_id=message_id,
    )
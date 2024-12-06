import os

from fastapi import APIRouter, Depends

from server.exceptions import *
from server.fastapi_security import oauth2_scheme
from server.messaging import MessagesManager
from server.models import *

router = APIRouter()
messages_manager = MessagesManager(os.getenv("SERVER_MESSAGES_DB"))


@router.post("")
@http_error_handler()
async def send_message(base_model: SendMessage, token: dict = Depends(oauth2_scheme)):
    return {"message_id": messages_manager.send_message(
        sender=token.get('sub'),
        conversation_id=base_model.conversation_id,
        content=base_model.content,
    )}

@router.get("")
@http_error_handler()
async def get_messages(token: dict = Depends(oauth2_scheme)):
    return messages_manager.get_messages(
        user_id=token.get('sub')
    )

@router.patch("/delivered")
@http_error_handler()
async def mark_as_delivered(base_model: Delivered, token: dict = Depends(oauth2_scheme)):
    messages_manager.mark_messages_as_delivered(
        user_id=token.get('sub'),
        messages_ids=base_model.messages_ids,
    )

@router.get("/{message_id}")
@http_error_handler()
async def get_message_infos(
        message_id: str,
        token: dict = Depends(oauth2_scheme)
):
    return messages_manager.get_message_infos(
        user_id=token.get('sub'),
        message_id=message_id,
    )

@router.delete("/{message_id}")
@http_error_handler()
async def delete_message(
        message_id: str,
        token: dict = Depends(oauth2_scheme)
):
    messages_manager.delete_message(
        user_id=token.get('sub'),
        message_id=message_id,
    )

@router.get("/conversations")
@http_error_handler()
async def get_all_conversations(
        token: dict = Depends(oauth2_scheme)
):
    return messages_manager.get_all_conversations(
        user_id=token.get('sub'),
    )

@router.post("/conversation")
@http_error_handler()
async def create_conversation(
        base_model: CreateConversation,
        token: dict = Depends(oauth2_scheme)
):
    return messages_manager.create_conversation(
        creator_id=token.get('sub'),
        members=base_model.members,
        name=base_model.conversation_name,
    )


@router.delete("/conversation")
@http_error_handler()
async def delete_conversation(
        base_model: DeleteConversation,
        token: dict = Depends(oauth2_scheme)
):
    messages_manager.delete_conversation(
        user_id=token.get('sub'),
        conversation_id=base_model.conversation_id,
    )

@router.patch("/remove")
@http_error_handler()
async def exclude_users(
        base_model: RemoveUsers,
        token: dict = Depends(oauth2_scheme)
):
    messages_manager.remove_users(
        user_id=token.get('sub'),
        conversation_id=base_model.conversation_id,
        users_to_remove=base_model.users_to_remove,
    )

@router.patch("/add")
@http_error_handler()
async def exclude_users(
        base_model: AddUsers,
        token: dict = Depends(oauth2_scheme)
):
    messages_manager.remove_users(
        user_id=token.get('sub'),
        conversation_id=base_model.conversation_id,
        users_to_remove=base_model.users_to_add,
    )
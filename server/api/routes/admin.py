from server.api.dependencies import *

router = APIRouter()

@router.post("/verify")
@http_error_handler({
    admin_challenge.AccessForbiddenError: status.HTTP_401_UNAUTHORIZED,
    admin_challenge.BadRequestError: status.HTTP_400_BAD_REQUEST
})
async def verify(base_model: Verify):
    return admin_challenge.verify_challenge(
        authenticated_challenge=base_model.authenticated_challenge,
    )

@router.patch("/freeze-account")
@http_error_handler()
async def freeze(
    user_id : str = Query(None, alias="user_id"),
):
    with open(conf("keys", "rsa_pub"), "rb") as file:
        pubkey = file.read()
    return admin_challenge.get_challenge(
        pubkey=pubkey,
        function=users_.freeze_account,
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
    with open(conf("keys", "rsa_pub"), "rb") as file:
        pubkey = file.read()
    return admin_challenge.get_challenge(
        pubkey=pubkey,
        function=users_.unfreeze_account,
        args=[],
        kwargs={
            'user_id':user_id
        }
    )

@router.get("/requests-per-ip")
@http_error_handler()
async def get_request_per_ip():
    with open(conf("keys", "rsa_pub"), "rb") as file:
        pubkey = file.read()
    return admin_challenge.get_challenge(
        pubkey=pubkey,
        function=requests_.get_per_ip,
        args=[],
        kwargs={}
    )
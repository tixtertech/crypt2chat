import traceback
from functools import wraps
from typing import Optional, Dict, Type

from colorama import Fore, Style
from fastapi import HTTPException, status

from server.logging import logging_


class Crypt2chatError(ValueError):
    pass

class UnauthorizedError(Crypt2chatError):
    pass

class AccessForbiddenError(Crypt2chatError):
    pass

class ReplayAttackError(Crypt2chatError):
    pass

class DataBaseError(Crypt2chatError):
    pass

class AlreadyTakenError(Crypt2chatError):
    pass

class NotFoundError(Crypt2chatError):
    pass

class CodeInjectionError(Crypt2chatError):
    pass

class FrozenAccountError(Crypt2chatError):
    pass


def http_error_handler(error_mapping: Optional[Dict[Type[Exception], int]] = None,):
    error_mapping_ = {
        UnauthorizedError: status.HTTP_401_UNAUTHORIZED,
        AccessForbiddenError: status.HTTP_403_FORBIDDEN,
        ReplayAttackError: status.HTTP_403_FORBIDDEN,
        FrozenAccountError: status.HTTP_403_FORBIDDEN,
        AlreadyTakenError: status.HTTP_409_CONFLICT,
        NotFoundError: status.HTTP_404_NOT_FOUND,
        CodeInjectionError: status.HTTP_422_UNPROCESSABLE_ENTITY,
        DataBaseError: status.HTTP_500_INTERNAL_SERVER_ERROR
    }

    if error_mapping:
        error_mapping_.update(error_mapping)

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                status_code = None
                for error_type, status_data in error_mapping_.items():
                    if isinstance(e, error_type):
                        status_code = status_data
                        break

                if status_code is None:
                    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

                if status_code >= 500:
                    logging_.app_error(f"{traceback.format_exc()}")
                    print(Fore.RED + "ERROR" + Style.RESET_ALL + f":\t{traceback.format_exc()}")
                else:
                    logging_.app_warning(f"{traceback.format_exc()}")
                    print(Fore.YELLOW + "WARNING" + Style.RESET_ALL + f":\t{type(e)}: {e}")

                raise HTTPException(status_code=status_code, detail=f"{type(e)}: {e}")
        return wrapper
    return decorator
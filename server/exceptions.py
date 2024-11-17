from functools import wraps
from typing import Optional, Dict, Type

from fastapi import HTTPException, status


class Crypt2chatError(ValueError):
    pass

class UnauthorizedError(Crypt2chatError):
    pass

class BlacklistedTokenError(Crypt2chatError):
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
        BlacklistedTokenError: status.HTTP_403_FORBIDDEN,
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

                raise HTTPException(status_code=status_code, detail=str(e))
        return wrapper
    return decorator
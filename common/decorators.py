from typing import Callable, Optional, Any


def try_except(
    except_func: Optional[Callable[[Exception], None]] = None,
    finally_func: Optional[Callable[[], None]] = None,
    except_raise: Optional[Exception] = None,
    finally_raise: Optional[Exception] = None,
    except_return: Optional[Any] = None,
    finally_return: Optional[Any] = None,
    propagate_exception: bool = False
) -> Callable:
    """
    A decorator to handle exceptions and execute a final function after the main function.

    :param except_func: A function that takes an exception as an argument.
                        It is called if the main function raises an exception.
    :param finally_func: A function that takes no arguments.
                         It is called after the main function, regardless of whether it raised an exception.
    :param propagate_exception: If True, re-raises the exception after except_func is called.
    """

    def decorator(func: Callable[..., Any]):
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if propagate_exception:
                    raise
                if except_func is not None:
                    except_func(e)
                if except_raise is not None:
                    raise except_raise
                if except_return is not None:
                    return except_return
            finally:
                if finally_func is not None:
                    finally_func()
                if finally_raise is not None:
                    raise finally_raise
                if finally_return is not None:
                    return finally_return

        return wrapper
    return decorator


import re
import functools
from typing import List, Callable, Any

# List of common SQL injection patterns
SQL_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # Single quotes, SQL comments
    r"(\%22)|(\")|(\%3B)|(;)",  # Double quotes, semicolons
    r"(?i)(\b(SELECT|INSERT|DELETE|UPDATE|DROP|UNION|ALTER|CREATE|RENAME|TRUNCATE|REPLACE)\b)",  # SQL keywords
    r"(?i)(OR|AND)\s+\d+\s*=\s*\d+",  # OR 1=1, etc.
    r"(?i)(\bUNION\b\s*\bSELECT\b)",  # UNION SELECT
    r"(\*\*)",  # Double asterisk for bypass attempts
    r"(?i)(\bWHERE\b\s*\bTRUE\b)",  # WHERE TRUE
]


def check_for_sql_injection(value: str) -> bool:
    """
    Checks if a string contains SQL injection patterns.

    :param value: The string to check
    :return: True if SQL injection is detected, False otherwise
    """
    for pattern in SQL_PATTERNS:
        if re.search(pattern, value):
            return True
    return False


def anti_code_injection(
        exclude_args: List[int] = [],
        exclude_kwargs: List[str] = [],
        in_case_return: Any = None,
        in_case_raise: Any = None
) -> Callable:
    """
    A decorator to guard against SQL injection by checking all
    positional and keyword arguments except those specified in exclude_args and exclude_kwargs.

    :param exclude_args: Indices of positional arguments to exclude from checking.
    :param exclude_kwargs: Keys of keyword arguments to exclude from checking.
    :param in_case_return: Value to return in case SQL injection is detected.
    :param in_case_raise: Exception to raise in case SQL injection is detected.
    :return: The decorated function with SQL injection protection.
    """

    def decorator(func: Callable[..., Any]):

        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Check positional arguments
            for i, arg in enumerate(args):
                if i not in exclude_args:
                    # Only check strings
                    if isinstance(arg, str) and check_for_sql_injection(arg):
                        if in_case_raise:
                            raise in_case_raise
                        return in_case_return

            # Check keyword arguments
            for key, value in kwargs.items():
                if key not in exclude_kwargs:
                    # Only check strings
                    if isinstance(value, str) and check_for_sql_injection(value):
                        if in_case_raise:
                            raise in_case_raise
                        return in_case_return

            # Execute the original function if everything is OK
            return func(*args, **kwargs)

        return wrapper

    return decorator

# validation.py
import re

def validate_string_input(value: str, max_length: int = 50, allow_spaces: bool = True) -> tuple[str | None, str | None]:
    """
    Validates and sanitizes a string input.
    Returns (sanitized_value, error_message)
    """
    if not value:
        return None, "Input cannot be empty."

    value = value.strip()
    if len(value) == 0:
        return None, "Input cannot be empty after trimming."
    if len(value) > max_length:
        return None, f"Input exceeds maximum length of {max_length} characters."

    # Username-specific rule: disallow spaces and restrict characters
    if not allow_spaces and " " in value:
        return None, "Spaces are not allowed in usernames."

    # Only allow letters, numbers, underscore, hyphen
    if not re.match(r"^[a-zA-Z0-9_-]+$", value):
        return None, "Only letters, numbers, underscore (_), and hyphen (-) are allowed."

    return value, None


def validate_numeric_input(value, min_val=None, max_val=None) -> tuple[float | None, str | None]:
    try:
        num = float(value)
        if min_val is not None and num < min_val:
            return None, f"Value must be ≥ {min_val}"
        if max_val is not None and num > max_val:
            return None, f"Value must be ≤ {max_val}"
        return num, None
    except (ValueError, TypeError):
        return None, "Please enter a valid number."


def validate_password(password: str, min_length: int = 6) -> tuple[bool, str | None]:
    if len(password) < min_length:
        return False, f"Password must be at least {min_length} characters long."
    if not re.search(r"[a-zA-Z]", password):
        return False, "Password must contain at least one letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    return True, None
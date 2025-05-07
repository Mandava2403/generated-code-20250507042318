import bcrypt
import re
import datetime
from typing import Dict, Tuple, Optional, Any

users_db: Dict[str, Dict[str, Any]] = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 300  # 5 minutes


def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def verify_password(plain_password: str, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)


def is_password_strong(password: str) -> Tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "Password is strong."


def is_email_valid(email: str) -> bool:
    # Basic email validation regex
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None


def register_user(email: str, password: str) -> Tuple[bool, str]:
    if not is_email_valid(email):
        return False, "Invalid email format."
    if email in users_db:
        return False, "Email already registered."

    strong_password, strength_message = is_password_strong(password)
    if not strong_password:
        return False, strength_message

    hashed_pw = hash_password(password)
    users_db[email] = {
        'hashed_password': hashed_pw,
        'failed_attempts': 0,
        'locked_until': None
    }
    return True, "User registered successfully."


def is_user_locked(email: str) -> Tuple[bool, Optional[str]]:
    user = users_db.get(email)
    if not user:
        return False, None # Should not happen if called after user existence check

    if user['locked_until'] and datetime.datetime.now() < user['locked_until']:
        remaining_lock_time = user['locked_until'] - datetime.datetime.now()
        return True, f"Account locked. Try again in {remaining_lock_time.seconds // 60} minutes and {remaining_lock_time.seconds % 60} seconds."
    elif user['locked_until'] and datetime.datetime.now() >= user['locked_until']:
        # Lock expired, reset it
        user['locked_until'] = None
        user['failed_attempts'] = 0 # Reset attempts after lock expires
        return False, None
    return False, None


def login_user(email: str, password: str) -> Tuple[bool, str]:
    if not is_email_valid(email):
        return False, "Invalid email format."

    user = users_db.get(email)
    if not user:
        return False, "Invalid email or password."

    locked, lock_message = is_user_locked(email)
    if locked:
        return False, lock_message if lock_message else "Account is locked."

    if verify_password(password, user['hashed_password']):
        user['failed_attempts'] = 0
        user['locked_until'] = None
        # In a real application, a session token would be generated and returned here.
        return True, "Login successful."
    else:
        user['failed_attempts'] += 1
        if user['failed_attempts'] >= MAX_FAILED_ATTEMPTS:
            user['locked_until'] = datetime.datetime.now() + datetime.timedelta(seconds=LOCKOUT_DURATION_SECONDS)
            return False, f"Invalid email or password. Account locked for {LOCKOUT_DURATION_SECONDS // 60} minutes due to too many failed attempts."
        else:
            attempts_left = MAX_FAILED_ATTEMPTS - user['failed_attempts']
            return False, f"Invalid email or password. {attempts_left} attempts remaining before account lock."
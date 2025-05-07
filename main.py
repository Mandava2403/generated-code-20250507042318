import getpass
import logging
from user_management import register_user, login_user

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def handle_registration():
    logger.info("Starting user registration process")
    print("\n--- Register New User ---")
    email = input("Enter email: ")
    logger.info(f"Registration attempt for email: {email}")
    password = getpass.getpass("Enter password: ")
    confirm_password = getpass.getpass("Confirm password: ")

    if password != confirm_password:
        logger.warning(f"Registration failed for {email}: passwords do not match")
        print("Passwords do not match.")
        return

    logger.info(f"Attempting to register user with email: {email}")
    success, message = register_user(email, password)
    print(message)
    if success:
        logger.info(f"User registration successful for email: {email}")
    else:
        logger.warning(f"User registration failed for email: {email} - {message}")


def handle_login():
    logger.info("Starting user login process")
    print("\n--- User Login ---")
    email = input("Enter email: ")
    logger.info(f"Login attempt for email: {email}")
    password = getpass.getpass("Enter password: ")

    logger.info(f"Attempting to authenticate user: {email}")
    success, message = login_user(email, password)
    print(message)
    if success:
        logger.info(f"User login successful for: {email}")
        # Simulate a logged-in state or further actions
        print(f"Welcome, {email}!")
    else:
        logger.warning(f"User login failed for: {email} - {message}")


def main():
    logger.info("Application started")
    while True:
        logger.debug("Displaying main menu")
        print("\n--- Login System ---")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ")
        logger.info(f"User selected option: {choice}")

        if choice == '1':
            handle_registration()
        elif choice == '2':
            handle_login()
        elif choice == '3':
            logger.info("User requested application exit")
            print("Exiting system.")
            break
        else:
            logger.warning(f"Invalid menu choice: {choice}")
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
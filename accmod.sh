import os
import sys
import subprocess
import pwd
import spwd
import datetime
import logging
import argparse

# Setup logger to get results saved for queries
def setup_logger(logfile): # setup the file to be used to store logs
    logger = logging.getLogger('administer_accounts')
    handler = logging.FileHandler(logfile)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(message)s') # set the format in which logs get stored
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

# Function to execute shell commands
def execute_command(command):
    try:
        result = subprocess.run(command, check=True, text=True, capture_output=True)
        return result.stdout
    except subprocess.CalledProcessError as e: # error getting the information requested
        return e.stderr

# Check if a user has a password set and if they have non lock the account
def check_existing_password():
    logger.info("Checking for users without passwords...")
    for user in pwd.getpwall():
        username = user.pw_name
        if username == 'root': # check to make sure they are allowed to access the shadow file
            continue
        try:
            shadow = spwd.getspnam(username)
            if shadow.sp_pwd == '*':
                # Lock the user account if no password
                execute_command(f"sudo usermod -L {username}")
                logger.info(f"User {username} has no password. Account has been locked.")
        except KeyError: # error getting the information requested
            logger.error(f"Error retrieving information for {username}")

# Report expired accounts
def report_expired_acc():
    logger.info("Checking for expired accounts...")
    current_time = datetime.datetime.now().timestamp()
    for user in pwd.getpwall():
        username = user.pw_name
        if username == 'root': # check to make sure they are allowed to access the shadow file
            continue
        try:
            shadow = spwd.getspnam(username)
            if shadow.sp_expire != -1 and shadow.sp_expire < current_time:
                logger.info(f"User {username}'s account has expired.")
        except KeyError: # error retrieving expired accounts
            logger.error(f"Error retrieving accounts for {username}")

# Report account expiration dates
def report_expiration():
    logger.info("Reporting expiration dates for accounts...")
    for user in pwd.getpwall():
        username = user.pw_name
        if username == 'root': # check to make sure they are allowed to access the shadow file
            continue
        try:
            shadow = spwd.getspnam(username)
            if shadow.sp_expire == -1:
                logger.info(f"User {username} has no expiration date.")
            else:
                expire_date = datetime.datetime.fromtimestamp(shadow.sp_expire).strftime('%Y-%m-%d %H:%M:%S') # assign the expiration date and time to a variable
                logger.info(f"User {username} - Expiration Date: {expire_date}")
        except KeyError: # error getting the information requested
            logger.error(f"Error retrieving information for {username}")

# Report accounts that do not expire
def report_no_expiration_acc():
    logger.info("Reporting accounts that do not expire...")
    for user in pwd.getpwall():
        username = user.pw_name
        if username == 'root': #check to make sure they are allowed to access the shadow file
            continue
        try:
            shadow = spwd.getspnam(username)
            if shadow.sp_expire == -1:
                logger.info(f"User {username} does not have an expiration date.")
        except KeyError: # error getting the information requested
            logger.error(f"Error retrieving information for {username}")

# Lock or unlock an account
def lock_unlock_acc(username, action):
    if action == "lock":
        execute_command(f"sudo usermod -L {username}")
        logger.info(f"User {username} has been locked.")
    elif action == "unlock":
        execute_command(f"sudo usermod -U {username}")
        logger.info(f"User {username} has been unlocked.")
    else: #error
        logger.error("Invalid action. Use 'lock' or 'unlock'.")

# Add a new user interactively
def add_user(username, home_dir, full_name, password, expire_date):
    if username == "root":
        logger.error("Cannot create root account.")
        return

    try:
        execute_command(f"sudo useradd -m -d {home_dir} -c \"{full_name}\" -e {expire_date} {username}")
        execute_command(f"echo \"{username}:{password}\" | sudo chpasswd")
        execute_command(f"sudo chage -d 0 {username}")  # Forces password reset on next login
        logger.info(f"User {username} created. Password reset required on first login.")
    except Exception as e: #error
        logger.error(f"Error creating user {username}: {e}")

# alter expiration date of a user
def change_expiration(username, new_expire_date):
    if username == "root":
        logger.error("Cannot change expiration date for root account.")
        return

    try:
        execute_command(f"sudo chage -E {new_expire_date} {username}")
        logger.info(f"Expiration date for user {username} changed to {new_expire_date}.")
    except Exception as e: #error
        logger.error(f"Error changing expiration date for {username}: {e}")

# Parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Administer user accounts")
    parser.add_argument("-l", "--logfile", required=True, help="Log file to write results to.")
    parser.add_argument("-r", "--report", action="store_true", help="Generate user account reports.")
    parser.add_argument("-a", "--add-user", action="store_true", help="Add a new user account interactively.")
    parser.add_argument("-u", "--username", type=str, help="Username for lock/unlock, modify expiration date.")
    parser.add_argument("-p", "--password", type=str, help="Password for new user.")
    parser.add_argument("-d", "--home-dir", type=str, help="Home directory for new user.")
    parser.add_argument("-f", "--full-name", type=str, help="Full name for new user.")
    parser.add_argument("-e", "--expire-date", type=str, help="Expiration date for new user (YYYY-MM-DD).")
    parser.add_argument("-m", "--modify-expire", action="store_true", help="Modify expiration date for user.")
    parser.add_argument("-l", "--lock", action="store_true", help="Lock a user account.")
    parser.add_argument("-u", "--unlock", action="store_true", help="Unlock a user account.")
    return parser.parse_args()

# Main function
def main():
    args = parse_arguments()

    # Setup logging
    logger = setup_logger(args.logfile)

    if args.report:
        check_existing_password()
        report_expired_acc()
        report_expiration()
        report_no_expiration_acc()
    elif args.add_user:
        if not (args.username and args.password and args.home_dir and args.full_name and args.expire_date):
            print("Please provide all necessary information to create a user.")
        else:
            add_user(args.username, args.home_dir, args.full_name, args.password, args.expire_date)
    elif args.modify_expire:
        if args.username and args.expire_date:
            change_expiration_date(args.username, args.expire_date)
        else:
            print("Please provide a username and new expiration date.")
    elif args.lock:
        if args.username:
            lock_unlock_account(args.username, "lock")
        else:
            print("Please provide a username to lock.")
    elif args.unlock:
        if args.username:
            lock_unlock_account(args.username, "unlock")
        else:
            print("Please provide a username to unlock.")
    else:
        print("No action specified.")

if __name__ == "__main__":
    main()

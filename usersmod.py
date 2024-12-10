#!/usr/bin/env python3
import os
import subprocess
import pwd
import shadow
import argparse
from datetime import datetime


# Utility function to log messages
def log_message(message, log_file):
    with open(log_file, 'a') as log:
        log.write(f"{datetime.now()} - {message}\n")
    print(message)


# Function to report users without a password and lock them
def report_no_password_users(log_file):
    users_locked = []
    for user in pwd.getpwall():
        username = user.pw_name
        try:
            shadow_entry = shadow.getspnam(username)
            if shadow_entry.sp_pwdp == "!" or shadow_entry.sp_pwdp == "*":
                # Lock the account if no password
                subprocess.run(["passwd", "-l", username], check=True)
                log_message(f"Account '{username}' has no password. Locked.", log_file)
                users_locked.append(username)
        except KeyError:
            continue
    if not users_locked:
        log_message("No users without a password found.", log_file)


# Function to report expired accounts
def report_expired_accounts(log_file):
    expired_users = []
    for user in pwd.getpwall():
        username = user.pw_name
        try:
            shadow_entry = shadow.getspnam(username)
            expiration = shadow_entry.sp_expire
            if expiration != 0 and expiration < int(datetime.now().timestamp()):
                # Account is expired
                expired_users.append(username)
        except KeyError:
            continue
    if expired_users:
        log_message(f"Expired accounts: {', '.join(expired_users)}", log_file)
    else:
        log_message("No expired accounts found.", log_file)


# Function to report expiration date/time for all accounts
def report_expiration_dates(log_file):
    expiration_info = []
    for user in pwd.getpwall():
        username = user.pw_name
        try:
            shadow_entry = shadow.getspnam(username)
            expiration = shadow_entry.sp_expire
            if expiration != 0:
                expiration_time = datetime.utcfromtimestamp(expiration).strftime('%Y-%m-%d %H:%M:%S')
                expiration_info.append(f"{username}: {expiration_time}")
        except KeyError:
            continue
    if expiration_info:
        log_message(f"Account expiration dates:\n" + "\n".join(expiration_info), log_file)
    else:
        log_message("No accounts with expiration dates found.", log_file)


# Function to report all accounts that do not expire
def report_non_expiring_accounts(log_file):
    non_expiring_users = []
    for user in pwd.getpwall():
        username = user.pw_name
        try:
            shadow_entry = shadow.getspnam(username)
            expiration = shadow_entry.sp_expire
            if expiration == 0:
                non_expiring_users.append(username)
        except KeyError:
            continue
    if non_expiring_users:
        log_message(f"Non-expiring accounts: {', '.join(non_expiring_users)}", log_file)
    else:
        log_message("No non-expiring accounts found.", log_file)


# Function to lock/unlock user accounts
def lock_unlock_account(username, lock, log_file):
    try:
        if lock:
            subprocess.run(["passwd", "-l", username], check=True)
            log_message(f"Account '{username}' has been locked.", log_file)
        else:
            subprocess.run(["passwd", "-u", username], check=True)
            log_message(f"Account '{username}' has been unlocked.", log_file)
    except subprocess.CalledProcessError:
        log_message(f"Failed to change the status of account '{username}'.", log_file)


# Function to add a new user account interactively
def add_user_account(log_file, username=None):
    if not username:
        username = input("Enter the username: ")

    home_directory = input(f"Enter home directory for {username}: ")
    full_name = input(f"Enter full name for {username}: ")
    password = input(f"Enter password for {username}: ")
    expiration_date = input(f"Enter expiration date for {username} (YYYY-MM-DD) or leave blank for no expiration: ")

    # Add the user using useradd
    try:
        subprocess.run(["useradd", "-m", "-d", home_directory, "-c", full_name, username], check=True)
        if password:
            subprocess.run(f"echo {username}:{password} | chpasswd", shell=True, check=True)
        if expiration_date:
            subprocess.run(["chage", "-E", expiration_date, username], check=True)
        
        # Force password reset on first login
        subprocess.run(["chage", "-d", "0", username], check=True)
        
        log_message(f"Account '{username}' created.", log_file)
    except subprocess.CalledProcessError as e:
        log_message(f"Error creating account '{username}': {e}", log_file)


# Function to change expiration date for a user
def change_expiration_date(username, expiration_date, log_file):
    if username == "root":
        log_message("Cannot change expiration date for root user.", log_file)
        return
    try:
        subprocess.run(["chage", "-E", expiration_date, username], check=True)
        log_message(f"Expiration date for '{username}' set to {expiration_date}.", log_file)
    except subprocess.CalledProcessError as e:
        log_message(f"Failed to change expiration date for '{username}': {e}", log_file)


def main():
    parser = argparse.ArgumentParser(description="Administer user accounts.")
    parser.add_argument("action", choices=["report-no-password", "report-expired", "report-expiration", 
                                           "report-non-expiring", "lock", "unlock", "add-user", "change-expiration"],
                        help="Action to perform.")
    parser.add_argument("--log", required=True, help="Path to the log file.")
    parser.add_argument("--username", help="Username for locking/unlocking or changing expiration date.")
    parser.add_argument("--expiration-date", help="Expiration date for user in YYYY-MM-DD format.")
    parser.add_argument("--file", help="File containing a list of usernames for user creation.")
    
    args = parser.parse_args()

    if args.action == "report-no-password":
        report_no_password_users(args.log)
    elif args.action == "report-expired":
        report_expired_accounts(args.log)
    elif args.action == "report-expiration":
        report_expiration_dates(args.log)
    elif args.action == "report-non-expiring":
        report_non_expiring_accounts(args.log)
    elif args.action == "lock":
        if not args.username:
            print("Username is required to lock an account.")
            sys.exit(1)
        lock_unlock_account(args.username, lock=True, log_file=args.log)
    elif args.action == "unlock":
        if not args.username:
            print("Username is required to unlock an account.")
            sys.exit(1)
        lock_unlock_account(args.username, lock=False, log_file=args.log)
    elif args.action == "add-user":
        if not args.username and not args.file:
            print("Username or file is required to add a user.")
            sys.exit(1)
        if args.username:
            add_user_account(args.log, args.username)
        elif args.file:
            with open(args.file, "r") as f:
                for line in f:
                    username = line.strip()
                    add_user_account(args.log, username)
    elif args.action == "change-expiration":
        if not args.username or not args.expiration_date:
            print("Username and expiration date are required.")
            sys.exit(1)
        change_expiration_date(args.username, args.expiration_date, args.log)

if __name__ == "__main__":
    main()

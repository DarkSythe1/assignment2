#!/bin/sh

# Function to log actions
log_action() {
    local message="$1"
    local log_file="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$log_file"
}

# Function to report users with no password
report_no_password() {
    echo "Users without passwords:"
    for user in $(cut -d: -f1 /etc/passwd); do
        if ! sudo passwd -S "$user" | grep -q ' P'; then
            echo "$user"
            sudo usermod -L "$user" # Lock the account
            log_action "Account for $user locked due to no password" "$log_file"
        fi
    done
}

# Function to report expired accounts
report_expired_accounts() {
    echo "Expired accounts:"
    for user in $(cut -d: -f1 /etc/passwd); do
        if sudo chage -l "$user" | grep -q 'Account expires'; then
            expiry_date=$(sudo chage -l "$user" | grep 'Account expires' | cut -d: -f2 | xargs)
            if [[ "$expiry_date" != "never" && $(date -d "$expiry_date" +%s) -lt $(date +%s) ]]; then
                echo "$user expired on $expiry_date"
            fi
        fi
    done
}

# Function to report account expiration dates
report_expiration_dates() {
    echo "Expiration dates for all users:"
    for user in $(cut -d: -f1 /etc/passwd); do
        if sudo chage -l "$user" | grep -q 'Account expires'; then
            expiry_date=$(sudo chage -l "$user" | grep 'Account expires' | cut -d: -f2 | xargs)
            echo "$user expires on $expiry_date"
        fi
    done
}

# Function to report accounts without expiration
report_no_expiration() {
    echo "Accounts without expiration:"
    for user in $(cut -d: -f1 /etc/passwd); do
        if sudo chage -l "$user" | grep -q 'Account expires'; then
            expiry_date=$(sudo chage -l "$user" | grep 'Account expires' | cut -d: -f2 | xargs)
            if [[ "$expiry_date" == "never" ]]; then
                echo "$user"
            fi
        fi
    done
}

# Function to lock/unlock a user account
lock_unlock_account() {
    local action="$1"
    local user="$2"
    if [ "$action" == "lock" ]; then
        sudo usermod -L "$user"
        log_action "Account $user locked" "$log_file"
    elif [ "$action" == "unlock" ]; then
        sudo usermod -U "$user"
        log_action "Account $user unlocked" "$log_file"
    else
        echo "Invalid action. Use 'lock' or 'unlock'."
        exit 1
    fi
}

# Function to add a new user
add_user() {
    local user_file="$1"
    while IFS=, read -r username homedir fullname password expiration; do
        if [[ "$username" != "root" ]]; then
            sudo useradd -m -d "$homedir" -c "$fullname" "$username"
            echo "$username:$password" | sudo chpasswd
            sudo chage -E "$expiration" "$username"
            sudo chage -d 0 "$username"  # Force password reset on first login
            log_action "Added user $username with expiration $expiration" "$log_file"
        else
            echo "Cannot add root user."
        fi
    done < "$user_file"
}

# Function to change user expiration date
change_expiration_date() {
    local user="$1"
    local expiration="$2"
    if [ "$user" != "root" ]; then
        sudo chage -E "$expiration" "$user"
        log_action "Changed expiration for user $user to $expiration" "$log_file"
    else
        echo "Root account cannot have an expiration date."
        exit 1
    fi
}

# Main script logic
if [ $# -lt 2 ]; then
    echo "Usage: $0 <command> <options>"
    echo "Commands:"
    echo "  report_no_password"
    echo "  report_expired_accounts"
    echo "  report_expiration_dates"
    echo "  report_no_expiration"
    echo "  lock_account <username>"
    echo "  unlock_account <username>"
    echo "  add_user <user_file>"
    echo "  change_expiration <username> <expiration_date>"
    exit 1
fi

command="$1"
log_file="$2"

case "$command" in
    report_no_password)
        report_no_password
        log_action "Reported users with no passwords" "$log_file"
        ;;
    report_expired_accounts)
        report_expired_accounts
        log_action "Reported expired accounts" "$log_file"
        ;;
    report_expiration_dates)
        report_expiration_dates
        log_action "Reported expiration dates" "$log_file"
        ;;
    report_no_expiration)
        report_no_expiration
        log_action "Reported accounts with no expiration" "$log_file"
        ;;
    lock_account)
        if [ $# -ne 3 ]; then
            echo "Usage: $0 lock_account <username>"
            exit 1
        fi
        lock_unlock_account "lock" "$3"
        ;;
    unlock_account)
        if [ $# -ne 3 ]; then
            echo "Usage: $0 unlock_account <username>"
            exit 1
        fi
        lock_unlock_account "unlock" "$3"
        ;;
    add_user)
        if [ $# -ne 3 ]; then
            echo "Usage: $0 add_user <user_file>"
            exit 1
        fi
        add_user "$3"
        ;;
    change_expiration)
        if [ $# -ne 4 ]; then
            echo "Usage: $0 change_expiration <username> <expiration_date>"
            exit 1
        fi
        change_expiration_date "$3" "$4"
        ;;
    *)
        echo "Invalid command: $command"
        exit 1
        ;;
esac

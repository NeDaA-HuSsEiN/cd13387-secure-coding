#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>  // For sleep
#include <time.h>    // For tracking lockout time
#include "hash_utils.h"

#define MAX_LINE_LENGTH 200
#define MAX_USERNAME_LENGTH 50
#define MAX_PASSWORD_LENGTH 50
#define MAX_COMMAND_LENGTH 50
#define MAX_HASH_LENGTH 65
#define SALT_LENGTH 2
#define LOCKOUT_THRESHOLD 3
#define LOCKOUT_DURATION 5  // in seconds

#define FILE_USERS "hashed_users.txt"

// Function to trim newline characters
void trim_newline(char* str) {
    char* pos;
    if ((pos = strchr(str, '\n')) != NULL)
        *pos = '\0';
}

// Function to update the user's failed attempts count in hashed_users.txt
void update_failed_attempts(const char* username, int attempts) {
    FILE* file = fopen(FILE_USERS, "r+");
    if (!file) {
        printf("Could not open %s\n", FILE_USERS);
        return;
    }

    char line[MAX_LINE_LENGTH];
    long position;
    while ((position = ftell(file)), fgets(line, sizeof(line), file)) {
        trim_newline(line);

        char file_username[MAX_USERNAME_LENGTH];
        char file_salt[SALT_LENGTH * 2 + 1];
        char file_hashed_password[MAX_HASH_LENGTH];
        int file_attempts;

        // Parse line into fields
        sscanf(line, "%[^:]:%[^:]:%[^:]:%d", file_username, file_salt, file_hashed_password, &file_attempts);

        if (strcmp(username, file_username) == 0) {
            fseek(file, position, SEEK_SET);
            fprintf(file, "%s:%s:%s:%d\n", file_username, file_salt, file_hashed_password, attempts);
            break;
        }
    }

    fclose(file);
}

// Function to check if username and password match an entry in hashed_users.txt
int check_login(const char* username, const char* password) {
    FILE* file = fopen(FILE_USERS, "r");
    if (file == NULL) {
        printf("Could not open %s\n", FILE_USERS);
        return 0;
    }

    char line[MAX_LINE_LENGTH];
    char file_username[MAX_USERNAME_LENGTH];
    char file_hashed_password[MAX_HASH_LENGTH];
    char file_salt[SALT_LENGTH * 2 + 1];
    char salt_bytes[SALT_LENGTH];
    int failed_attempts;

    while (fgets(line, sizeof(line), file)) {
        trim_newline(line);

        sscanf(line, "%[^:]:%[^:]:%[^:]:%d", file_username, file_salt, file_hashed_password, &failed_attempts);

        if (strcmp(username, file_username) == 0) {
            if (failed_attempts >= LOCKOUT_THRESHOLD) {
                fclose(file);
                return -1;  // User is locked out
            }

            // Convert salt to bytes
            hex_to_bytes(file_salt, strlen(file_salt), salt_bytes);

            // Hash the input password with the stored salt
            char hashed_input[MAX_HASH_LENGTH];
            hash_password(password, salt_bytes, hashed_input);

            // Compare hashed input with the stored hashed password
            if (strcmp(hashed_input, file_hashed_password) == 0) {
                fclose(file);
                return 1;  // Login successful
            } else {
                fclose(file);
                return 0;  // Login failed, but not locked out
            }
        }
    }

    fclose(file);
    return 0;  // Login failed, user not found
}

void lockout_check(const char* username, int* attempts, time_t* last_attempt_time) {
    time_t current_time = time(NULL);

    if (*attempts >= LOCKOUT_THRESHOLD) {
        double time_elapsed = difftime(current_time, *last_attempt_time);

        if (time_elapsed < LOCKOUT_DURATION) {
            printf("Account locked. Try again in %d seconds.\n", LOCKOUT_DURATION - (int)time_elapsed);
            sleep(LOCKOUT_DURATION - (int)time_elapsed);
        }
        
        *attempts = LOCKOUT_THRESHOLD;  // Keep threshold in file if already locked
    } else {
        *last_attempt_time = current_time;
    }
}

int main() {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    char command[MAX_COMMAND_LENGTH];
    int attempts = 0;
    time_t last_attempt_time = 0;

    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    trim_newline(username);

    while (1) {
        printf("Enter password: ");
        fgets(password, sizeof(password), stdin);
        trim_newline(password);

        lockout_check(username, &attempts, &last_attempt_time);

        int login_result = check_login(username, password);

        if (login_result == 1) {
            printf("Login successful!\n");
            update_failed_attempts(username, 0);  // Reset attempts on success
            break;
        } else if (login_result == -1) {
            printf("Account is temporarily locked. Please wait.\n");
            lockout_check(username, &attempts, &last_attempt_time);
        } else {
            printf("Login failed.\n");
            attempts++;
            update_failed_attempts(username, attempts);
            last_attempt_time = time(NULL);
        }
    }

    return 0;
}

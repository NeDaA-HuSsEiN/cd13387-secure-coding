#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "hash_utils.h"

#define MAX_LINE_LENGTH 200
#define MAX_USERNAME_LENGTH 50
#define MAX_PASSWORD_LENGTH 50
#define MAX_COMMAND_LENGTH 50
#define MAX_HASH_LENGTH 65
#define SALT_LENGTH 2
#define MAX_FAILED_ATTEMPTS 3
#define LOCKOUT_TIME 5  // 5 seconds

#define FILE_USERS "hashed_users.txt"

// Function to trim newline characters
void trim_newline(char* str) {
    char* pos;
    if ((pos = strchr(str, '\n')) != NULL)
        *pos = '\0';
}

// Function to update the hashed_users.txt file with the counter value after login attempts
void update_failed_attempts(const char* username, int failed_attempts) {
    FILE* file = fopen(FILE_USERS, "r+");
    if (file == NULL) {
        printf("Could not open %s for updating\n", FILE_USERS);
        return;
    }

    char line[MAX_LINE_LENGTH];
    long pos;

    while ((pos = ftell(file)) >= 0 && fgets(line, sizeof(line), file)) {
        trim_newline(line);

        char file_username[MAX_USERNAME_LENGTH];
        char file_salt[SALT_LENGTH];
        char file_hashed_password[MAX_HASH_LENGTH];

        sscanf(line, "%[^:]", file_username);

        if (strcmp(username, file_username) == 0) {
            fseek(file, pos, SEEK_SET);
            fprintf(file, "%s:%s:%s:%d\n", file_username, file_salt, file_hashed_password, failed_attempts);
            break;
        }
    }

    fclose(file);
}


// Function to check if username and password match an entry in users.txt
int check_login(const char* username, const char* password) {

    FILE* file = fopen(FILE_USERS, "r");
    if (file == NULL) {
        printf("Could not open users.txt\n");
        return 0;
    }

    char line[MAX_LINE_LENGTH];
    char file_username[MAX_USERNAME_LENGTH];
    char file_hashed_password[MAX_HASH_LENGTH];
    char file_salt[SALT_LENGTH * 2 + 1];
    char salt_bytes[SALT_LENGTH];
    int failed_attempts;

    while (fgets(line, sizeof(line), file)) {
        // Remove the newline character
        trim_newline(line);

        sscanf(line, "%[^:]:%[^:]:%[^:]:%d", file_username, file_salt, file_hashed_password, &failed_attempts);

        if (strcmp(username, file_username) == 0) {
            if (failed_attempts >= MAX_FAILED_ATTEMPTS) {
                printf("Account is locked. Please wait %d seconds.\n", LOCKOUT_TIME);
                sleep(LOCKOUT_TIME);
                failed_attempts = 0;
                update_failed_attempts(username, failed_attempts);
            }

            // Convert salt to bytes
            hex_to_bytes(file_salt, strlen(file_salt), salt_bytes);

            char hashed_input[MAX_HASH_LENGTH];
            hash_password(password, salt_bytes, hashed_input);
       
            if (strcmp(hashed_input, file_hashed_password) == 0) {
                update_failed_attempts(username, 0);  // Reset failed attempts after a successful login
                fclose(file);
                return 1;  // Login successful
            } else {
                failed_attempts++;
                update_failed_attempts(username, failed_attempts);
                printf("Login failed. Attempt %d/%d\n", failed_attempts, MAX_FAILED_ATTEMPTS);
            }
        }
    }

    fclose(file);
    return 0;  // Login failed
}

int main() {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    char command[MAX_COMMAND_LENGTH];

    // Prompt user for username and password
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    trim_newline(username);  // Remove newline character

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    trim_newline(password);  // Remove newline character

    // Check login credentials
    if (check_login(username, password)) {
        printf("Login successful!\n");

        // Command prompt loop
        while (1) {
            printf("> ");
            scanf("%s", command);

            if (strcmp(command, "exit") == 0) {
                break;
            } else {
                printf("Unknown command.\nAllowed command is exit.\n");
            }
        }
    } else {
        printf("Login failed.\n");
    }

    return 0;
}
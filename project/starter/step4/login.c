#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> 
#include "hash_utils.h"

#define MAX_LINE_LENGTH 200
#define MAX_USERNAME_LENGTH 50
#define MAX_PASSWORD_LENGTH 50
#define MAX_COMMAND_LENGTH 50
#define MAX_HASH_LENGTH 65
#define SALT_LENGTH 2
#define LOCKOUT_THRESHOLD 3
#define LOCKOUT_TIMEOUT 5  // in seconds

#define FILE_USERS "hashed_users.txt"

// Function to trim newline characters
void trim_newline(char* str) {
    char* pos;
    if ((pos = strchr(str, '\n')) != NULL)
        *pos = '\0';
}

// Function to update a specific user's row
void overwrite_last_section_for_user(char* line, const char* target_username, int new_value) {
    // Copy the line to avoid modifying the original
    char line_copy[MAX_LINE_LENGTH];
    strcpy(line_copy, line);

    // Get the username from the line
    char* token = strtok(line_copy, ":");
    if (token == NULL) return;

    // Check if the username matches the target
    if (strcmp(token, target_username) == 0) {
        // Find the last occurrence of the delimiter in the original line
        char* last_delim = strrchr(line, ":");
        
        if (last_delim != NULL) {
            // Move past the last delimiter and overwrite with new integer value
            last_delim++;
            sprintf(last_delim, "%d", new_value);
        }
    }
}

// Function to update the user's failed attempts count in hashed_users.txt
void update_failed_attempts(const char* username, int attempts) {

    FILE *file = fopen(FILE_USERS, "r");
    if (file == NULL) {
        printf("Could not open the file.\n");
        return;
    }

    // Temporary file to store modified lines
    FILE *temp_file = fopen("temp.txt", "w");
    if (temp_file == NULL) {
        printf("Could not open the temporary file.\n");
        fclose(file);
        return;
    }

    char line[MAX_LINE_LENGTH];

    // Read each line from the file
    while (fgets(line, sizeof(line), file) != NULL) {
        // Remove newline character at the end of the line
        trim_newline(line);

        // Update only the target user's row
        overwrite_last_section_for_user(line, username, attempts);

        // Write the (possibly modified) line to the temporary file
        fprintf(temp_file, "%s\n", line);
    }

    // Close both files
    fclose(file);
    fclose(temp_file);

    // Replace the original file with the temporary file
    remove(FILE_USERS);
    rename("temp.txt", FILE_USERS);
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

    while (fgets(line, sizeof(line), file)) {
        // Remove the newline character
        trim_newline(line);

        // Split the line into username, salt, and hashed password
        char* token = strtok(line, ":");
        if (token != NULL) {
            strcpy(file_username, token);
            token = strtok(NULL, ":");
            if (token != NULL) {
                strcpy(file_salt, token);
                token = strtok(NULL, ":");
                
                if (token != NULL) {
                    strcpy(file_hashed_password, token);
                }
            }
        }

        // Compare entered username and password with the file's values
        if (strcmp(username, file_username) == 0) {

            // Convert salt to bytes
            hex_to_bytes(file_salt, strlen(file_salt), salt_bytes);

           // Hash the input password with the stored salt
            char hashed_input[MAX_HASH_LENGTH];
            hash_password(password, salt_bytes, hashed_input);
  
            // Compare hashed input with the stored hashed password
            if (strcmp(hashed_input, file_hashed_password) == 0) {
                fclose(file);
                return 1;  // Login successful
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
    int fail_attempts = 0;
    int exit_flag = 0;
    
    while(1){
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
            fail_attempts = 0;
            update_failed_attempts(username, fail_attempts);

            // Command prompt loop
            while (1) {
                printf("> ");
                scanf("%s", command);

                if (strcmp(command, "exit") == 0) {
                    exit_flag = 1;
                    break;
                } else {
                    printf("Unknown command.\nAllowed command is exit.\n");
                }
            }
        } else {
            printf("Login failed.\n");
            fail_attempts++;
            update_failed_attempts(username, fail_attempts);

            if(fail_attempts >= LOCKOUT_THRESHOLD)
            {
                printf("Account is temporarily locked. Please wait.\n");
                sleep(LOCKOUT_TIMEOUT);
            }
        }
        
        if(exit_flag)
        {
            break;
        }
    }

    return 0;
}
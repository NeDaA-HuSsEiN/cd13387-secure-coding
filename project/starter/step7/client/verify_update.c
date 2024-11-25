/******************************************************************************

                            Online C Compiler.
                Code, Compile, Run and Debug C program online.
Write your code in this editor and press "Run" button to compile and execute it.

*******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#define CERT_FILE "software_update.crt"
#define CA_CERT_FILE "rootCA.crt"
#define SIGNATURE_FILE "software_update.sig"
#define UPDATE_FILE "software_update.bin"
#define CHECKSUM_FILE "software_update.checksum"

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// Function to verify the certificate
int verify_certificate(const char *cert_file, const char *ca_cert_file) {
    FILE *ca_file = fopen(ca_cert_file, "r");
    FILE *cert_to_verify = fopen(cert_file, "r");
    if (!ca_file || !cert_to_verify) {
        perror("Error opening certificate file");
        return 0;
    }

    X509 *ca_cert = PEM_read_X509(ca_file, NULL, NULL, NULL);
    X509 *cert = PEM_read_X509(cert_to_verify, NULL, NULL, NULL);

    fclose(ca_file);
    fclose(cert_to_verify);

    if (!ca_cert || !cert) {
        handle_openssl_error();
    }

    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    X509_STORE_add_cert(store, ca_cert);
    X509_STORE_CTX_init(ctx, store, cert, NULL);

    int result = X509_verify_cert(ctx);
    X509_free(ca_cert);
    X509_free(cert);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    return result;
}

// Function to verify the signature
int verify_signature(const char *update_file, const char *signature_file, const char *cert_file) {
    FILE *cert_fp = fopen(cert_file, "r");
    FILE *sig_fp = fopen(signature_file, "rb");
    FILE *update_fp = fopen(update_file, "rb");

    if (!cert_fp || !sig_fp || !update_fp) {
        perror("Error opening file");
        return 0;
    }

    // Read the certificate and extract the public key
    X509 *cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    EVP_PKEY *public_key = X509_get_pubkey(cert);

    // Read the signature
    fseek(sig_fp, 0, SEEK_END);
    size_t sig_len = ftell(sig_fp);
    fseek(sig_fp, 0, SEEK_SET);
    unsigned char *signature = malloc(sig_len);
    fread(signature, 1, sig_len, sig_fp);

    // Hash the update file
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);

    unsigned char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), update_fp)) > 0) {
        SHA256_Update(&sha_ctx, buffer, bytes_read);
    }
    SHA256_Final(hash, &sha_ctx);

    // Verify the signature
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pkey_ctx = NULL;

    EVP_DigestVerifyInit(md_ctx, &pkey_ctx, EVP_sha256(), NULL, public_key);
    int result = EVP_DigestVerify(md_ctx, signature, sig_len, hash, SHA256_DIGEST_LENGTH);

    // Clean up
    EVP_MD_CTX_free(md_ctx);
    X509_free(cert);
    EVP_PKEY_free(public_key);
    free(signature);
    fclose(cert_fp);
    fclose(sig_fp);
    fclose(update_fp);

    return result;
}

// Function to verify the checksum
int verify_checksum(const char *update_file, const char *checksum_file) {
    FILE *fp = fopen(checksum_file, "r");
    if (!fp) {
        perror("Error opening checksum file");
        return 0;
    }

    char expected_checksum[SHA256_DIGEST_LENGTH * 2 + 1];
    fscanf(fp, "%64s", expected_checksum);
    fclose(fp);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);

    FILE *update_fp = fopen(update_file, "rb");
    if (!update_fp) {
        perror("Error opening update file");
        return 0;
    }

    unsigned char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), update_fp)) > 0) {
        SHA256_Update(&sha_ctx, buffer, bytes_read);
    }
    SHA256_Final(hash, &sha_ctx);
    fclose(update_fp);

    char calculated_checksum[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&calculated_checksum[i * 2], "%02x", hash[i]);
    }

    return strcmp(expected_checksum, calculated_checksum) == 0;
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Verify certificate
    printf("Verifying certificate...\n");
    if (!verify_certificate(CERT_FILE, CA_CERT_FILE)) {
        fprintf(stderr, "Certificate verification failed!\n");
        return EXIT_FAILURE;
    }
    printf("Certificate verified successfully.\n");

    // Verify signature
    printf("Verifying digital signature...\n");
    if (!verify_signature(UPDATE_FILE, SIGNATURE_FILE, CERT_FILE)) {
        fprintf(stderr, "Digital signature verification failed!\n");
        return EXIT_FAILURE;
    }
    printf("Digital signature verified successfully.\n");

    // Verify checksum
    printf("Verifying checksum...\n");
    if (!verify_checksum(UPDATE_FILE, CHECKSUM_FILE)) {
        fprintf(stderr, "Checksum verification failed!\n");
        return EXIT_FAILURE;
    }
    printf("Checksum verified successfully.\n");

    printf("Software update is valid.\n");

    return EXIT_SUCCESS;
}

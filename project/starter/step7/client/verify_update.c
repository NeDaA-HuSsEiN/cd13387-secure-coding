#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

// Macro to check conditions and print errors
#define CHECK(condition, message) \
    if (!(condition)) { \
        fprintf(stderr, "Error: %s\n", message); \
        ERR_print_errors_fp(stderr); \
        exit(EXIT_FAILURE); \
    }

// Helper function to print OpenSSL errors
void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// Verify if a certificate is signed by the root CA
int verify_certificate(const char *root_ca_crt, const char *cert_file) {
    // Open and load the root CA certificate
    FILE *root_fp = fopen(root_ca_crt, "r");
    CHECK(root_fp != NULL, "Failed to open root CA certificate file.");
    X509 *root_cert = PEM_read_X509(root_fp, NULL, NULL, NULL);
    fclose(root_fp);
    CHECK(root_cert != NULL, "Failed to parse root CA certificate.");

    // Open and load the software update certificate
    FILE *cert_fp = fopen(cert_file, "r");
    CHECK(cert_fp != NULL, "Failed to open software update certificate file.");
    X509 *cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    fclose(cert_fp);
    CHECK(cert != NULL, "Failed to parse software update certificate.");

    // Set up a store to hold the root CA and verify the certificate
    X509_STORE *store = X509_STORE_new();
    CHECK(store != NULL, "Failed to create X509_STORE.");
    CHECK(X509_STORE_add_cert(store, root_cert) == 1, "Failed to add root CA to X509_STORE.");

    // Create and initialize a verification context
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    CHECK(ctx != NULL, "Failed to create X509_STORE_CTX.");
    CHECK(X509_STORE_CTX_init(ctx, store, cert, NULL) == 1, "Failed to initialize X509_STORE_CTX.");

    // Verify the certificate
    int result = X509_verify_cert(ctx);

    // Clean up and free resources
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(root_cert);
    X509_free(cert);

    return result == 1;  // Return 1 if verification succeeded
}

// Verify the signature of the binary file using the certificate's public key
int verify_signature(const char *crt_file, const char *sig_file, const char *bin_file) {
    // Open and load the certificate
    FILE *crt_fp = fopen(crt_file, "r");
    CHECK(crt_fp != NULL, "Failed to open certificate file.");
    X509 *cert = PEM_read_X509(crt_fp, NULL, NULL, NULL);
    fclose(crt_fp);
    CHECK(cert != NULL, "Failed to parse certificate.");

    // Extract the public key from the certificate
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    CHECK(pubkey != NULL, "Failed to extract public key from certificate.");
    X509_free(cert);

    // Read the signature file into memory
    FILE *sig_fp = fopen(sig_file, "rb");
    CHECK(sig_fp != NULL, "Failed to open signature file.");
    fseek(sig_fp, 0, SEEK_END);
    size_t sig_len = ftell(sig_fp);
    fseek(sig_fp, 0, SEEK_SET);
    unsigned char *sig = malloc(sig_len);
    CHECK(sig != NULL, "Failed to allocate memory for signature.");
    fread(sig, 1, sig_len, sig_fp);
    fclose(sig_fp);

    // Open the binary file for reading
    FILE *bin_fp = fopen(bin_file, "rb");
    CHECK(bin_fp != NULL, "Failed to open binary file.");

    // Hash the binary file using SHA256
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    CHECK(hash_ctx != NULL, "Failed to create hash context.");
    CHECK(EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL) == 1, "Failed to initialize hash context.");

    unsigned char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), bin_fp)) > 0) {
        CHECK(EVP_DigestUpdate(hash_ctx, buffer, bytes_read) == 1, "Failed to update hash.");
    }
    fclose(bin_fp);
    CHECK(EVP_DigestFinal_ex(hash_ctx, hash, &hash_len) == 1, "Failed to finalize hash.");
    EVP_MD_CTX_free(hash_ctx);

    // Verify the signature against the hash
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    CHECK(md_ctx != NULL, "Failed to create EVP_MD_CTX.");
    int result = EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pubkey) == 1 &&
                 EVP_DigestVerify(md_ctx, sig, sig_len, hash, hash_len) == 1;

    // Clean up resources
    free(sig);
    EVP_PKEY_free(pubkey);
    EVP_MD_CTX_free(md_ctx);

    return result;  // Return 1 if verification succeeded
}

// Verify the checksum of the binary file
int verify_checksum(const char *bin_file, const char *checksum_file) {
    // Open the binary file for hashing
    FILE *bin_fp = fopen(bin_file, "rb");
    CHECK(bin_fp != NULL, "Failed to open binary file.");

    // Open the checksum file for comparison
    FILE *checksum_fp = fopen(checksum_file, "r");
    CHECK(checksum_fp != NULL, "Failed to open checksum file.");

    // Compute the hash of the binary file
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    CHECK(md_ctx != NULL, "Failed to create hash context.");
    CHECK(EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) == 1, "Failed to initialize hash context.");

    unsigned char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), bin_fp)) > 0) {
        CHECK(EVP_DigestUpdate(md_ctx, buffer, bytes_read) == 1, "Failed to update hash.");
    }
    fclose(bin_fp);
    CHECK(EVP_DigestFinal_ex(md_ctx, hash, &hash_len) == 1, "Failed to finalize hash.");
    EVP_MD_CTX_free(md_ctx);

    // Read the expected checksum from the file
    char expected_checksum[65];
    fscanf(checksum_fp, "%64s", expected_checksum);
    fclose(checksum_fp);

    // Convert the computed hash to a string
    char actual_checksum[65];
    for (int i = 0; i < hash_len; ++i) {
        sprintf(&actual_checksum[i * 2], "%02x", hash[i]);
    }

    // Compare the computed checksum with the expected checksum
    return strcmp(expected_checksum, actual_checksum) == 0;
}

// Main function to verify the software update
int main() {
    const char *root_ca_crt = "rootCA.crt";
    const char *update_crt = "received_package/software_update.crt";
    const char *update_sig = "received_package/software_update.sig";
    const char *update_bin = "received_package/software_update.bin";
    const char *update_checksum = "received_package/software_update.checksum";

    // Load OpenSSL libraries
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    printf("Verifying software update...\n");

    // Verify the certificate is signed by the root CA
    CHECK(verify_certificate(root_ca_crt, update_crt), "Certificate verification failed.");
    printf("Certificate verified successfully.\n");

    // Verify the signature of the binary
    CHECK(verify_signature(update_crt, update_sig, update_bin), "Signature verification failed.");
    printf("Signature verified successfully.\n");

    // Verify the checksum of the binary
    CHECK(verify_checksum(update_bin, update_checksum), "Checksum verification failed.");
    printf("Checksum verified successfully.\n");

    printf("Software update is valid.\n");

    return 0;
}

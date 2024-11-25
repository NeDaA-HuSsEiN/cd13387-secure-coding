#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define CHECK(condition, message) \
    if (!(condition)) { \
        fprintf(stderr, "Error: %s\n", message); \
        ERR_print_errors_fp(stderr); \
        exit(EXIT_FAILURE); \
    }

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int verify_signature(const char *crt_file, const char *sig_file, const char *bin_file) {
    FILE *crt_fp = fopen(crt_file, "r");
    CHECK(crt_fp != NULL, "Failed to open certificate file.");

    X509 *cert = PEM_read_X509(crt_fp, NULL, NULL, NULL);
    fclose(crt_fp);
    CHECK(cert != NULL, "Failed to parse certificate.");

    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    CHECK(pubkey != NULL, "Failed to extract public key from certificate.");
    X509_free(cert);

    FILE *sig_fp = fopen(sig_file, "rb");
    CHECK(sig_fp != NULL, "Failed to open signature file.");
    fseek(sig_fp, 0, SEEK_END);
    size_t sig_len = ftell(sig_fp);
    fseek(sig_fp, 0, SEEK_SET);

    unsigned char *sig = malloc(sig_len);
    CHECK(sig != NULL, "Failed to allocate memory for signature.");
    fread(sig, 1, sig_len, sig_fp);
    fclose(sig_fp);

    FILE *bin_fp = fopen(bin_file, "rb");
    CHECK(bin_fp != NULL, "Failed to open binary file.");

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    CHECK(md_ctx != NULL, "Failed to create EVP_MD_CTX.");

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

    CHECK(EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pubkey) == 1, "Failed to initialize signature verification.");
    EVP_PKEY_free(pubkey);

    int result = EVP_DigestVerify(md_ctx, sig, sig_len, hash, hash_len);
    free(sig);
    EVP_MD_CTX_free(md_ctx);

    return result == 1;
}

int verify_checksum(const char *bin_file, const char *checksum_file) {
    FILE *bin_fp = fopen(bin_file, "rb");
    CHECK(bin_fp != NULL, "Failed to open binary file.");

    FILE *checksum_fp = fopen(checksum_file, "r");
    CHECK(checksum_fp != NULL, "Failed to open checksum file.");

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

    char expected_checksum[65];
    fscanf(checksum_fp, "%64s", expected_checksum);
    fclose(checksum_fp);

    char actual_checksum[65];
    for (int i = 0; i < hash_len; ++i) {
        sprintf(&actual_checksum[i * 2], "%02x", hash[i]);
    }

    return strcmp(expected_checksum, actual_checksum) == 0;
}

int main() {
    const char *root_ca_crt = "rootCA.crt";
    const char *update_crt = "software_update.crt";
    const char *update_sig = "software_update.sig";
    const char *update_bin = "software_update.bin";
    const char *update_checksum = "software_update.checksum";

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    printf("Verifying software update...\n");

    CHECK(verify_signature(update_crt, update_sig, update_bin), "Signature verification failed.");
    printf("Signature verified successfully.\n");

    CHECK(verify_checksum(update_bin, update_checksum), "Checksum verification failed.");
    printf("Checksum verified successfully.\n");

    printf("Software update is valid.\n");

    return 0;
}

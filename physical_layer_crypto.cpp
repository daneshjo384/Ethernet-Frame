#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define BUFFER_SIZE 65536
#define AES_KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16

// Encryption function with AES-GCM
bool encrypt_aes_gcm(const unsigned char* plaintext, int plaintext_len,
    const unsigned char* key, const unsigned char* iv,
    unsigned char* ciphertext, unsigned char* tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;

    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Decode function
bool decrypt_aes_gcm(const unsigned char* ciphertext, int ciphertext_len,
    const unsigned char* key, const unsigned char* iv,
    const unsigned char* tag, unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;

    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

int main() {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // encryption key (must be kept safe in practice)
    unsigned char key[AES_KEY_SIZE];
    RAND_bytes(key, AES_KEY_SIZE);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char encrypted_buffer[BUFFER_SIZE];
    unsigned char decrypted_buffer[BUFFER_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char tag[TAG_SIZE];

    std::cout << "[+] Physical Layer Crypto Started\n";

    while (true) {
        int bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (bytes < 0) {
            perror("Recv failed");
            continue;
        }
        // Create a random IV
        RAND_bytes(iv, IV_SIZE);

        // Encryption
        if (encrypt_aes_gcm(buffer, bytes, key, iv, encrypted_buffer, tag)) {
            std::cout << "[+] Encrypted " << bytes << " bytes\n";

            // Here you can send the packet through another socket
            // sendto(sock, encrypted_buffer, bytes, 0, ...);
        }

        // decode (for testing)
        if (decrypt_aes_gcm(encrypted_buffer, bytes, key, iv, tag, decrypted_buffer)) {
            std::cout << "[+] Decrypted " << bytes << " bytes\n";
        }
    }

    close(sock);
    return 0;
}
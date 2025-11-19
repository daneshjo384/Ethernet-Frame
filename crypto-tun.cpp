#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <netinet/in.h>
#include <thread>
#include <atomic>

#define AES_KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16
#define BUFFER_SIZE 65536

// fixed key (in practice, DH or shared key should be used)
static const unsigned char static_key[AES_KEY_SIZE] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

// AES-256-GCM encryption function
bool encrypt_aes_gcm(const unsigned char* plaintext, int plaintext_len,
    unsigned char* ciphertext, unsigned char* iv, unsigned char* tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto err;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, static_key, iv) != 1) goto err;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) goto err;
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) goto err;
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) goto err;

    EVP_CIPHER_CTX_free(ctx);
    return true;

err:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}

// Decode function
bool decrypt_aes_gcm(const unsigned char* ciphertext, int ciphertext_len,
    const unsigned char* iv, const unsigned char* tag,
    unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto err;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, static_key, iv) != 1) goto err;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag) != 1) goto err;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) goto err;
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) goto err;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;

err:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}

// Create TUN Interface
int create_tun(const char* dev_name) {
    struct ifreq ifr;
    int fd;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // IP only, no additional headers
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, (void*)&ifr) < 0) {
        perror("ioctl TUNSETIFF");
        close(fd);
        return -1;
    }

    std::cout << "[+] TUN interface " << dev_name << " created.\n";
    return fd;
}

// Send encrypted packet to destination (with UDP)
void send_encrypted_packet(int udp_sock, const unsigned char* encrypted, int enc_len,
    const char* dst_ip, int dst_port) {
    struct sockaddr_in dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(dst_port);
    inet_pton(AF_INET, dst_ip, &dst_addr.sin_addr);

    sendto(udp_sock, encrypted, enc_len, 0,
        (struct sockaddr*)&dst_addr, sizeof(dst_addr));
}

// Receive the packet from the network and decode it
void receive_and_decrypt(int udp_sock, int tun_fd, std::atomic<bool>& running) {
    unsigned char buffer[BUFFER_SIZE];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    while (running) {
        int bytes = recvfrom(udp_sock, buffer, BUFFER_SIZE, 0,
            (struct sockaddr*)&src_addr, &addr_len);
        if (bytes <= 0) continue;

        if (bytes < IV_SIZE + TAG_SIZE + 1) {
            std::cerr << "[-] Invalid packet size\n";
            continue;
        }

        // Separate IV, TAG, and encrypted data
        unsigned char iv[IV_SIZE];
        unsigned char tag[TAG_SIZE];
        unsigned char ciphertext[bytes - IV_SIZE - TAG_SIZE];
        int ciphertext_len = bytes - IV_SIZE - TAG_SIZE;

        memcpy(iv, buffer, IV_SIZE);
        memcpy(tag, buffer + IV_SIZE, TAG_SIZE);
        memcpy(ciphertext, buffer + IV_SIZE + TAG_SIZE, ciphertext_len);

        // Decode
        unsigned char plaintext[BUFFER_SIZE];
        if (decrypt_aes_gcm(ciphertext, ciphertext_len, iv, tag, plaintext)) {
            write(tun_fd, plaintext, ciphertext_len);
            std::cout << "[+] Decrypted and forwarded to TUN: " << ciphertext_len << " bytes\n";
        }
        else {
            std::cerr << "[-] Decryption failed\n";
        }
    }
}

// Send packet from TUN to network
void forward_from_tun(int tun_fd, int udp_sock, const char* dst_ip, int dst_port,
    std::atomic<bool>& running) {
    unsigned char buffer[BUFFER_SIZE];

    while (running) {
        int bytes = read(tun_fd, buffer, BUFFER_SIZE);
        if (bytes <= 0) continue;

        // Generate random IV
        unsigned char iv[IV_SIZE];
        RAND_bytes(iv, IV_SIZE);

        // Encryption
        unsigned char ciphertext[BUFFER_SIZE];
        unsigned char tag[TAG_SIZE];
        if (!encrypt_aes_gcm(buffer, bytes, ciphertext, iv, tag)) {
            std::cerr << "[-] Encryption failed\n";
            continue;
        }

        // Final package: IV + TAG + ciphertext
        unsigned char final_packet[IV_SIZE + TAG_SIZE + BUFFER_SIZE];
        int packet_len = IV_SIZE + TAG_SIZE + bytes;

        memcpy(final_packet, iv, IV_SIZE);
        memcpy(final_packet + IV_SIZE, tag, TAG_SIZE);
        memcpy(final_packet + IV_SIZE + TAG_SIZE, ciphertext, bytes);

        send_encrypted_packet(udp_sock, final_packet, packet_len, dst_ip, dst_port);
        std::cout << "[+] Encrypted and sent: " << bytes << " bytes\n";
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <tun_name> <peer_ip>\n";
        std::cerr << "Example: " << argv[0] << " tun0 192.168.1.100\n";
        return 1;
    }

    const char* tun_name = argv[1];
    const char* peer_ip = argv[2];
    const int peer_port = 9000;

    // Need root
    if (geteuid() != 0) {
        std::cerr << "[-] This program must be run as root!\n";
        return 1;
    }

    // Create TUN
    int tun_fd = create_tun(tun_name);
    if (tun_fd < 0) return 1;

    // Create UDP socket for encrypted sending
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("socket");
        close(tun_fd);
        return 1;
    }

    std::atomic<bool> running(true);

    // receive function (decrypt)
    std::thread recv_thread(receive_and_decrypt, udp_sock, tun_fd, std::ref(running));

    // send function (encrypt)
    std::thread send_thread(forward_from_tun, tun_fd, udp_sock, peer_ip, peer_port, std::ref(running));

    std::cout << "[+] Crypto TUN started. Press Ctrl+C to stop.\n";

    // Establish network connection
    // Run the following commands in the other terminal:
    // sudo ip addr add 10.0.0.1/24 dev tun0
    // sudo ip link set tun0 up
    // sudo route add -net 10.0.0.0/24 dev tun0

   // Wait for Ctrl+C
    signal(SIGINT, [](int) { running = false; });

    recv_thread.join();
    send_thread.join();

    close(tun_fd);
    close(udp_sock);
    std::cout << "\n[+] Stopped.\n";
    return 0;
}
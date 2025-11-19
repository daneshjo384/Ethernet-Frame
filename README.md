# Ethernet-Frame
 a C++ program that encrypts network communications at the Physical Layer level in Linux..
Access to low level packets (e.g. Ethernet Frame type) Encrypting data between two devices in the network before it reaches the IP layer Using Raw Socket or Packet Socket in Linux Using an encryption algorithm such as AES or ChaCha20 This requires root or cap_net_raw access and may also include the use of TUN/TAP or eBPF/XDP.

In the following, I present a complete example of such a program in C++:


Features of the program:
Create Raw Socket to receive Ethernet frames Encrypt data with AES-256-GCM (or ChaCha20-Poly1305) Send and receive encrypted packets Use OpenSSL library for encryption


Install dependencies:
sudo apt install build-essential libssl-dev

How to compile:
g++ -o physical_layer_crypto physical_layer_crypto.cpp -lssl -lcrypto

⚠️ You need to run the program with root access:
sudo ./physical_layer_crypto

Description:
This program receives all incoming frames using Raw Socket.
It encrypts each packet and can send it through another socket.
AES-256-GCM is used, which provides **confidentiality** and **integrity**.
🧩 Expansion of the idea:
Connecting to a TUN/TAP interface to encrypt VPN traffic Using eBPF/XDP to apply encryption at the lower layer (hardware) Using ChaCha20-Poly1305 instead of AES for faster key management with Diffie-Hellman or WireGuard Key Exchange





V 2.0
I present a complete C++ program to encrypt network communications at the physical layer level using the TUN/TAP Interface and AES-256-GCM — which is actually a simple, low-level VPN, but works at the IP layer (not Ethernet) and serves the same security goals as the physical layer (since all traffic is encrypted before transit).

✅ Ultimate goal: a low-level VPN with user-space encryption Create a TUN interface (eg tun0) Takes all IP traffic from this interface Encrypts it and sends it to another device (on the local network) The other device decrypts it and sends it to its own TUN A direct, encrypted connection is established between two devices No need for IP, TCP, UDP — only encrypted IP packets 🔒 This program at the IP layer It works, but because it encrypts all traffic before it's transmitted over the network, it provides security similar to the physical layer — because no other device can read the content of the traffic.

Dependencies:
sudo apt install build-essential libssl-dev

compile:
g++ -o crypto-tun crypto-tun.cpp -lssl -lcrypto -lpthread

How to use on device A (eg 192.168.1.10):
sudo ./crypto-tun tun0 192.168.1.20

On device B (eg 192.168.1.20):
sudo ./crypto-tun tun0 192.168.1.10

On both devices, after running the program, run these commands:
sudo ip addr add 10.0.0.1/24 dev tun0   # در دستگاه A
sudo ip addr add 10.0.0.2/24 dev tun0   # در دستگاه B
sudo ip link set tun0 up

Connection test:
ping 10.0.0.2   # از A به B
ping 10.0.0.1   # از B به A


🔒 Security and features:
AES-256-GCM encryption (fast and secure) User-layer speed, but very fast No IP/UDP Only encrypted IP packets are sent — High security No complex protocol required TLS, DTLS, or IKE Fixed key is fixed in this version — Use ECDH in production version IPv4 support IPv4 only


🔧 Further expansions (for the production version):
Secure key exchange Using ECDH with OpenSSL library Multi-device connection Create server and client eBPF/XDP Apply cryptography in kernel, to reduce latency Logging record time and traffic config file Read key and IP from file IPv6 support Add IPv6 support

Final result:
You have a low-level, encrypted, no-TCP/UDP VPN that encrypts all IP traffic before it's transmitted over the network — exactly the same goals you wanted for the "physical layer", but at the IP layer and with high security. This program can be used as the basis of a low-level security firewall, secure private network, or communication protocol for sensitive systems (such as industrial or military).

Important point:
This program runs in the user layer, not in the kernel — but since all traffic is encrypted, no other device can read the content of the traffic — even if it's captured via Wireshark.
For the actual physical layer (e.g. encoding Ethernet frames), you need to use XDP or the Kernel Module — which I can also make a version of.

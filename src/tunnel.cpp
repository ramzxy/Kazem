#include "tunnel.h"
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#ifdef __APPLE__
// macOS specific headers
#include <net/if.h>
#include <net/if_utun.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#elif defined(__linux__)
// Linux specific headers
#include <linux/if.h>
#include <linux/if_tun.h>
#endif

// Constructor - initialize the tunnel
Tunnel::Tunnel(std::shared_ptr<Connection> connection, 
               std::shared_ptr<Encryption> encryption)
    : connection_(connection),
      encryption_(encryption),
      tun_fd_(-1),
      running_(false),
      bytes_sent_(0),
      bytes_received_(0),
      packets_sent_(0),
      packets_received_(0) {
    
    std::cout << "Tunnel object initialized" << std::endl;
}

// Destructor - ensure clean shutdown
Tunnel::~Tunnel() {
    // Stop the tunnel if it's running
    if (running_) {
        stop();
    }
    
    // Close the TUN device if it's open
    if (tun_fd_ >= 0) {
        close(tun_fd_);
        tun_fd_ = -1;
    }
    
    std::cout << "Tunnel object destroyed" << std::endl;
}

// Start the VPN tunnel
bool Tunnel::start() {
    // Check if the tunnel is already running
    if (running_) {
        std::cerr << "Tunnel is already running" << std::endl;
        return false;
    }
    
    // Check if we have a valid connection
    if (!connection_ || !connection_->is_connected()) {
        std::cerr << "No valid connection to VPN server" << std::endl;
        return false;
    }
    
    // Step 1: Create a TUN interface
    // For educational purposes, we'll use a simplified approach
    // In a real VPN client, this would involve platform-specific code
    tun_fd_ = create_tun_interface("vpn0");
    if (tun_fd_ < 0) {
        std::cerr << "Failed to create TUN interface" << std::endl;
        return false;
    }
    
    std::cout << "Created TUN interface with fd: " << tun_fd_ << std::endl;
    
    // Step 2: Configure routing
    // This would set up the system to route traffic through our VPN
    if (!configure_routing()) {
        std::cerr << "Failed to configure routing" << std::endl;
        close(tun_fd_);
        tun_fd_ = -1;
        return false;
    }
    
    std::cout << "Configured routing for VPN tunnel" << std::endl;
    
    // Step 3: Start the tunnel
    running_ = true;
    
    // Step 4: Start the worker threads
    // These threads will handle the actual packet processing
    tun_to_server_thread_ = std::thread(&Tunnel::tun_to_server_worker, this);
    server_to_tun_thread_ = std::thread(&Tunnel::server_to_tun_worker, this);
    
    std::cout << "VPN tunnel started" << std::endl;
    return true;
}

// Stop the VPN tunnel
void Tunnel::stop() {
    // Check if the tunnel is running
    if (!running_) {
        return;
    }
    
    // Step 1: Signal the worker threads to stop
    running_ = false;
    
    // Step 2: Wait for the worker threads to finish
    if (tun_to_server_thread_.joinable()) {
        tun_to_server_thread_.join();
    }
    
    if (server_to_tun_thread_.joinable()) {
        server_to_tun_thread_.join();
    }
    
    // Step 3: Close the TUN device
    if (tun_fd_ >= 0) {
        close(tun_fd_);
        tun_fd_ = -1;
    }
    
    std::cout << "VPN tunnel stopped" << std::endl;
}

// Check if the tunnel is active
bool Tunnel::is_active() const {
    return running_ && tun_fd_ >= 0 && connection_ && connection_->is_connected();
}

// Get statistics about the tunnel
std::string Tunnel::get_stats() const {
    std::string stats = "VPN Tunnel Statistics:\n";
    stats += "  Running: " + std::string(running_ ? "Yes" : "No") + "\n";
    stats += "  Bytes sent: " + std::to_string(bytes_sent_) + "\n";
    stats += "  Bytes received: " + std::to_string(bytes_received_) + "\n";
    stats += "  Packets sent: " + std::to_string(packets_sent_) + "\n";
    stats += "  Packets received: " + std::to_string(packets_received_) + "\n";
    
    return stats;
}

// Create a TUN/TAP virtual network interface
int Tunnel::create_tun_interface(const std::string& name) {
    // This is a simplified implementation for educational purposes
    // In a real VPN client, this would be platform-specific
    
    #ifdef __APPLE__
    // macOS implementation (simplified)
    // On macOS, we use the utun kernel control interface
    
    // Step 1: Create a PF_SYSTEM socket for communicating with the kernel
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        std::cerr << "Failed to create control socket" << std::endl;
        return -1;
    }
    
    // Step 2: Connect to the utun control device
    struct ctl_info ctlInfo;
    memset(&ctlInfo, 0, sizeof(ctlInfo));
    strncpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name));
    
    if (ioctl(fd, CTLIOCGINFO, &ctlInfo) < 0) {
        std::cerr << "Failed to get utun control info" << std::endl;
        close(fd);
        return -1;
    }
    
    // Step 3: Connect to the first available utun device
    struct sockaddr_ctl sc;
    memset(&sc, 0, sizeof(sc));
    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.sc_unit = 0; // This will create utun0, 1 for utun1, etc.
    
    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
        std::cerr << "Failed to connect to utun device" << std::endl;
        close(fd);
        return -1;
    }
    
    std::cout << "Created utun device" << std::endl;
    return fd;
    
    #elif defined(__linux__)
    // Linux implementation (simplified)
    // On Linux, we use the /dev/net/tun device
    
    // Step 1: Open the TUN/TAP device
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        std::cerr << "Failed to open /dev/net/tun" << std::endl;
        return -1;
    }
    
    // Step 2: Set up the TUN device
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN device, no packet info
    strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ);
    
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        std::cerr << "Failed to set TUN device parameters" << std::endl;
        close(fd);
        return -1;
    }
    
    std::cout << "Created TUN device: " << name << std::endl;
    return fd;
    
    #else
    // Unsupported platform
    std::cerr << "TUN/TAP not implemented for this platform" << std::endl;
    return -1;
    #endif
}

// Configure the system routing table
bool Tunnel::configure_routing() {
    // This is a simplified implementation for educational purposes
    // In a real VPN client, this would involve executing system commands
    // to modify the routing table
    
    // For educational purposes, we'll just pretend this works
    std::cout << "Note: In a real VPN client, this would configure the system's routing table" << std::endl;
    std::cout << "      to route traffic through the VPN tunnel." << std::endl;
    std::cout << "      This typically involves:" << std::endl;
    std::cout << "      1. Setting the default route to go through the TUN interface" << std::endl;
    std::cout << "      2. Adding routes for the VPN server to bypass the tunnel" << std::endl;
    std::cout << "      3. Configuring DNS servers" << std::endl;
    
    // In a real implementation, we would run commands like:
    // - On Linux: ip route add ... or route add ...
    // - On macOS: route add ...
    // - On Windows: route add ... or netsh interface ip add route ...
    
    return true;
}

// Thread function for processing packets from TUN to server
void Tunnel::tun_to_server_worker() {
    std::cout << "Started TUN to server worker thread" << std::endl;
    
    // Buffer for reading packets from the TUN interface
    std::vector<uint8_t> buffer(2048);
    
    while (running_) {
        // Step 1: Read a packet from the TUN interface
        ssize_t bytes_read = read(tun_fd_, buffer.data(), buffer.size());
        
        if (bytes_read <= 0) {
            // Error or no data
            if (bytes_read < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                std::cerr << "Error reading from TUN: " << strerror(errno) << std::endl;
            }
            
            // Sleep a bit to avoid busy-waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        
        // Step 2: Process the outgoing packet
        // This includes encapsulation and encryption
        std::vector<uint8_t> packet(buffer.begin(), buffer.begin() + bytes_read);
        
        if (!process_outgoing_packet(packet)) {
            std::cerr << "Failed to process outgoing packet" << std::endl;
            continue;
        }
        
        // Update statistics
        bytes_sent_ += bytes_read;
        packets_sent_++;
        
        #ifdef DEBUG_MODE
        std::cout << "Sent packet of " << bytes_read << " bytes to server" << std::endl;
        #endif
    }
    
    std::cout << "TUN to server worker thread stopped" << std::endl;
}

// Thread function for processing packets from server to TUN
void Tunnel::server_to_tun_worker() {
    std::cout << "Started server to TUN worker thread" << std::endl;
    
    // Buffer for reading packets from the server
    std::vector<uint8_t> buffer(2048);
    
    while (running_) {
        // Step 1: Read a packet from the server
        int bytes_read = connection_->receive_data(buffer.data(), buffer.size());
        
        if (bytes_read <= 0) {
            // Error or no data
            if (bytes_read < 0) {
                std::cerr << "Error reading from server" << std::endl;
            }
            
            // Sleep a bit to avoid busy-waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        
        // Step 2: Process the incoming packet
        // This includes decryption and de-encapsulation
        std::vector<uint8_t> packet(buffer.begin(), buffer.begin() + bytes_read);
        
        if (!process_incoming_packet(packet)) {
            std::cerr << "Failed to process incoming packet" << std::endl;
            continue;
        }
        
        // Update statistics
        bytes_received_ += bytes_read;
        packets_received_++;
        
        #ifdef DEBUG_MODE
        std::cout << "Received packet of " << bytes_read << " bytes from server" << std::endl;
        #endif
    }
    
    std::cout << "Server to TUN worker thread stopped" << std::endl;
}

// Process a packet from the local system
bool Tunnel::process_outgoing_packet(const std::vector<uint8_t>& packet) {
    try {
        // Step 1: Analyze the packet (for educational purposes)
        // In a real VPN, we might need to modify the packet headers
        #ifdef DEBUG_MODE
        if (packet.size() >= 20) {  // Minimum IPv4 header size
            // Extract some basic information from the IPv4 header
            uint8_t version = (packet[0] >> 4) & 0xF;
            uint8_t ihl = packet[0] & 0xF;
            uint16_t total_length = (packet[2] << 8) | packet[3];
            uint8_t protocol = packet[9];
            uint32_t src_ip = (packet[12] << 24) | (packet[13] << 16) | (packet[14] << 8) | packet[15];
            uint32_t dst_ip = (packet[16] << 24) | (packet[17] << 16) | (packet[18] << 8) | packet[19];
            
            std::cout << "Outgoing packet: IPv" << (int)version 
                      << ", Protocol: " << (int)protocol
                      << ", Length: " << total_length
                      << ", Src IP: " << ((src_ip >> 24) & 0xFF) << "."
                                      << ((src_ip >> 16) & 0xFF) << "."
                                      << ((src_ip >> 8) & 0xFF) << "."
                                      << (src_ip & 0xFF)
                      << ", Dst IP: " << ((dst_ip >> 24) & 0xFF) << "."
                                      << ((dst_ip >> 16) & 0xFF) << "."
                                      << ((dst_ip >> 8) & 0xFF) << "."
                                      << (dst_ip & 0xFF)
                      << std::endl;
        }
        #endif
        
        // Step 2: Encrypt the packet
        // In a real VPN, we would also add a header with sequence numbers, etc.
        std::vector<uint8_t> encrypted_packet = encryption_->encrypt(packet);
        
        if (encrypted_packet.empty()) {
            std::cerr << "Failed to encrypt packet" << std::endl;
            return false;
        }
        
        // Step 3: Send the encrypted packet to the server
        int bytes_sent = connection_->send_data(encrypted_packet.data(), encrypted_packet.size());
        
        if (bytes_sent < 0) {
            std::cerr << "Failed to send packet to server" << std::endl;
            return false;
        }
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error processing outgoing packet: " << e.what() << std::endl;
        return false;
    }
}

// Process a packet from the VPN server
bool Tunnel::process_incoming_packet(const std::vector<uint8_t>& packet) {
    try {
        // Step 1: Decrypt the packet
        std::vector<uint8_t> decrypted_packet = encryption_->decrypt(packet);
        
        if (decrypted_packet.empty()) {
            std::cerr << "Failed to decrypt packet" << std::endl;
            return false;
        }
        
        // Step 2: Analyze the packet (for educational purposes)
        #ifdef DEBUG_MODE
        if (decrypted_packet.size() >= 20) {  // Minimum IPv4 header size
            // Extract some basic information from the IPv4 header
            uint8_t version = (decrypted_packet[0] >> 4) & 0xF;
            uint8_t ihl = decrypted_packet[0] & 0xF;
            uint16_t total_length = (decrypted_packet[2] << 8) | decrypted_packet[3];
            uint8_t protocol = decrypted_packet[9];
            uint32_t src_ip = (decrypted_packet[12] << 24) | (decrypted_packet[13] << 16) | 
                              (decrypted_packet[14] << 8) | decrypted_packet[15];
            uint32_t dst_ip = (decrypted_packet[16] << 24) | (decrypted_packet[17] << 16) | 
                              (decrypted_packet[18] << 8) | decrypted_packet[19];
            
            std::cout << "Incoming packet: IPv" << (int)version 
                      << ", Protocol: " << (int)protocol
                      << ", Length: " << total_length
                      << ", Src IP: " << ((src_ip >> 24) & 0xFF) << "."
                                      << ((src_ip >> 16) & 0xFF) << "."
                                      << ((src_ip >> 8) & 0xFF) << "."
                                      << (src_ip & 0xFF)
                      << ", Dst IP: " << ((dst_ip >> 24) & 0xFF) << "."
                                      << ((dst_ip >> 16) & 0xFF) << "."
                                      << ((dst_ip >> 8) & 0xFF) << "."
                                      << (dst_ip & 0xFF)
                      << std::endl;
        }
        #endif
        
        // Step 3: Write the decrypted packet to the TUN interface
        ssize_t bytes_written = write(tun_fd_, decrypted_packet.data(), decrypted_packet.size());
        
        if (bytes_written < 0) {
            std::cerr << "Failed to write packet to TUN: " << strerror(errno) << std::endl;
            return false;
        }
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error processing incoming packet: " << e.what() << std::endl;
        return false;
    }
} 
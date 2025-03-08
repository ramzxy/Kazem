#ifndef TUNNEL_H
#define TUNNEL_H

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <boost/asio.hpp>
#include "connection.h"
#include "encryption.h"

/**
 * @class Tunnel
 * @brief Creates and manages the VPN tunnel
 * 
 * The Tunnel class is responsible for:
 * 1. Creating a virtual network interface (TUN/TAP)
 * 2. Routing traffic between the local system and the VPN server
 * 3. Encapsulating and encrypting packets
 * 4. Managing the tunnel lifecycle
 * 
 * This is the core of the VPN client functionality.
 */
class Tunnel {
public:
    /**
     * @brief Constructor - initializes the tunnel
     * @param connection The connection to the VPN server
     * @param encryption The encryption system for securing traffic
     * 
     * Sets up the tunnel but doesn't start it yet.
     */
    Tunnel(std::shared_ptr<Connection> connection, 
           std::shared_ptr<Encryption> encryption);
    
    /**
     * @brief Destructor - ensures clean shutdown
     */
    ~Tunnel();
    
    /**
     * @brief Start the VPN tunnel
     * @return true if tunnel started successfully
     * 
     * This method:
     * 1. Creates a virtual network interface
     * 2. Sets up routing
     * 3. Starts the packet processing threads
     */
    bool start();
    
    /**
     * @brief Stop the VPN tunnel
     * 
     * Stops all packet processing and cleans up resources.
     */
    void stop();
    
    /**
     * @brief Check if the tunnel is active
     * @return true if tunnel is running
     */
    bool is_active() const;
    
    /**
     * @brief Get statistics about the tunnel
     * @return A string containing tunnel statistics
     * 
     * Statistics include bytes sent/received, packets processed, etc.
     */
    std::string get_stats() const;

private:
    // Connection to the VPN server
    std::shared_ptr<Connection> connection_;
    
    // Encryption system
    std::shared_ptr<Encryption> encryption_;
    
    // Virtual network interface file descriptor
    int tun_fd_;
    
    // Tunnel state
    std::atomic<bool> running_;
    
    // Worker threads
    std::thread tun_to_server_thread_;
    std::thread server_to_tun_thread_;
    
    // Statistics
    std::atomic<uint64_t> bytes_sent_;
    std::atomic<uint64_t> bytes_received_;
    std::atomic<uint64_t> packets_sent_;
    std::atomic<uint64_t> packets_received_;
    
    /**
     * @brief Create a TUN/TAP virtual network interface
     * @param name Name for the interface
     * @return File descriptor for the interface, or -1 on error
     * 
     * This creates a virtual network interface that can be used
     * to capture and inject network packets.
     */
    int create_tun_interface(const std::string& name);
    
    /**
     * @brief Configure the system routing table
     * @return true if routing was configured successfully
     * 
     * This sets up the system to route traffic through the VPN tunnel.
     */
    bool configure_routing();
    
    /**
     * @brief Thread function for processing packets from TUN to server
     * 
     * This function:
     * 1. Reads packets from the TUN interface
     * 2. Encrypts them
     * 3. Sends them to the VPN server
     */
    void tun_to_server_worker();
    
    /**
     * @brief Thread function for processing packets from server to TUN
     * 
     * This function:
     * 1. Receives encrypted packets from the VPN server
     * 2. Decrypts them
     * 3. Writes them to the TUN interface
     */
    void server_to_tun_worker();
    
    /**
     * @brief Process a packet from the local system
     * @param packet The raw packet data
     * @return true if processing was successful
     * 
     * This handles the encapsulation and encryption of outgoing packets.
     */
    bool process_outgoing_packet(const std::vector<uint8_t>& packet);
    
    /**
     * @brief Process a packet from the VPN server
     * @param packet The encrypted packet data
     * @return true if processing was successful
     * 
     * This handles the decryption and de-encapsulation of incoming packets.
     */
    bool process_incoming_packet(const std::vector<uint8_t>& packet);
};

#endif // TUNNEL_H 
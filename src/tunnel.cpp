#include "tunnel.h"
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>       // For strerror, memset, strncpy
#include <string>        // For string operations
#include <cstdlib>       // For system()
#include <cstdio>        // For popen, pclose, FILE operations
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <cerrno>        // For errno
#include <netinet/in.h>  // For htonl

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
#elif defined(_WIN32) || defined(_WIN64)
// Windows specific headers
#include <windows.h>
#include <winioctl.h>
// You'll need the TAP-Windows driver headers
// These are typically available from the OpenVPN project
#include "tap-windows.h"  // Contains TAP_WIN_IOCTL_* definitions
#endif

Tunnel::Tunnel(std::shared_ptr<Connection> connection,
               std::shared_ptr<Encryption> encryption)
    : connection_(connection),
      encryption_(encryption),
      tun_fd_(-1),
      running_(false),
      bytes_sent_(0),
      bytes_received_(0),
      packets_sent_(0),
      packets_received_(0),
      original_gateway_(""),
      original_interface_("")
    {
    std::cout << "Tunnel object initialized" << std::endl;
}

Tunnel::~Tunnel()
{
    if (running_)
    {
        stop();
    }

    if (tun_fd_ >= 0)
    {
        close(tun_fd_);
        tun_fd_ = -1;
    }

    std::cout << "Tunnel object destroyed" << std::endl;
}

bool Tunnel::start()
{
    if (running_)
    {
        std::cerr << "Tunnel is already running" << std::endl;
        return false;
    }

    if (!connection_ || !connection_->is_connected())
    {
        std::cerr << "No valid connection to VPN server" << std::endl;
        return false;
    }

    tun_fd_ = create_tun_interface("vpn0");
    if (tun_fd_ < 0)
    {
        std::cerr << "Failed to create TUN interface" << std::endl;
        return false;
    }

    std::cout << "Created TUN interface with fd: " << tun_fd_ << std::endl;

    if (!configure_routing())
    {
        std::cerr << "Failed to configure routing" << std::endl;
        close(tun_fd_);
        tun_fd_ = -1;
        return false;
    }

    std::cout << "Configured routing for VPN tunnel" << std::endl;

    running_ = true;

    tun_to_server_thread_ = std::thread(&Tunnel::tun_to_server_worker, this);
    server_to_tun_thread_ = std::thread(&Tunnel::server_to_tun_worker, this);

    std::cout << "VPN tunnel started" << std::endl;
    return true;
}

void Tunnel::stop()
{
    if (!running_)
    {
        return;
    }

    std::cout << "Stopping VPN tunnel..." << std::endl;

    // Step 1: Signal the worker threads to stop
    running_ = false;

    // Step 2: Wait for the worker threads to finish
    if (tun_to_server_thread_.joinable())
    {
        tun_to_server_thread_.join();
    }

    if (server_to_tun_thread_.joinable())
    {
        server_to_tun_thread_.join();
    }

    // Step 3: Restore original routing
    restore_routing();

    // Step 4: Close the TUN device
    if (tun_fd_ >= 0)
    {
        close(tun_fd_);
        tun_fd_ = -1;
    }

    std::cout << "VPN tunnel stopped" << std::endl;
}

bool Tunnel::is_active() const
{
    return running_ && tun_fd_ >= 0 && connection_ && connection_->is_connected();
}

// Get statistics about the tunnel
std::string Tunnel::get_stats() const
{
    std::string stats = "VPN Tunnel Statistics:\n";
    stats += "  Running: " + std::string(running_ ? "Yes" : "No") + "\n";
    stats += "  Bytes sent: " + std::to_string(bytes_sent_) + "\n";
    stats += "  Bytes received: " + std::to_string(bytes_received_) + "\n";
    stats += "  Packets sent: " + std::to_string(packets_sent_) + "\n";
    stats += "  Packets received: " + std::to_string(packets_received_) + "\n";

    return stats;
}

// Create a TUN/TAP virtual network interface
int Tunnel::create_tun_interface(const std::string &name) {
    // This method creates a virtual network interface that allows our application
    // to capture and inject network packets. The implementation is highly platform-specific.
    
#if defined(_WIN32) || defined(_WIN64)
    // ==================== WINDOWS IMPLEMENTATION ====================
    
    // Windows requires the TAP-Windows driver to be installed
    // This driver creates virtual network adapters that user-mode applications can use
    
    // Step 1: Include necessary Windows headers
    #include <windows.h>
    #include <winioctl.h>
    #include <string>
    
    // TAP-Windows Control IOCTL codes - these would normally come from tap-windows.h
    // but we define them here for completeness
    #define TAP_WIN_IOCTL_GET_MAC               CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define TAP_WIN_IOCTL_GET_VERSION           CTL_CODE(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define TAP_WIN_IOCTL_GET_MTU               CTL_CODE(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define TAP_WIN_IOCTL_GET_INFO              CTL_CODE(FILE_DEVICE_UNKNOWN, 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT CTL_CODE(FILE_DEVICE_UNKNOWN, 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define TAP_WIN_IOCTL_SET_MEDIA_STATUS      CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define TAP_WIN_IOCTL_CONFIG_DHCP_MASQ      CTL_CODE(FILE_DEVICE_UNKNOWN, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define TAP_WIN_IOCTL_GET_LOG_LINE          CTL_CODE(FILE_DEVICE_UNKNOWN, 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT   CTL_CODE(FILE_DEVICE_UNKNOWN, 9, METHOD_BUFFERED, FILE_ANY_ACCESS)
    
    // Step 2: Find the TAP-Windows adapter
    // In a real implementation, we would enumerate network adapters to find TAP devices
    // For simplicity, we'll use a hardcoded device path, but this should be dynamic
    
    // Format for TAP-Windows device paths: \\.\Global\{GUID}.tap
    // We'll try to open a few common device paths
    std::vector<std::string> possible_devices = {
        "\\\\.\\Global\\MyTapDevice",                  // Custom name
        "\\\\.\\Global\\{6F85B048-0CE2-4426-A254-95C917D9D9C3}.tap", // Example GUID
        "\\\\.\\Global\\tap0",                         // OpenVPN default
        "\\\\.\\tap0"                                  // Alternative format
    };
    
    HANDLE handle = INVALID_HANDLE_VALUE;
    
    for (const auto& device_path : possible_devices) {
        // Try to open the device
        handle = CreateFileA(
            device_path.c_str(),                  // Device path
            GENERIC_READ | GENERIC_WRITE,         // Read/write access
            0,                                    // No sharing
            NULL,                                 // Default security attributes
            OPEN_EXISTING,                        // Open existing device
            FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, // For async I/O
            NULL                                  // No template file
        );
        
        if (handle != INVALID_HANDLE_VALUE) {
            std::cout << "Successfully opened TAP device: " << device_path << std::endl;
            break;
        }
    }
    
    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open any TAP device. Error code: " << GetLastError() << std::endl;
        std::cerr << "Make sure the TAP-Windows driver is installed." << std::endl;
        return -1;
    }
    
    // Step 3: Set the TAP adapter to TUN mode (IP packets only)
    DWORD status = 1;  // 1 = TAP adapter enabled
    DWORD bytesReturned;
    
    if (!DeviceIoControl(
            handle,
            TAP_WIN_IOCTL_SET_MEDIA_STATUS,      // Control code
            &status, sizeof(status),             // Input buffer
            &status, sizeof(status),             // Output buffer
            &bytesReturned,                      // Bytes returned
            NULL                                 // Overlapped
        )) {
        std::cerr << "Failed to set TAP device status. Error code: " << GetLastError() << std::endl;
        CloseHandle(handle);
        return -1;
    }
    
    // Step 4: Configure the TAP adapter with an IP address
    // This sets up a point-to-point connection between the TAP adapter and our application
    
    // IP configuration: local IP = 10.8.0.1, remote IP = 10.8.0.2
    // Format: [local IP (4 bytes)][remote IP (4 bytes)]
    uint32_t ip_config[2];
    ip_config[0] = htonl(0x0A080001);  // 10.8.0.1
    ip_config[1] = htonl(0x0A080002);  // 10.8.0.2
    
    if (!DeviceIoControl(
            handle,
            TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT, // Control code
            ip_config, sizeof(ip_config),        // Input buffer
            ip_config, sizeof(ip_config),        // Output buffer
            &bytesReturned,                      // Bytes returned
            NULL                                 // Overlapped
        )) {
        std::cerr << "Failed to configure TAP device IP. Error code: " << GetLastError() << std::endl;
        CloseHandle(handle);
        return -1;
    }
    
    std::cout << "Successfully configured TAP device with IP 10.8.0.1" << std::endl;
    
    // Convert Windows HANDLE to int for compatibility with the rest of the code
    // Note: This is a simplification and has limitations on 64-bit systems
    return reinterpret_cast<intptr_t>(handle);
    
#elif defined(__APPLE__)
    // ==================== MACOS IMPLEMENTATION ====================
    
    // macOS uses the utun kernel control interface for creating TUN devices
    // This is a different approach from Linux or Windows
    
    // Step 1: Create a PF_SYSTEM socket for communicating with the kernel
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        std::cerr << "Failed to create control socket: " << strerror(errno) << std::endl;
        return -1;
    }
    
    // Step 2: Connect to the utun control device
    // First, we need to get the control ID for the utun device
    struct ctl_info ctlInfo;
    memset(&ctlInfo, 0, sizeof(ctlInfo));
    
    // UTUN_CONTROL_NAME is defined in <net/if_utun.h> as "com.apple.net.utun_control"
    strncpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name));
    
    // Get the control ID using ioctl
    if (ioctl(fd, CTLIOCGINFO, &ctlInfo) < 0) {
        std::cerr << "Failed to get utun control info: " << strerror(errno) << std::endl;
        close(fd);
        return -1;
    }
    
    // Step 3: Connect to a specific utun unit
    // We'll try to connect to utun0, utun1, etc. until we find an available one
    struct sockaddr_ctl sc;
    memset(&sc, 0, sizeof(sc));
    sc.sc_family = AF_SYSTEM;
    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_len = sizeof(sc);
    
    // Try to connect to utun0, utun1, etc.
    int unit = 0;
    int max_attempts = 10;  // Try up to utun9
    
    for (unit = 0; unit < max_attempts; unit++) {
        sc.sc_unit = unit + 1;  // utun devices start at 1, not 0
        
        if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) == 0) {
            break;  // Successfully connected
        }
        
        // If the error is "Device busy", try the next unit
        if (errno != EBUSY) {
            std::cerr << "Failed to connect to utun" << unit << ": " << strerror(errno) << std::endl;
            close(fd);
            return -1;
        }
    }
    
    if (unit >= max_attempts) {
        std::cerr << "Failed to find an available utun device after " << max_attempts << " attempts" << std::endl;
        close(fd);
        return -1;
    }
    
    // Step 4: Get the interface name
    // On macOS, the interface name is utunX where X is the unit number
    std::string if_name = "utun" + std::to_string(unit);
    std::cout << "Created TUN interface: " << if_name << std::endl;
    
    // Step 5: Configure the interface with an IP address
    // On macOS, we use the ifconfig command to set the IP address
    // In a real implementation, we would use the SIOCAIFADDR ioctl
    
    // Set the interface up with IP 10.8.0.1 and point-to-point to 10.8.0.2
    std::string cmd = "ifconfig " + if_name + " 10.8.0.1 10.8.0.2 up";
    int result = system(cmd.c_str());
    
    if (result != 0) {
        std::cerr << "Failed to configure TUN interface IP address" << std::endl;
        close(fd);
        return -1;
    }
    
    std::cout << "Successfully configured " << if_name << " with IP 10.8.0.1" << std::endl;
    
    // Return the file descriptor
    return fd;
    
#elif defined(__linux__)
    // ==================== LINUX IMPLEMENTATION ====================
    
    // Linux uses the /dev/net/tun device for creating TUN/TAP interfaces
    
    // Step 1: Open the TUN/TAP device
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        std::cerr << "Failed to open /dev/net/tun: " << strerror(errno) << std::endl;
        return -1;
    }
    
    // Step 2: Set up the TUN device
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    
    // Set the flags: IFF_TUN for a TUN device (IP packets)
    // IFF_NO_PI to not include packet information
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    
    // Set the device name if specified
    if (!name.empty()) {
        strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    }
    
    // Create the TUN device with our parameters
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        std::cerr << "Failed to set TUN device parameters: " << strerror(errno) << std::endl;
        close(fd);
        return -1;
    }
    
    // Get the actual device name (might be different if we didn't specify one)
    std::string if_name = ifr.ifr_name;
    std::cout << "Created TUN device: " << if_name << std::endl;
    
    // Step 3: Configure the interface with an IP address
    // On Linux, we use the ip command to set the IP address
    // In a real implementation, we would use the SIOCSIFADDR ioctl
    
    // Set the interface up with IP 10.8.0.1
    std::string cmd = "ip addr add 10.8.0.1/24 dev " + if_name;
    int result = system(cmd.c_str());
    
    if (result != 0) {
        std::cerr << "Failed to set TUN interface IP address" << std::endl;
        // We don't close the fd here because the interface was created successfully
        // The caller can decide what to do
    }
    
    // Set the interface up
    cmd = "ip link set dev " + if_name + " up";
    result = system(cmd.c_str());
    
    if (result != 0) {
        std::cerr << "Failed to bring up TUN interface" << std::endl;
        // Again, we don't close the fd here
    } else {
        std::cout << "Successfully configured " << if_name << " with IP 10.8.0.1" << std::endl;
    }
    
    // Return the file descriptor
    return fd;
    
#else
    // ==================== UNSUPPORTED PLATFORM ====================
    std::cerr << "TUN/TAP not implemented for this platform" << std::endl;
    return -1;
#endif
}

// Configure the system routing table
bool Tunnel::configure_routing()
{
    std::cout << "Configuring routing tables to use VPN tunnel..." << std::endl;
    
    // Store the original default gateway for restoration when the VPN disconnects
    std::string original_gateway;
    std::string vpn_gateway = "10.8.0.2"; // The VPN tunnel endpoint on our side
    std::string vpn_server_ip = connection_->server_ip_; // Get the VPN server's IP
    
#if defined(_WIN32) || defined(_WIN64)
    // ==================== WINDOWS IMPLEMENTATION ====================
    
    // Step 1: Get the current default gateway (to be restored later)
    FILE* pipe = _popen("route print 0.0.0.0 mask 0.0.0.0", "r");
    if (!pipe) {
        std::cerr << "Failed to execute route command" << std::endl;
        return false;
    }
    
    char buffer[256];
    std::string result = "";
    while (!feof(pipe)) {
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
    }
    _pclose(pipe);
    
    // Parse the output to find the default gateway
    size_t pos = result.find("0.0.0.0");
    if (pos != std::string::npos) {
        // Skip the first "0.0.0.0" and find the next non-whitespace
        pos = result.find_first_not_of(" \t", pos + 7);
        if (pos != std::string::npos) {
            // Find the next whitespace
            size_t end = result.find_first_of(" \t", pos);
            if (end != std::string::npos) {
                original_gateway = result.substr(pos, end - pos);
                std::cout << "Original default gateway: " << original_gateway << std::endl;
            }
        }
    }
    
    if (original_gateway.empty()) {
        std::cerr << "Failed to determine original default gateway" << std::endl;
        return false;
    }
    
    // Step 2: Add a route to the VPN server via the original gateway
    std::string cmd = "route add " + vpn_server_ip + " mask 255.255.255.255 " + original_gateway + " metric 1";
    int result_code = system(cmd.c_str());
    if (result_code != 0) {
        std::cerr << "Failed to add route to VPN server" << std::endl;
        return false;
    }
    
    // Step 3: Change the default route to go through the VPN tunnel
    cmd = "route change 0.0.0.0 mask 0.0.0.0 " + vpn_gateway + " metric 1";
    result_code = system(cmd.c_str());
    if (result_code != 0) {
        std::cerr << "Failed to change default route" << std::endl;
        // Try to restore the route to the VPN server
        cmd = "route delete " + vpn_server_ip;
        system(cmd.c_str());
        return false;
    }
    
    // Save the original gateway for restoration when disconnecting
    original_gateway_ = original_gateway;
    
    std::cout << "Successfully configured Windows routing for VPN" << std::endl;
    return true;
    
#elif defined(__APPLE__)
    // ==================== MACOS IMPLEMENTATION ====================
    
    // Step 1: Get the current default gateway
    FILE* pipe = popen("route -n get default | grep gateway | awk '{print $2}'", "r");
    if (!pipe) {
        std::cerr << "Failed to execute route command" << std::endl;
        return false;
    }
    
    char buffer[256];
    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        original_gateway = buffer;
        // Remove trailing newline
        original_gateway.erase(original_gateway.find_last_not_of("\n\r") + 1);
    }
    pclose(pipe);
    
    if (original_gateway.empty()) {
        std::cerr << "Failed to determine original default gateway" << std::endl;
        return false;
    }
    
    std::cout << "Original default gateway: " << original_gateway << std::endl;
    
    // Step 2: Add a route to the VPN server via the original gateway
    std::string cmd = "route add " + vpn_server_ip + "/32 " + original_gateway;
    int result_code = system(cmd.c_str());
    if (result_code != 0) {
        std::cerr << "Failed to add route to VPN server" << std::endl;
        return false;
    }
    
    // Step 3: Change the default route to go through the VPN tunnel
    cmd = "route change default " + vpn_gateway;
    result_code = system(cmd.c_str());
    if (result_code != 0) {
        std::cerr << "Failed to change default route" << std::endl;
        // Try to restore the route to the VPN server
        cmd = "route delete " + vpn_server_ip + "/32";
        system(cmd.c_str());
        return false;
    }
    
    // Save the original gateway for restoration when disconnecting
    original_gateway_ = original_gateway;
    
    std::cout << "Successfully configured macOS routing for VPN" << std::endl;
    return true;
    
#elif defined(__linux__)
    // ==================== LINUX IMPLEMENTATION ====================
    
    // Step 1: Get the current default gateway and interface
    FILE* pipe = popen("ip route show default | head -n 1 | awk '{print $3 \" \" $5}'", "r");
    if (!pipe) {
        std::cerr << "Failed to execute ip route command" << std::endl;
        return false;
    }
    
    char buffer[256];
    std::string default_interface;
    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::string result = buffer;
        // Remove trailing newline
        result.erase(result.find_last_not_of("\n\r") + 1);
        
        // Parse gateway and interface
        std::istringstream iss(result);
        iss >> original_gateway >> default_interface;
    }
    pclose(pipe);
    
    if (original_gateway.empty() || default_interface.empty()) {
        std::cerr << "Failed to determine original default gateway or interface" << std::endl;
        return false;
    }
    
    std::cout << "Original default gateway: " << original_gateway 
              << " via interface: " << default_interface << std::endl;
    
    // Step 2: Add a route to the VPN server via the original gateway
    std::string cmd = "ip route add " + vpn_server_ip + "/32 via " + original_gateway + 
                      " dev " + default_interface;
    int result_code = system(cmd.c_str());
    if (result_code != 0) {
        std::cerr << "Failed to add route to VPN server" << std::endl;
        return false;
    }
    
    // Step 3: Change the default route to go through the VPN tunnel
    // First, delete the current default route
    cmd = "ip route del default";
    result_code = system(cmd.c_str());
    if (result_code != 0) {
        std::cerr << "Failed to delete default route" << std::endl;
        // Try to restore the route to the VPN server
        cmd = "ip route del " + vpn_server_ip + "/32";
        system(cmd.c_str());
        return false;
    }
    
    // Then add the new default route through the VPN
    cmd = "ip route add default via " + vpn_gateway;
    result_code = system(cmd.c_str());
    if (result_code != 0) {
        std::cerr << "Failed to add new default route" << std::endl;
        // Try to restore the original default route
        cmd = "ip route add default via " + original_gateway + " dev " + default_interface;
        system(cmd.c_str());
        // And remove the VPN server route
        cmd = "ip route del " + vpn_server_ip + "/32";
        system(cmd.c_str());
        return false;
    }
    
    // Save the original gateway and interface for restoration when disconnecting
    original_gateway_ = original_gateway;
    original_interface_ = default_interface;
    
    std::cout << "Successfully configured Linux routing for VPN" << std::endl;
    return true;
    
#else
    // ==================== UNSUPPORTED PLATFORM ====================
    std::cerr << "Routing configuration not implemented for this platform" << std::endl;
    return false;
#endif
}

// Restore the original system routing
bool Tunnel::restore_routing() {
    if (original_gateway_.empty()) {
        // No original gateway stored, nothing to restore
        return true;
    }
    
    std::cout << "Restoring original routing configuration..." << std::endl;
    
#if defined(_WIN32) || defined(_WIN64)
    // ==================== WINDOWS IMPLEMENTATION ====================
    
    // Step 1: Restore the original default gateway
    std::string cmd = "route change 0.0.0.0 mask 0.0.0.0 " + original_gateway_ + " metric 1";
    int result_code = system(cmd.c_str());
    if (result_code != 0) {
        std::cerr << "Failed to restore original default route" << std::endl;
        return false;
    }
    
    // Step 2: Remove the specific route to the VPN server
    cmd = "route delete " + connection_->server_ip_;
    result_code = system(cmd.c_str());
    if (result_code != 0) {
        std::cerr << "Failed to remove VPN server route" << std::endl;
        // Not returning false here as this is not critical
    }
    
    std::cout << "Successfully restored Windows routing configuration" << std::endl;
    return true;
    
#elif defined(__APPLE__)
    // ==================== MACOS IMPLEMENTATION ====================
    
    // Step 1: Restore the original default gateway
    std::string cmd = "route change default " + original_gateway_;
    int result_code = system(cmd.c_str());
    if (result_code != 0) {
        std::cerr << "Failed to restore original default route" << std::endl;
        return false;
    }
    
    // Step 2: Remove the specific route to the VPN server
    cmd = "route delete " + connection_->server_ip_ + "/32";
    result_code = system(cmd.c_str());
    if (result_code != 0) {
        std::cerr << "Failed to remove VPN server route" << std::endl;
        // Not returning false here as this is not critical
    }
    
    std::cout << "Successfully restored macOS routing configuration" << std::endl;
    return true;
    
#elif defined(__linux__)
    // ==================== LINUX IMPLEMENTATION ====================
    
    // Step 1: Delete the current default route
    std::string cmd = "ip route del default";
    int result_code = system(cmd.c_str());
    if (result_code != 0) {
        std::cerr << "Failed to delete current default route" << std::endl;
        // Continue anyway, as we want to try to restore the original route
    }
    
    // Step 2: Restore the original default route
    cmd = "ip route add default via " + original_gateway_;
    if (!original_interface_.empty()) {
        cmd += " dev " + original_interface_;
    }
    result_code = system(cmd.c_str());
    if (result_code != 0) {
        std::cerr << "Failed to restore original default route" << std::endl;
        return false;
    }
    
    // Step 3: Remove the specific route to the VPN server
    cmd = "ip route del " + connection_->server_ip_ + "/32";
    result_code = system(cmd.c_str());
    if (result_code != 0) {
        std::cerr << "Failed to remove VPN server route" << std::endl;
        // Not returning false here as this is not critical
    }
    
    std::cout << "Successfully restored Linux routing configuration" << std::endl;
    return true;
    
#else
    // ==================== UNSUPPORTED PLATFORM ====================
    std::cerr << "Routing restoration not implemented for this platform" << std::endl;
    return false;
#endif
}

// Thread function for processing packets from TUN to server
void Tunnel::tun_to_server_worker()
{
    std::cout << "Started TUN to server worker thread" << std::endl;

    // Buffer for reading packets from the TUN interface
    std::vector<uint8_t> buffer(2048);

    while (running_)
    {
        // Step 1: Read a packet from the TUN interface
        ssize_t bytes_read = read(tun_fd_, buffer.data(), buffer.size());

        if (bytes_read <= 0)
        {
            // Error or no data
            if (bytes_read < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            {
                std::cerr << "Error reading from TUN: " << strerror(errno) << std::endl;
            }

            // Sleep a bit to avoid busy-waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        // Step 2: Process the outgoing packet
        // This includes encapsulation and encryption
        std::vector<uint8_t> packet(buffer.begin(), buffer.begin() + bytes_read);

        if (!process_outgoing_packet(packet))
        {
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
void Tunnel::server_to_tun_worker()
{
    std::cout << "Started server to TUN worker thread" << std::endl;

    // Buffer for reading packets from the server
    std::vector<uint8_t> buffer(2048);

    while (running_)
    {
        // Step 1: Read a packet from the server
        int bytes_read = connection_->receive_data(buffer.data(), buffer.size());

        if (bytes_read <= 0)
        {
            // Error or no data
            if (bytes_read < 0)
            {
                std::cerr << "Error reading from server" << std::endl;
            }

            // Sleep a bit to avoid busy-waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        // Step 2: Process the incoming packet
        // This includes decryption and de-encapsulation
        std::vector<uint8_t> packet(buffer.begin(), buffer.begin() + bytes_read);

        if (!process_incoming_packet(packet))
        {
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
bool Tunnel::process_outgoing_packet(const std::vector<uint8_t> &packet)
{
    try
    {
// Step 1: Analyze the packet (for educational purposes)
// In a real VPN, we might need to modify the packet headers
#ifdef DEBUG_MODE
        if (packet.size() >= 20)
        { // Minimum IPv4 header size
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

        if (encrypted_packet.empty())
        {
            std::cerr << "Failed to encrypt packet" << std::endl;
            return false;
        }

        // Step 3: Send the encrypted packet to the server
        int bytes_sent = connection_->send_data(encrypted_packet.data(), encrypted_packet.size());

        if (bytes_sent < 0)
        {
            std::cerr << "Failed to send packet to server" << std::endl;
            return false;
        }

        return true;
    }
    catch (const std::exception &e)
    {
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
#include "connection.h"
#include "encryption.h"
#include "tunnel.h"
#include <boost/asio.hpp>
#include <csignal>
#include <iostream>
#include <memory>
#include <string>

std::shared_ptr<Tunnel> g_tunnel;
bool g_running = true;

void signal_handler(int signal) {
  std::cout << "Received signal " << signal << ", shutting down..."
            << std::endl;
  g_running = false;

  if (g_tunnel) {
    g_tunnel->stop();
  }
}

void print_usage(const char *program_name) {
  std::cout << "Usage: " << program_name << " [server_ip] [server_port]"
            << std::endl;
  std::cout
      << "  server_ip   - IP address of the VPN server (default: 127.0.0.1)"
      << std::endl;
  std::cout << "  server_port - Port number of the VPN server (default: 8090)"
            << std::endl;
}

int main(int argc, char *argv[]) {
  // Default server settings
  std::string server_ip = "127.0.0.1";
  int server_port = 8090;

  if (argc > 1) {
    server_ip = argv[1];
  }

  if (argc > 2) {
    try {
      server_port = std::stoi(argv[2]);
      if (server_port <= 0 || server_port > 65535) {
        std::cerr << "Error: Port number must be between 1 and 65535"
                  << std::endl;
        return 1;
      }
    } catch (const std::exception &e) {
      std::cerr << "Error: Invalid port number: " << argv[2] << std::endl;
      print_usage(argv[0]);
      return 1;
    }
  }

  std::signal(SIGINT, signal_handler);  // Ctrl+C
  std::signal(SIGTERM, signal_handler); // Termination request

  try {
    std::cout << "Starting KazemVPN client..." << std::endl;
    std::cout << "Connecting to server: " << server_ip << ":" << server_port
              << std::endl;

    boost::asio::io_context io_context;

    auto connection =
        std::make_shared<Connection>(io_context, server_ip, server_port);

    auto encryption = std::make_shared<Encryption>();

    if (!encryption->generate_key(256)) {
      std::cerr << "Failed to generate encryption key" << std::endl;
      return 1;
    }

    if (!connection->connect()) {
      std::cerr << "Failed to connect to VPN server" << std::endl;
      return 1;
    }

    g_tunnel = std::make_shared<Tunnel>(connection, encryption);

    if (!g_tunnel->start()) {
      std::cerr << "Failed to start VPN tunnel" << std::endl;
      return 1;
    }

    std::cout << "VPN tunnel established successfully!" << std::endl;
    std::cout << "Press Ctrl+C to disconnect" << std::endl;

    while (g_running) {
      // Process any pending asynchronous operations
      io_context.poll();

      // Print tunnel statistics periodically
      static int counter = 0;
      if (++counter % 100 == 0) {
        std::cout << g_tunnel->get_stats() << std::endl;
      }

      // Sleep to avoid consuming too much CPU
      std::this_thread::sleep_for(std::chrono::milliseconds(100));

      // Check if the tunnel is still active
      if (!g_tunnel->is_active()) {
        std::cerr << "VPN tunnel disconnected" << std::endl;
        break;
      }
    }

    // The shared_ptr destructors will handle cleanup
    std::cout << "Shutting down VPN client..." << std::endl;

    return 0;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
}
#include <iostream>
#include <boost/asio.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>


void receive_data(boost::asio::ip::tcp::socket& socket);
void send_data(boost::asio::ip::tcp::socket& socket);

int main() {
    const std::string server_ip = "127.0.0.1"; // change to the server ip
    const int server_port = 8090; // change to the server port  
    try {
        boost::asio::io_context io;
        boost::asio::ip::tcp::resolver resolver(io);
        boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(server_ip, std::to_string(server_port));
        boost::asio::ip::tcp::socket socket(io);
        boost::asio::connect(socket, endpoints);

        std::cout << "Connected to VPN server" << std::endl;
    
        send_data(socket);
        receive_data(socket);
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void send_data(boost::asio::ip::tcp::socket& socket) {
    std::string message = "Hello, server!";
    boost::asio::write(socket, boost::asio::buffer(message));
}

void receive_data(boost::asio::ip::tcp::socket& socket) {
    char buffer[1024];
    boost::system::error_code error;
    size_t length = boost::asio::read(socket, boost::asio::buffer(buffer), boost::asio::transfer_at_least(1), error);
    if (error) {
        throw boost::system::system_error(error);
    }
}
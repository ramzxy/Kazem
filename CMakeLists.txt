cmake_minimum_required(VERSION 3.10)
project(KazemVPN CXX)

# Set CMake policies
if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()

# Set C++ standard before defining targets
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
set(BOOST_ROOT "/opt/homebrew")
find_package(Boost REQUIRED COMPONENTS system thread)
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(include)

# Source files
set(SOURCES
    src/main.cpp
    src/tunnel.cpp
    src/encryption.cpp
    src/connection.cpp
)

# Header files
set(HEADERS
    include/tunnel.h
    include/encryption.h
    include/connection.h
)

# Create executable
add_executable(KazemVPN ${SOURCES})

# Link libraries
target_link_libraries(KazemVPN 
    Boost::system 
    Boost::thread
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# Add compile definitions for debug mode
target_compile_definitions(KazemVPN PRIVATE
    $<$<CONFIG:Debug>:DEBUG_MODE>
)

# Output binary to bin directory
set_target_properties(KazemVPN PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

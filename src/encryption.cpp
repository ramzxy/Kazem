#include "encryption.h"
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>

// Constructor - initialize OpenSSL
Encryption::Encryption() : ctx_(nullptr) {
    // Initialize OpenSSL
    init_openssl();
    
    // Create a new cipher context
    ctx_ = EVP_CIPHER_CTX_new();
    if (!ctx_) {
        std::cerr << "Failed to create cipher context" << std::endl;
        throw std::runtime_error("OpenSSL initialization failed");
    }
    
    std::cout << "Encryption system initialized" << std::endl;
}

// Destructor - clean up OpenSSL resources
Encryption::~Encryption() {
    // Free the cipher context
    if (ctx_) {
        EVP_CIPHER_CTX_free(ctx_);
        ctx_ = nullptr;
    }
    
    // Clean up OpenSSL
    cleanup_openssl();
    
    std::cout << "Encryption system destroyed" << std::endl;
}

// Generate a new encryption key
bool Encryption::generate_key(int key_size) {
    // Validate key size (must be 128, 192, or 256 bits)
    if (key_size != 128 && key_size != 192 && key_size != 256) {
        std::cerr << "Invalid key size: " << key_size << std::endl;
        return false;
    }
    
    // Convert bits to bytes
    int key_bytes = key_size / 8;
    
    // Resize the key vector to the appropriate size
    key_.resize(key_bytes);
    
    // Generate random bytes for the key using OpenSSL's RAND_bytes
    if (RAND_bytes(key_.data(), key_bytes) != 1) {
        std::cerr << "Failed to generate random key" << std::endl;
        return false;
    }
    
    std::cout << "Generated " << key_size << "-bit encryption key" << std::endl;
    return true;
}

// Encrypt data using the current key
std::vector<uint8_t> Encryption::encrypt(const std::vector<uint8_t>& plaintext) {
    // Check if we have a key
    if (key_.empty()) {
        std::cerr << "No encryption key set" << std::endl;
        return {};
    }
    
    // Step 1: Generate a random initialization vector (IV)
    std::vector<uint8_t> iv(IV_SIZE);
    if (RAND_bytes(iv.data(), IV_SIZE) != 1) {
        std::cerr << "Failed to generate IV" << std::endl;
        return {};
    }
    
    // Step 2: Initialize the cipher context for encryption
    // We're using AES in CBC mode, which is a block cipher
    // The key size determines whether we use AES-128, AES-192, or AES-256
    const EVP_CIPHER* cipher = nullptr;
    switch (key_.size()) {
        case 16: // 128 bits
            cipher = EVP_aes_128_cbc();
            break;
        case 24: // 192 bits
            cipher = EVP_aes_192_cbc();
            break;
        case 32: // 256 bits
            cipher = EVP_aes_256_cbc();
            break;
        default:
            std::cerr << "Invalid key size for AES: " << key_.size() << " bytes" << std::endl;
            return {};
    }
    
    // Initialize the encryption operation with our key and IV
    if (EVP_EncryptInit_ex(ctx_, cipher, nullptr, key_.data(), iv.data()) != 1) {
        std::cerr << "Failed to initialize encryption" << std::endl;
        return {};
    }
    
    // Step 3: Prepare the output buffer
    // The output will be at most plaintext size + block size - 1 + IV size
    int block_size = EVP_CIPHER_block_size(cipher);
    std::vector<uint8_t> ciphertext(iv.size() + plaintext.size() + block_size);
    
    // Step 4: Copy the IV to the beginning of the ciphertext
    // This is necessary so the decryption function knows what IV was used
    std::copy(iv.begin(), iv.end(), ciphertext.begin());
    
    // Step 5: Encrypt the plaintext
    int out_len1 = 0;
    if (EVP_EncryptUpdate(ctx_, ciphertext.data() + iv.size(), &out_len1, 
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        std::cerr << "Encryption failed" << std::endl;
        return {};
    }
    
    // Step 6: Finalize the encryption (handle any remaining blocks)
    int out_len2 = 0;
    if (EVP_EncryptFinal_ex(ctx_, ciphertext.data() + iv.size() + out_len1, &out_len2) != 1) {
        std::cerr << "Encryption finalization failed" << std::endl;
        return {};
    }
    
    // Step 7: Resize the ciphertext to the actual size
    ciphertext.resize(iv.size() + out_len1 + out_len2);
    
    #ifdef DEBUG_MODE
    std::cout << "Encrypted " << plaintext.size() << " bytes to " 
              << ciphertext.size() << " bytes (including " << iv.size() 
              << "-byte IV)" << std::endl;
    #endif
    
    return ciphertext;
}

// Decrypt data using the current key
std::vector<uint8_t> Encryption::decrypt(const std::vector<uint8_t>& ciphertext) {
    // Check if we have a key
    if (key_.empty()) {
        std::cerr << "No encryption key set" << std::endl;
        return {};
    }
    
    // Check if the ciphertext is large enough to contain an IV
    if (ciphertext.size() <= IV_SIZE) {
        std::cerr << "Ciphertext too short" << std::endl;
        return {};
    }
    
    // Step 1: Extract the IV from the beginning of the ciphertext
    std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + IV_SIZE);
    
    // Step 2: Initialize the cipher context for decryption
    const EVP_CIPHER* cipher = nullptr;
    switch (key_.size()) {
        case 16: // 128 bits
            cipher = EVP_aes_128_cbc();
            break;
        case 24: // 192 bits
            cipher = EVP_aes_192_cbc();
            break;
        case 32: // 256 bits
            cipher = EVP_aes_256_cbc();
            break;
        default:
            std::cerr << "Invalid key size for AES: " << key_.size() << " bytes" << std::endl;
            return {};
    }
    
    // Initialize the decryption operation with our key and the extracted IV
    if (EVP_DecryptInit_ex(ctx_, cipher, nullptr, key_.data(), iv.data()) != 1) {
        std::cerr << "Failed to initialize decryption" << std::endl;
        return {};
    }
    
    // Step 3: Prepare the output buffer
    // The plaintext will be at most the size of the ciphertext minus the IV
    std::vector<uint8_t> plaintext(ciphertext.size() - IV_SIZE);
    
    // Step 4: Decrypt the ciphertext (excluding the IV)
    int out_len1 = 0;
    if (EVP_DecryptUpdate(ctx_, plaintext.data(), &out_len1, 
                          ciphertext.data() + IV_SIZE, 
                          static_cast<int>(ciphertext.size() - IV_SIZE)) != 1) {
        std::cerr << "Decryption failed" << std::endl;
        return {};
    }
    
    // Step 5: Finalize the decryption (handle any remaining blocks)
    int out_len2 = 0;
    if (EVP_DecryptFinal_ex(ctx_, plaintext.data() + out_len1, &out_len2) != 1) {
        std::cerr << "Decryption finalization failed: " 
                  << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return {};
    }
    
    // Step 6: Resize the plaintext to the actual size
    plaintext.resize(out_len1 + out_len2);
    
    #ifdef DEBUG_MODE
    std::cout << "Decrypted " << ciphertext.size() << " bytes to " 
              << plaintext.size() << " bytes" << std::endl;
    #endif
    
    return plaintext;
}

// Set the encryption key directly
bool Encryption::set_key(const std::vector<uint8_t>& key) {
    // Validate key size
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        std::cerr << "Invalid key size: " << key.size() << " bytes" << std::endl;
        return false;
    }
    
    // Copy the key
    key_ = key;
    
    std::cout << "Set " << (key.size() * 8) << "-bit encryption key" << std::endl;
    return true;
}

// Get the current encryption key
std::vector<uint8_t> Encryption::get_key() const {
    return key_;
}

// Initialize the OpenSSL library
void Encryption::init_openssl() {
    // Load the error strings for error reporting
    ERR_load_crypto_strings();
    
    // Initialize the OpenSSL library
    OpenSSL_add_all_algorithms();
    
    // Seed the random number generator
    // In a real application, you should use a better source of entropy
    RAND_poll();
}

// Clean up OpenSSL resources
void Encryption::cleanup_openssl() {
    // Clean up the error strings
    ERR_free_strings();
    
    // Clean up all algorithms
    EVP_cleanup();
    
    // Clean up the random number generator
    RAND_cleanup();
} 
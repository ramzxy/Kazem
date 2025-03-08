#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>

/**
 * @class Encryption
 * @brief Handles encryption and decryption of VPN traffic
 * 
 * The Encryption class is responsible for:
 * 1. Generating and managing encryption keys
 * 2. Encrypting outgoing VPN traffic
 * 3. Decrypting incoming VPN traffic
 * 4. Implementing secure key exchange protocols
 * 
 * This class uses OpenSSL for cryptographic operations.
 */
class Encryption {
public:
    /**
     * @brief Constructor - initializes the encryption system
     * 
     * Sets up the OpenSSL environment and prepares for key generation.
     */
    Encryption();
    
    /**
     * @brief Destructor - cleans up OpenSSL resources
     */
    ~Encryption();
    
    /**
     * @brief Generate a new encryption key
     * @param key_size Size of the key in bits (typically 128, 256)
     * @return true if key generation was successful
     * 
     * In a real VPN, keys are often negotiated with the server
     * using protocols like Diffie-Hellman key exchange.
     */
    bool generate_key(int key_size = 256);
    
    /**
     * @brief Encrypt data using the current key
     * @param plaintext The data to encrypt
     * @return The encrypted data (ciphertext)
     * 
     * This method:
     * 1. Generates a random initialization vector (IV)
     * 2. Encrypts the data using AES in CBC mode
     * 3. Prepends the IV to the ciphertext for decryption
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
    
    /**
     * @brief Decrypt data using the current key
     * @param ciphertext The encrypted data to decrypt
     * @return The decrypted data (plaintext)
     * 
     * This method:
     * 1. Extracts the IV from the beginning of the ciphertext
     * 2. Decrypts the data using AES in CBC mode
     */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);
    
    /**
     * @brief Set the encryption key directly
     * @param key The encryption key to use
     * @return true if the key was set successfully
     * 
     * This is used when receiving a key from the server
     * during the key exchange process.
     */
    bool set_key(const std::vector<uint8_t>& key);
    
    /**
     * @brief Get the current encryption key
     * @return The current encryption key
     * 
     * This should be used carefully, as exposing the key
     * compromises security.
     */
    std::vector<uint8_t> get_key() const;

private:
    // Encryption key
    std::vector<uint8_t> key_;
    
    // OpenSSL cipher context
    EVP_CIPHER_CTX* ctx_;
    
    // Size of the initialization vector (IV)
    static const int IV_SIZE = 16;  // 128 bits
    
    /**
     * @brief Initialize the OpenSSL library
     * 
     * Sets up the OpenSSL environment for cryptographic operations.
     */
    void init_openssl();
    
    /**
     * @brief Clean up OpenSSL resources
     * 
     * Frees memory and handles proper shutdown of OpenSSL.
     */
    void cleanup_openssl();
};

#endif // ENCRYPTION_H 
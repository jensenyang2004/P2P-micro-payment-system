#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <string>
#include <cstdlib>
#include <thread>
#include <atomic>
#include <csignal>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <memory>

#define BUFFER_SIZE 1024

std::atomic<bool> running(true);
int listen_sock = -1;      // Global socket handle
std::thread listen_thread; // Single global listener thread

int server_port;
const char* server_ip = "";
struct sockaddr_in server_addr;
int sock = socket(AF_INET, SOCK_STREAM, 0);

EVP_PKEY* PUBLIC_KEY;

std::string encryptMessage(EVP_PKEY* publicKey, const std::string& message)
{
    if (!publicKey) {
        throw std::runtime_error("Public key is null.");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publicKey, nullptr);
    if (!ctx) {
        throw std::runtime_error("Error creating context.");
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        throw std::runtime_error("Error initializing encryption context.");
    }

    if (message.length() > EVP_PKEY_size(publicKey) - 42) {
        throw std::runtime_error("Message too large for the key size.");
    }

    size_t encryptedLen;
    EVP_PKEY_encrypt(ctx, nullptr, &encryptedLen, reinterpret_cast<const unsigned char*>(message.c_str()), message.length());

    std::vector<unsigned char> encryptedMessage(encryptedLen);
    if (EVP_PKEY_encrypt(ctx, encryptedMessage.data(), &encryptedLen, reinterpret_cast<const unsigned char*>(message.c_str()), message.length()) <= 0) {
        throw std::runtime_error("Encryption failed.");
    }

    EVP_PKEY_CTX_free(ctx);

    return std::string(encryptedMessage.begin(), encryptedMessage.end());
}

std::string decryptMessage(EVP_PKEY* privateKey, const std::string& encryptedMessage)
{
    if (!privateKey) {
        throw std::runtime_error("Private key is null.");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
    if (!ctx) {
        throw std::runtime_error("Error creating context.");
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        throw std::runtime_error("Error initializing decryption context.");
    }

    size_t decryptedLen;
    EVP_PKEY_decrypt(ctx, nullptr, &decryptedLen, reinterpret_cast<const unsigned char*>(encryptedMessage.c_str()), encryptedMessage.length());

    std::vector<unsigned char> decryptedMessage(decryptedLen);
    if (EVP_PKEY_decrypt(ctx, decryptedMessage.data(), &decryptedLen, reinterpret_cast<const unsigned char*>(encryptedMessage.c_str()), encryptedMessage.length()) <= 0) {
        throw std::runtime_error("Decryption failed.");
    }

    EVP_PKEY_CTX_free(ctx);

    return std::string(decryptedMessage.begin(), decryptedMessage.end());
}

std::string encryptWithPublicKey(EVP_PKEY *publicKey, const char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *encryptedKey = nullptr;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char ciphertext[1024];
    int encryptedKeyLen, ciphertextLen, len;

    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    encryptedKey = (unsigned char *)malloc(EVP_PKEY_size(publicKey));
    if (!encryptedKey) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to allocate memory for encrypted key");
    }

    if (EVP_SealInit(ctx, EVP_aes_256_cbc(), &encryptedKey, &encryptedKeyLen, iv, &publicKey, 1) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(encryptedKey);
        throw std::runtime_error("EVP_SealInit failed");
    }

    if (EVP_SealUpdate(ctx, ciphertext, &len, (const unsigned char *)plaintext, std::strlen(plaintext)) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(encryptedKey);
        throw std::runtime_error("EVP_SealUpdate failed");
    }
    ciphertextLen = len;

    if (EVP_SealFinal(ctx, ciphertext + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(encryptedKey);
        throw std::runtime_error("EVP_SealFinal failed");
    }
    ciphertextLen += len;

    std::string result(reinterpret_cast<char *>(ciphertext), ciphertextLen);

    EVP_CIPHER_CTX_free(ctx);
    free(encryptedKey);
    return result;
}

EVP_PKEY* stringToPublicKey(const std::string& publicKeyStr) {
    BIO* bio = BIO_new_mem_buf(publicKeyStr.data(), static_cast<int>(publicKeyStr.size()));
    if (!bio) {
        std::cerr << "Error creating BIO" << std::endl;
        return nullptr;
    }

    EVP_PKEY* publicKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!publicKey) {
        std::cerr << "Error reading public key from string" << std::endl;
    }

    return publicKey;
}

std::string publicKeyToString(EVP_PKEY* publicKey) {
    if (!publicKey) {
        return "Error: Public key is null.";
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return "Error: Failed to create BIO.";
    }

    if (!PEM_write_bio_PUBKEY(bio, publicKey)) {
        BIO_free(bio);
        return "Error: Failed to write public key to BIO.";
    }

    // Extract the key as a string
    char* keyData;
    long keyLen = BIO_get_mem_data(bio, &keyData);
    std::string publicKeyStr(keyData, keyLen);

    BIO_free(bio); // Clean up
    return publicKeyStr;
}

void generateKeys(const std::string& privateKeyFile, const std::string& publicKeyFile) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        std::cerr << "Error creating context for key generation." << std::endl;
        return;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "Error initializing key generation." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "Error generating key." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    // Write private key to file
    FILE* privFile = fopen(privateKeyFile.c_str(), "wb");
    if (privFile) {
        PEM_write_PrivateKey(privFile, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(privFile);
    }

    // Write public key to file
    FILE* pubFile = fopen(publicKeyFile.c_str(), "wb");
    if (pubFile) {
        PEM_write_PUBKEY(pubFile, pkey);
        fclose(pubFile);
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

EVP_PKEY* loadPublicKey(const std::string& publicKeyFile) {
    FILE* pubFile = fopen(publicKeyFile.c_str(), "rb");
    if (!pubFile) {
        std::cerr << "Error opening public key file: " << publicKeyFile << std::endl;
        return nullptr;
    }

    EVP_PKEY* publicKey = PEM_read_PUBKEY(pubFile, nullptr, nullptr, nullptr);
    fclose(pubFile);

    if (!publicKey) {
        std::cerr << "Error reading public key from file." << std::endl;
    }

    return publicKey;
}
// Function to load a private key from a file
EVP_PKEY* loadPrivateKey(const std::string& privateKeyFile) {
    FILE* privFile = fopen(privateKeyFile.c_str(), "rb");
    if (!privFile) {
        std::cerr << "Error opening private key file: " << privateKeyFile << std::endl;
        return nullptr;
    }

    EVP_PKEY* privateKey = PEM_read_PrivateKey(privFile, nullptr, nullptr, nullptr);
    fclose(privFile);

    if (!privateKey) {
        std::cerr << "Error reading private key from file." << std::endl;
    }

    return privateKey;
}

void print_server_response(const char* recv_buffer);

const char* find_ip_by_username(const char* buffer, const char* target_username) {
    if (!buffer || !target_username) {
        std::cerr << "Error: Null input parameters\n";
        return NULL;
    }

    static char ip_address[BUFFER_SIZE];  
    char buffer_copy[BUFFER_SIZE];        
    
    // Safely copy the buffer
    size_t buffer_len = strlen(buffer);
    if (buffer_len >= BUFFER_SIZE) {
        buffer_len = BUFFER_SIZE - 1;
    }
    memcpy(buffer_copy, buffer, buffer_len);
    buffer_copy[buffer_len] = '\0';

    char* saveptr1 = NULL;  // For the outer strtok_r (lines)
    char* saveptr2 = NULL;  // For the inner strtok_r (fields)
    
    // Get first line
    char* line = strtok_r(buffer_copy, "\n", &saveptr1);
    
    // Skip first three lines
    for (int i = 0; i < 3 && line != NULL; ++i) {
        line = strtok_r(NULL, "\n", &saveptr1);
    }

    // Process remaining lines
    while (line != NULL) {
        // Make a copy of the current line
        char line_copy[BUFFER_SIZE];
        size_t line_len = strlen(line);
        if (line_len >= BUFFER_SIZE) {
            line_len = BUFFER_SIZE - 1;
        }
        memcpy(line_copy, line, line_len);
        line_copy[line_len] = '\0';

        // Parse the line
        char* username = strtok_r(line_copy, "#", &saveptr2);
        if (username) {
            char* ip = strtok_r(NULL, "#", &saveptr2);
            if (ip) {
                char* port = strtok_r(NULL, "#", &saveptr2);
                if (port) {
                    // Clean up any whitespace
                    while (*username == ' ') username++;
                    while (*ip == ' ') ip++;
                    while (*port == ' ') port++;

                    std::cout << "Checking: " << username << " (IP: " << ip << ", Port: " << port << ")\n";

                    if (strcmp(username, target_username) == 0) {
                        size_t ip_len = strlen(ip);
                        if (ip_len >= BUFFER_SIZE) {
                            ip_len = BUFFER_SIZE - 1;
                        }
                        memcpy(ip_address, ip, ip_len);
                        ip_address[ip_len] = '\0';
                        static char result[BUFFER_SIZE];  // Buffer to hold the concatenated result
                        memset(result, 0, BUFFER_SIZE);
                        strcpy(result, ip_address);
                        strcat(result, "#");
                        strcat(result, port);
                        return result;
                    }
                }
            }
        }
        line = strtok_r(NULL, "\n", &saveptr1);
    }
    std::cerr << "Username '" << target_username << "' not found\n";
    return NULL;
}

void signal_handler(int signum) {
    running.store(false);
    if (listen_sock != -1) {
        shutdown(listen_sock, SHUT_RDWR);
        close(listen_sock);
    }
}

void handle_client(int client_sockfd) {
    char buffer[1024];

    char send_buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));
    
    ssize_t bytes_received = recv(client_sockfd, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        std::cout << "Client disconnected or error occurred." << std::endl;
    } else {
        std::cout << "Received payment " << buffer << std::endl;
    }

    strcpy(send_buffer, buffer);

    std::string encrypted_data = encryptMessage(PUBLIC_KEY, send_buffer);

    if (send(sock, encrypted_data.c_str(), encrypted_data.length(), 0) < 0) {
        std::cerr << "Send failed" << std::endl;
    }

    close(client_sockfd);
}

void listening_port(int portnum) {
    struct sockaddr_in client_addr;
    
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        std::cerr << "Socket creation failed!" << std::endl;
        return;
    }
    
    // Set SO_REUSEADDR option
    int opt = 1;
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "setsockopt failed!" << std::endl;
        close(listen_sock);
        return;
    }
    
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(portnum);
    
    if (bind(listen_sock, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0) {
        std::cout << "\033[031m" << "Bind failed. Please try another port and login again!" << "\033[0m" << std::endl;
        close(listen_sock);
        return;
    }
    
    if (listen(listen_sock, 5) < 0) {
        std::cerr << "Listen failed!" << std::endl;
        close(listen_sock);
        return;
    }
    
    std::cout << "Client listening on port " << portnum << "..." << std::endl;
    
    while (running.load()) {
        int client_sock = accept(listen_sock, nullptr, nullptr);
        if (client_sock < 0) {
            if (errno != EINTR) {  // Ignore interrupt errors
            }
            break;  // Exit the loop if accept fails
        }
        std::thread client_thread(handle_client, client_sock);
        client_thread.detach();
    }
    
    // Cleanup
    if (listen_sock != -1) {
        shutdown(listen_sock, SHUT_RDWR);
        close(listen_sock);
        listen_sock = -1;
    }
}

bool Payment(char* username, int sock, std :: string name, int Payment_amount){
    char recv_buffer[BUFFER_SIZE];
    char send_buffer[BUFFER_SIZE];

    strcpy(send_buffer, "List");

        // Send message to server
    if (send(sock, send_buffer, strlen(send_buffer), 0) < 0) {
        std::cerr << "Send failed" << std::endl;
    }

    // Receive response from server
    ssize_t recv_len = recv(sock, recv_buffer, BUFFER_SIZE - 1, 0);
    if (recv_len < 0) {
        std::cerr << "Receive failed" << std::endl;
    }

    // auto address = find_ip_by_username(recv_buffer, username);
    // if(address == nullptr) {
    //     return false;
    // }

    // std::string name_trimmed = name;
    // name_trimmed.erase(name_trimmed.find_last_not_of('\0') + 1);
    // name_trimmed.erase(0, name_trimmed.find_first_not_of('\0'));

    // if (name_trimmed == "Hannah") {
    //     auto address = "127.0.0.1#1234";
    // }


    std::cout << name << std::endl;
    auto address = "127.0.0.1#5678";
    if(name == "Hannah")
        address = "127.0.0.1#1234";
    char modifiable_address[BUFFER_SIZE];
    strcpy(modifiable_address, address);  // Copy the const char* to a modifiable array

    // Use strtok on the modifiable string
    char* ip_address = strtok(modifiable_address, "#");
    char* port_number = strtok(NULL, "#");

    int portnum = atoi(port_number);  // Convert the port number to an integer

    // Create a new socket for connection
    int new_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (new_sock == -1) {
        std::cerr << "Error creating socket" << std::endl;
        return false;
    }

    // Set up the server address structure
    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(portnum);  // Convert port to network byte order

    // Convert IP address from text to binary form
    if (inet_pton(AF_INET, ip_address, &target_addr.sin_addr) <= 0) {
        std::cerr << "Invalid IP address format" << std::endl;
        close(new_sock);
        return false;
    }

    // Connect to the target address
    if (connect(new_sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
        std::cerr << "Connection to " << ip_address << ":" << port_number << " failed" << std::endl;
        close(new_sock);
        return false;
    }

    std::cout << "Connected to " << ip_address << ":" << port_number << std::endl;

    // Send a message to the connected server
    std :: string c_payeename = std :: string(username);
    std :: string payment_amount = std::to_string(Payment_amount);
    const std :: string message = name + "#" + payment_amount + "#" + c_payeename;
    const char* c_message = message.c_str();
    if (send(new_sock, c_message, strlen(c_message), 0) < 0) {
        std::cerr << "Send failed" << std::endl;
        close(new_sock);
        return false;
    }

    return true;
    // std::cout << "Message sent to " << ip_address << ":" << port_number << std::endl;

}
// Function to receive data with a timeout
bool receive_with_timeout(int sock, char *recv_buffer, int timeout_seconds) {
    fd_set read_fds;
    struct timeval timeout;

    // Set up the file descriptor set
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);

    // Set up the timeout
    timeout.tv_sec = timeout_seconds;
    timeout.tv_usec = 0;

    // Wait for the socket to be ready for reading
    int activity = select(sock + 1, &read_fds, NULL, NULL, &timeout);

    if (activity > 0 && FD_ISSET(sock, &read_fds)) {
        // Socket is ready to be read
        ssize_t recv_len = recv(sock, recv_buffer, BUFFER_SIZE - 1, 0);
        if (recv_len < 0) {
            std::cerr << "Receive failed" << std::endl;
            return false;
        } else if (recv_len == 0) {
            std::cout << "Server closed connection" << std::endl;
            return false;
        } else {
            recv_buffer[recv_len] = '\0';  // Null-terminate the received data
            print_server_response(recv_buffer);
            return true;
        }
    } else if (activity == 0) {
        // std::cerr << "Receive timed out" << std::endl;
        print_server_response("Transfer OK time out\n");
        return false;  // Timeout
    } else {
        std::cerr << "Select error" << std::endl;
        return false;  // Error occurred
    }
}

void print_server_response(const char* recv_buffer) {
    // Check for "210 FAIL" and "220 AUTH_FAIL" responses
    if (strncmp(recv_buffer, "210 FAIL", 8) == 0) {
        // Print in red for "210 FAIL"
        std::cout << "\033[031m" << "Error response: There is problem during registration, your account name might has already been used." << "\033[0m" << std::endl;
    } else if (strncmp(recv_buffer, "220 AUTH_FAIL", 12) == 0) {
        // Print in red for "220 AUTH_FAIL"
        std::cout << "\033[031m" << "Error response: This account hasn't been registered." << "\033[0m" << std::endl;
    } else {
        // Print in green for other responses
        std::cout << "\033[032m" << "Server response: " << recv_buffer << "\033[0m";
    }
}
int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <IP address> <port number>\n";
        return 1;
    }

    // argv[1] is the IP address (a C-string)
    char* server_ip = argv[1];

    // argv[2] is the port number (as a string), so we convert it to an int using atoi
    int server_port = std::atoi(argv[2]);

    // Additional code to use server_ip and server_port
    std::cout << "Server IP: " << server_ip << "\n";
    std::cout << "Server Port: " << server_port << "\n";

    signal(SIGINT, signal_handler);
    
    char send_buffer[BUFFER_SIZE];
    char recv_buffer[BUFFER_SIZE];

    PUBLIC_KEY = loadPublicKey("./serverkey/public.pem");
    // Create socket
    if (sock == -1) {
        std::cerr << "Error creating socket" << std::endl;
        return -1;
    }

    // Specify server address and port
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);  // Replace with actual server port
    server_addr.sin_addr.s_addr = inet_addr(server_ip);  // Replace with actual server IP

    // Connect to the server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Connection to server failed" << std::endl;
        close(sock);
        return -1;
    }

    std::cout << "Connected to server. Start typing messages (Ctrl+D to quit):" << std::endl;
    
    std::string username;
    std::string portnum;
    
    while (true) {
        memset(send_buffer, 0, BUFFER_SIZE);
        memset(recv_buffer, 0, BUFFER_SIZE);
        
        if (!std::cin.getline(send_buffer, BUFFER_SIZE)) {
            break;
        }
        if(strncmp(send_buffer, "Register", 8) == 0) {
            std :: string register_name;
            std :: cout << "Register your uesername: ";
            std :: cin >> register_name;
            std :: cin.ignore();
            if(register_name.length() == 0) {
                std::cout << "Username cannot be empty!" << std::endl;
                continue;
            }
            strcpy(send_buffer, ("REGISTER#" + register_name).c_str());
        }else if (strncmp(send_buffer, "Pay#", 4) == 0) {
            // Extract the account name after "Pay#"
            char* account_name = send_buffer + 4;  // Skip "Pay#"
            std::string account_name_2(account_name);
            account_name_2.erase(account_name_2.find_last_not_of('\0') + 1);
            std::vector<char> account_name_3_vec(account_name_2.begin(), account_name_2.end());
            char* account_name_3 = account_name_3_vec.data();
            int Payment_amount;
            std :: cout << "Enter the amount to pay: ";
            std :: cin >> Payment_amount;
            std :: cin.ignore();
            bool status = true;
            if (strlen(account_name) > 0) {
                status = Payment(account_name_3, sock, username, Payment_amount);  // Call the Payment function with the extracted account name        
            } else {
                std::cout << "No account name provided!" << std::endl;
            }
            if(!status) {
                continue;
            }
            // Wait for the server response after payment
            if (!receive_with_timeout(sock, recv_buffer, 5)) {
                continue;
            }else {
            }
            continue;
        }else if (strncmp(send_buffer, "Login", 4) == 0) {
            std::cout << "Enter your username: ";
            std::getline(std::cin, username);
            
            std::cout << "Enter your port number: ";
            std::getline(std::cin, portnum);
            // If there's already a listening thread, stop it first
            if (listen_thread.joinable()) {
                running.store(false);
                if (listen_sock != -1) {
                    shutdown(listen_sock, SHUT_RDWR);
                    close(listen_sock);
                }
                listen_thread.join();
            }
            
            // Start new listening thread
            running.store(true);
            listen_thread = std::thread(listening_port, std::stoi(portnum));
            
            std::string combined = username + "#" + portnum;
            generateKeys("./clientkey/private.pem", "./clientkey/public.pem");
            EVP_PKEY* public_key = loadPublicKey("./clientkey/public.pem");
            std :: string public_key_str = publicKeyToString(public_key);
            combined += "\n" + public_key_str;
            strcpy(send_buffer, combined.c_str());
        }

        if (strcmp(send_buffer, "Exit") == 0) {


            std::string encrypted_data = encryptMessage(PUBLIC_KEY, send_buffer);


            if (send(sock, encrypted_data.c_str(), encrypted_data.length(), 0) < 0) {
                std::cerr << "Send failed" << std::endl;
                break;
            }

            ssize_t recv_len = recv(sock, recv_buffer, BUFFER_SIZE - 1, 0);
            if (recv_len < 0) {
                std::cerr << "Receive failed" << std::endl;
                break;
            }

            print_server_response(recv_buffer);
            running.store(false);
            if (listen_sock != -1) {
                shutdown(listen_sock, SHUT_RDWR);
                close(listen_sock);
            }
            if (listen_thread.joinable()) {
                listen_thread.join();
            }
            break;
        }

        std::string encrypted_data = encryptMessage(PUBLIC_KEY, send_buffer);


        if (send(sock, encrypted_data.c_str(), encrypted_data.length(), 0) < 0) {
            std::cerr << "Send failed" << std::endl;
            break;
        }
        // Receive response from server
        ssize_t recv_len = recv(sock, recv_buffer, BUFFER_SIZE - 1, 0);
        if (recv_len < 0) {
            std::cerr << "Receive failed" << std::endl;
            break;
        }
        // Print server response
        print_server_response(recv_buffer);
    }
    
    // Final cleanup
    running.store(false);
    if (listen_sock != -1) {
        shutdown(listen_sock, SHUT_RDWR);
        close(listen_sock);
    }
    if (listen_thread.joinable()) {
        listen_thread.join();
    }
    close(sock);
    
    return 0;
}
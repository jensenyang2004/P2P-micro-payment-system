#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <vector>
#include <algorithm>
#include <sys/select.h>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <map>
#include <sstream>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <memory>

#define PORT 8888
#define MAX_CLIENTS 10
#define GREEN_TEXT "\033[32m"
#define RED_TEXT "\033[31m"
#define YELLOW_TEXT "\033[33m"
#define RESET_COLOR "\033[0m"

struct User {
    std::string username;
    int balance;
    std::string ip_address;
    int port_number;
    bool is_online;
    int socket_fd;
};

// Global data (protect with mutex)
std::mutex users_mutex;
std::map<std::string, User> users;  // username -> User
std::mutex clients_mutex;
std::vector<int> client_sockets;  // Add this as a global variable
EVP_PKEY* PUBLIC_KEY;
EVP_PKEY* PRIVATE_KEY;

class ThreadPool {
public:
    ThreadPool(size_t num_threads) : stop(false) {
        for(size_t i = 0; i < num_threads; ++i) {
            workers.emplace_back([this] {
                while(true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex);
                        condition.wait(lock, [this] {
                            return stop || !tasks.empty();
                        });
                        
                        if(stop && tasks.empty()) {
                            return;
                        }
                        
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
            });
        }
    }
    
    template<class F>
    void enqueue(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }
    
    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for(std::thread &worker: workers) {
            worker.join();
        }
    }

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};

ThreadPool pool(4); // Create 4 worker threads

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

void handle_client(int client_fd) {
    char buffer[1024] = {0};
    struct sockaddr_in peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    getpeername(client_fd, (struct sockaddr*)&peer_addr, &peer_len);
    std::string client_ip = inet_ntoa(peer_addr.sin_addr);
    std::string username = "";
    while(true) {
        int valread = read(client_fd, buffer, 1024);
        if(valread <= 0) {
            std::cout << RED_TEXT << "Client disconnected. Socket fd: " << client_fd << RESET_COLOR << std::endl;
        // Optional: Clean up user state
        if (!username.empty()) {
            std::lock_guard<std::mutex> lock(users_mutex);
            if (users.find(username) != users.end()) {
                users[username].is_online = false;
                users[username].socket_fd = -1;
            }
        }
        
        close(client_fd);
        break;  // Exit the loop for this client
            close(client_fd);
            break;
        }

        std::string raw_message(buffer, valread);
        std::string response;

        std::string decrypted_message = decryptMessage(PRIVATE_KEY, raw_message);

        std::string message = decrypted_message;
        message.erase(message.find_last_not_of('\0') + 1);

        if (message.find("REGISTER#") == 0) {
            username = message.substr(9);
            std::lock_guard<std::mutex> lock(users_mutex);
            std::cout << "'" << username << "'" << std::endl;
            if (users.find(username) == users.end()) {
                users[username] = {
                    username,
                    10000,      
                    client_ip,
                    0,          
                    false,      
                    client_fd   
                };
                std::cout << users[username].balance << std::endl;
                response = "100 OK\n";
                std::cout << GREEN_TEXT << "username \"" << username << "\" registered" << RESET_COLOR << std::endl;
            } else {
                response = "210 FAIL\n";
            }
        }
        else if (message.find("#") != std::string::npos) {
            size_t first_hash = message.find("#");
            size_t second_hash = message.find("#", first_hash + 1);
            
            if (second_hash != std::string::npos) {
                std::cout << YELLOW_TEXT << "transfering..." << RESET_COLOR << std::endl;
                std::string sender = message.substr(0, first_hash);
                int amount = std::stoi(message.substr(first_hash + 1, second_hash - first_hash - 1));
                std::string receiver = message.substr(second_hash + 1);
                
                if (username == receiver) {
                    std::lock_guard<std::mutex> lock(users_mutex);
                    
                    if (users.find(sender) != users.end() && users[sender].is_online && users[sender].balance >= amount) {
                        users[sender].balance -= amount;
                        users[receiver].balance += amount;
                        std::string transfer_response = "Transfer OK!\n";
                        send(users[sender].socket_fd, transfer_response.c_str(), transfer_response.length(), 0);
                        memset(buffer, 0, sizeof(buffer));  // Clear buffer before continuing
                        std::cout << GREEN_TEXT << "transaction success: " << amount << " from " << sender << " to " << receiver << RESET_COLOR << std::endl;
                        continue;  // Go back to start of while loop
                    }else{
                        std::string transfer_response = "Transfer FAIL\n";
                        send(users[sender].socket_fd, transfer_response.c_str(), transfer_response.length(), 0);
                        memset(buffer, 0, sizeof(buffer));  // Clear buffer before continuing
                        std::cout << RED_TEXT << "transaction failed: " << amount << " from " << sender << " to " << receiver << RESET_COLOR << std::endl;
                        continue;  
                    }
                } else {
                    response = "400 BAD REQUEST\n";
                }
            } else {
                // Original login handling code
                username = message.substr(0, first_hash);
                int port_num = std::stoi(message.substr(first_hash + 1));
                username.erase(username.find_last_not_of(" \n\r\t") + 1);  // Remove trailing spaces
                std::cout << "username at login handling:" << username << ": making sure no space behind it" << std::endl;
                std::lock_guard<std::mutex> lock(users_mutex);
                if (users.find(username) != users.end()) {
                    // Update user status
                    users[username].is_online = true;
                    users[username].port_number = port_num;
                    users[username].ip_address = client_ip;
                    users[username].socket_fd = client_fd;
                    
                    // Construct response
                    response = std::to_string(users[username].balance) + "\n"
                              "public_key\n";
                    
                    // Count online users and build list
                    int online_count = 0;
                    std::string online_users;
                    for (const auto& user : users) {
                        if (user.second.is_online) {
                            online_count++;
                            online_users += user.first + "#" + 
                                          user.second.ip_address + "#" + 
                                          std::to_string(user.second.port_number) + "\n";
                        }
                    }
                    
                    response += std::to_string(online_count) + "\n" + online_users;

                    std::cout << GREEN_TEXT << username << " is online on " << client_ip << "#" << port_num << RESET_COLOR << std::endl;

                } else {
                    response = "220 AUTH_FAIL\n";
                }
            }
        }
        else if(message.find("List") == 0) {
            if(username == "") {
                response = "401 BAD REQUEST\n";
                send(client_fd, response.c_str(), response.length(), 0);
                continue;
            }
            // Construct response
            response = std::to_string(users[username].balance) + "\n"
                        "public_key\n";  // Replace with actual public key if needed
            
            // Count online users and build list
            int online_count = 0;
            std::string online_users;
            for (const auto& user : users) {
                if (user.second.is_online) {
                    online_count++;
                    online_users += user.first + "#" + 
                                    user.second.ip_address + "#" + 
                                    std::to_string(user.second.port_number) + "\n";
                }
            }
            response += std::to_string(online_count) + "\n" + online_users;
        }
        else if(message.find("Exit") == 0) {

            std::cout << "Exit condition detected" << std::endl;
            {
                std::lock_guard<std::mutex> lock(users_mutex);
                users[username].is_online = false;
                users[username].socket_fd = -1;  // Mark socket as invalid
            }
            
            response = "Bye\n";
            send(client_fd, response.c_str(), response.length(), 0);
            memset(buffer, 0, sizeof(buffer));
            
            // Close socket and clean up
            {
                std::lock_guard<std::mutex> lock(clients_mutex);
                auto it = std::find(client_sockets.begin(), client_sockets.end(), client_fd);
                if (it != client_sockets.end()) {
                    client_sockets.erase(it);
                }
            }
            std::cout << YELLOW_TEXT << "Client disconnected. Socket fd: " << client_fd << RESET_COLOR << std::endl;
            close(client_fd);  // Make sure to close the socket
            break;
        }
        else {
            response = "402 BAD REQUEST\n";
        }

        send(client_fd, response.c_str(), response.length(), 0);
        memset(buffer, 0, sizeof(buffer));
    }
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

void print_usage(const char* program_name) {
    std::cerr << "Usage: " << program_name << " <port_number> -mode" << std::endl;
    exit(EXIT_FAILURE);
}

// Add this function to safely remove a socket from client_sockets
void remove_client_socket(int socket_fd) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    auto it = std::find(client_sockets.begin(), client_sockets.end(), socket_fd);
    if (it != client_sockets.end()) {
        client_sockets.erase(it);
    }
}

int main(int argc, char *argv[]) {
    // Check command line arguments
    if (argc != 3) {
        print_usage(argv[0]);
    }

    // Parse port number
    int port = std::stoi(argv[1]);
    std::string mode = argv[2];

    // Validate port number
    if (port <= 0 || port > 65535) {
        std::cerr << "Invalid port number. Must be between 1 and 65535" << std::endl;
        exit(EXIT_FAILURE);
    }

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    
    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        std::cerr << "Socket creation failed" << std::endl;
        exit(EXIT_FAILURE);
    }
    
    // Set socket options to reuse address and port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        std::cerr << "Setsockopt (SO_REUSEADDR) failed" << std::endl;
        exit(EXIT_FAILURE);
    }
    
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
        std::cerr << "Setsockopt (SO_REUSEPORT) failed" << std::endl;
        exit(EXIT_FAILURE);
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    // Bind socket to port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        std::cerr << "Bind failed" << std::endl;
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        std::cerr << "Listen failed" << std::endl;
        exit(EXIT_FAILURE);
    }
    
    // Create thread pool
    
    std::cout << GREEN_TEXT << "Server is listening on port " << port << RESET_COLOR << std::endl;

    PUBLIC_KEY = loadPublicKey("./serverkey/public.pem");
    PRIVATE_KEY = loadPrivateKey("./serverkey/private.pem");
    
    // Main server loop - now just accepts connections and hands them to thread pool
    while(true) {
        // Accept new connection
        int new_socket;
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            std::cerr << "Accept failed" << std::endl;
            continue;
        }
        
        struct sockaddr_in peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        getpeername(new_socket, (struct sockaddr*)&peer_addr, &peer_len);
        std::string client_ip = inet_ntoa(peer_addr.sin_addr);
        int client_port = ntohs(peer_addr.sin_port);
        
        std::cout << GREEN_TEXT << "New client connected: " << client_ip << "#" << client_port << RESET_COLOR << std::endl;
        
        // Add to client sockets vector (protect with mutex if needed)
        client_sockets.push_back(new_socket);
        
        // Hand off client handling to thread pool
        pool.enqueue([new_socket]() {
            handle_client(new_socket);
            remove_client_socket(new_socket);
        });
    }
    
    // Close all client sockets
    for(int socket : client_sockets) {
        close(socket);
    }
    
    // Close server socket
    close(server_fd);
    
    return 0;
}

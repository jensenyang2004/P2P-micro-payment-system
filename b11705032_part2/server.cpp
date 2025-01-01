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
// int public_key = 0;
std::mutex clients_mutex;
std::vector<int> client_sockets;  // Add this as a global variable

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
            close(client_fd);
            break;
        }

        std::string message(buffer);
        std::string response;

        if (message.find("REGISTER#") == 0) {
            username = message.substr(9);
            std::lock_guard<std::mutex> lock(users_mutex);
            
            if (users.find(username) == users.end()) {
                users[username] = {
                    username,
                    10000,      
                    client_ip,
                    0,          
                    false,      
                    client_fd   
                };
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
    if (argc != 2) {
        print_usage(argv[0]);
    }

    // Parse port numbers
    int port = std::stoi(argv[1]);
    // std::string mode = argv[2];

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

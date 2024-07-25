#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORT 8080

int main(int argc, char *argv[]) {
    // Initialize Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("WSAStartup failed with error: %d\n", result);
        return 1;
    }

    // Create a socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET) {
        perror("socket failed");
        WSACleanup();
        return 1;
    }

    // Set SO_REUSEADDR option (similar to Linux)
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof(opt)) == SOCKET_ERROR) {
        perror("setsockopt failed");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    // Set up server address
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket to the address
    if (bind(server_fd, (struct sockaddr *) &address, sizeof(address)) == SOCKET_ERROR) {
        perror("bind failed");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) == SOCKET_ERROR) {
        perror("listen failed");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    // Accept a connection
    struct sockaddr_in client_addr;
    int client_addr_size = sizeof(client_addr);
    int new_socket = accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_size);
    if (new_socket == INVALID_SOCKET) {
        perror("accept failed");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    // Receive data from the client
    char buffer[1024] = {0};
    size_t valread = recv(new_socket, buffer, sizeof(buffer) - 1, 0); // Reserve space for null terminator
    if (valread == SOCKET_ERROR) {
        perror("recv failed");
        closesocket(new_socket);
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    printf("Received from client: %s\n", buffer);

    // Send message to the client
    char *hello = "Hello from server";
    if (send(new_socket, hello, strlen(hello), 0) == SOCKET_ERROR) {
        perror("send failed");
        closesocket(new_socket);
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }
    printf("Hello message sent\n");

    // Close the connected socket
    closesocket(new_socket);

    // Close the listening socket
    closesocket(server_fd);

    // Cleanup Winsock
    WSACleanup();

    return 0;
}

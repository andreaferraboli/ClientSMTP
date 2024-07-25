#include <winsock2.h>
#include <stdio.h>
#include <string.h>
#include <Ws2tcpip.h>

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
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd == INVALID_SOCKET) {
        perror("socket failed");
        WSACleanup();
        return 1;
    }

    // Set up server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to the server
    if (connect(client_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        perror("connect failed");
        closesocket(client_fd);
        WSACleanup();
        return 1;
    }

    // Send message to the server
    char *hello = "Hello from client";
    if (send(client_fd, hello, strlen(hello), 0) == SOCKET_ERROR) {
        perror("send failed");
        closesocket(client_fd);
        WSACleanup();
        return 1;
    }
    printf("Hello message sent\n");

    // Receive data from the server
    char buffer[1024] = {0};
    int valread = recv(client_fd, buffer, sizeof(buffer) - 1, 0); // Reserve space for null terminator
    if (valread == SOCKET_ERROR) {
        perror("recv failed");
        closesocket(client_fd);
        WSACleanup();
        return 1;
    }

    printf("Received from server: %s\n", buffer);

    // Close the socket
    closesocket(client_fd);

    // Cleanup Winsock
    WSACleanup();

    return 0;
}

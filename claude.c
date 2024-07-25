#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define SMTP_SERVER "smtp.gmail.com"
#define SMTP_PORT 587
#define BUFFER_SIZE 1024

void send_command(SOCKET sock, const char *command, char *response) {
    send(sock, command, strlen(command), 0);
    recv(sock, response, BUFFER_SIZE, 0);
    printf("Sent: %s", command);
    printf("Received: %s", response);
}

int main() {
    WSADATA wsa_data;
    SOCKET sock = INVALID_SOCKET;
    struct addrinfo *result = NULL, *ptr = NULL, hints;
    char buffer[BUFFER_SIZE];
    int iResult;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo(SMTP_SERVER, "587", &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a socket and connect to the server
    ptr = result;
    sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
    if (sock == INVALID_SOCKET) {
        printf("Error creating socket: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    iResult = connect(sock, ptr->ai_addr, (int) ptr->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        closesocket(sock);
        sock = INVALID_SOCKET;
    }

    freeaddrinfo(result);

    if (sock == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }
    // Receive initial greeting
    recv(sock, buffer, BUFFER_SIZE, 0);
    printf("Server: %s", buffer);

    // EHLO command
    send_command(sock, "EHLO example.com\r\n", buffer);

    // STARTTLS command
    send_command(sock, "STARTTLS\r\n", buffer);

    // At this point, you should upgrade the connection to use SSL/TLS
    // This requires additional libraries and is beyond the scope of this example

    // AUTH LOGIN command
    send_command(sock, "AUTH LOGIN\r\n", buffer);

    // Send Base64 encoded username
    send_command(sock, "dGl6emk3MEBnbWFpbC5jb20=\r\n", buffer);

    // Send Base64 encoded password
    send_command(sock, "bHJiaCB3Z3JrIGl5d3IgZ2xkdg==\r\n", buffer);

    // MAIL FROM command
    send_command(sock, "MAIL FROM:tizzi70@gmail.com\r\n", buffer);

    // RCPT TO command
    send_command(sock, "RCPT TO:andrew.ferro04@gmail.com\r\n", buffer);

    // DATA command
    send_command(sock, "DATA\r\n", buffer);

    // Send email content
    const char *email_content =
            "From: tizzi70@gmail.com\r\n"
            "To: andrew.ferro04@gmail.com\r\n"
            "Subject: Test Email\r\n\r\n"
            "This is a test email sent from a C program.\r\n"
            ".\r\n";
    send_command(sock, email_content, buffer);

    // QUIT command
    send_command(sock, "QUIT\r\n", buffer);

    // Cleanup
    closesocket(sock);
    WSACleanup();

    return 0;
}
#include<stdio.h>
#include<winsock2.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#pragma comment(lib, "ws2_32.lib") //Winsock Library

#define FROM_EMAIL "andrew.ferro04@gmail.com"
#define TO_EMAIL "tizzi70@gmail.com"
#define SUBJECT "Test Email from C Program"
#define BODY "This is a test email sent from a C program using SMTP."
char* base64(const char* input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    char* buffer;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines - write everything in one line
    BIO_write(b64, input, strlen(input));
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);
    BIO_set_close(b64, BIO_NOCLOSE);
    BIO_free_all(b64);

    buffer = (char*)malloc((bufferPtr->length + 1)*sizeof(char));
    memcpy(buffer, bufferPtr->data, bufferPtr->length);
    buffer[bufferPtr->length] = '\0';

    return buffer;
}


int main(int argc, char *argv[]) {
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in server;
    char *message, server_reply[2000];
    int recv_size;

    printf("\nInitialising Winsock...");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed. Error Code : %d", WSAGetLastError());
        return 1;
    }

    printf("Initialised.\n");

    //Create a socket
    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
        printf("Could not create socket : %d", WSAGetLastError());
    }

    printf("Socket created.\n");


    server.sin_family = AF_INET;
    server.sin_port = htons(587);
    struct hostent *host = gethostbyname("smtp.gmail.com");
    if (host == NULL) {
        printf("Unable to get host: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

// The h_addr_list field contains a list of IP addresses. We'll just use the first one.
    server.sin_addr.s_addr = *(u_long *) host->h_addr_list[0];
    //Connect to remote server
    if (connect(s, (struct sockaddr *) &server, sizeof(server)) < 0) {
        puts("connect error");
        return 1;
    }

    puts("Connected");


    printf("Connected to SMTP server.\n");


    recv_size = recv(s, server_reply, sizeof(server_reply), 0);
    if (recv_size == SOCKET_ERROR) {
        printf("Failed to receive server greeting: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 1;
    }
    printf("Server reply: %s\n", server_reply);

    // Send HELO command
    const char *helo_command = "HELO localhost\r\n";
    if (send(s, helo_command, strlen(helo_command), 0) == SOCKET_ERROR) {
        printf("Failed to send HELO command: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 1;
    }
    recv_size = recv(s, server_reply, sizeof(server_reply), 0);
    if (recv_size == SOCKET_ERROR) {
        printf("Failed to receive reply after HELO: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 1;
    }
    printf("Server reply: %s\n", server_reply);
    // Since we're just pinging, no data needs to be sent or received.
    // Send STARTTLS command (optional for secure connection)
    const char *starttls_command = "STARTTLS\r\n";
    if (send(s, starttls_command, strlen(starttls_command), 0) == SOCKET_ERROR) {
        printf("Failed to send STARTTLS command: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 1;
    }
    recv_size = recv(s, server_reply, sizeof(server_reply), 0);
    if (recv_size == SOCKET_ERROR) {
        printf("Failed to receive reply after STARTTLS: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 1;
    }
    printf("Server reply: %s\n", server_reply);
    // Send AUTH LOGIN command
    const char *auth_login_command = "AUTH LOGIN\r\n";
    if (send(s, auth_login_command, strlen(auth_login_command), 0) == SOCKET_ERROR) {
        printf("Failed to send AUTH LOGIN command: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 1;
    }
    recv_size = recv(s, server_reply, sizeof(server_reply), 0);
    if (recv_size == SOCKET_ERROR) {
        printf("Failed to receive reply after AUTH LOGIN: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 1;
    }
    printf("Server reply: %s\n", server_reply);

    // Send username
    char username[] = "andrew.ferro04@gmail.com";

    // Allocate memory for the encoded string, considering potential errors
    char *encoded_username = strcat(base64(username), "\r\n");
    printf("Encoded username: %s\n", encoded_username);
    if (send(s, encoded_username, strlen(encoded_username), 0) == SOCKET_ERROR) {
        printf("Failed to send encoded username: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return SOCKET_ERROR;
    }
    recv_size = recv(s, server_reply, sizeof(server_reply), 0);
    if (recv_size == SOCKET_ERROR) {
        printf("Failed to receive reply after sending username: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 1;
    }
    printf("Server reply: %s\n", server_reply);

    // Send password
    char password[] = "_HSbpF_5-mw9gaEkH3Ak0ww+R3EPi8";
    char *encoded_password = strcat(base64(password), "\r\n");
    if (send(s, encoded_password, strlen(encoded_password), 0) == SOCKET_ERROR) {
        printf("Failed to send encoded password: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 1;
    }
    recv_size = recv(s, server_reply, sizeof(server_reply), 0);
    if (recv_size == SOCKET_ERROR) {
        printf("Failed to receive reply after sending password: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 1;
    }
    printf("Server reply: %s\n", server_reply);
    // Close the connection
    closesocket(s);

    // Clean up Winsock
    WSACleanup();
}


#include<stdio.h>
#include<winsock2.h>
//#include <openssl/bio.h>
//#include <openssl/evp.h>
#pragma comment(lib, "ws2_32.lib") //Winsock Library

#define FROM_EMAIL "andrew.ferro04@gmail.com"
#define TO_EMAIL "tizzi70@gmail.com"
#define SUBJECT "Test Email from C Program"
#define BODY "This is a test email sent from a C program using SMTP."
//char* base64(const char* input) {
//    BIO *bio, *b64;
//    long length;
//    BUF_MEM *bufferPtr;
//    b64 = BIO_new(BIO_f_base64());
//    bio = BIO_new(BIO_s_mem());
//    bio = BIO_push(b64, bio);
//
//    BIO_write(bio, input, strlen(input));
//    BIO_flush(bio);
//    length = BIO_get_mem_data(bio, &bufferPtr);
//
//    char* base64Output = (char*)malloc((length + 1) * sizeof(char));
//    memcpy(base64Output, &bufferPtr, length);
//    base64Output[length] = '\0';
//
//    BIO_free_all(bio);
//
//    return base64Output;
//}
static const char encoding_table[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '+', '/'
};

size_t base64_encode(const unsigned char *input, size_t len, char *output) {
    size_t encoded_len = 4 * ((len + 2) / 3); // Calculate the estimated output length

    // Handle potential memory allocation failures gracefully
    if (output == NULL) {
        return 0; // Indicate error (no output buffer provided)
    }
    output[encoded_len] = '\0'; // Ensure null termination

    size_t i = 0, j = 0;
    while (len--) {
        unsigned char octet = input[i++];

        // Encode the first 6 bits
        output[j++] = encoding_table[octet >> 2];

        if (len == 0) {
            // Last byte: Pad with '=' if necessary
            output[j++] = (octet & 3) << 4 ? encoding_table[(octet & 3) << 4] : '=';
            output[j++] = '=';
            break;
        }

        unsigned char octet2 = input[i++];

        // Encode the next 6 bits
        output[j++] = encoding_table[(octet & 3) << 4 | (octet2 >> 4)];

        if (len == 0) {
            // Last byte or two bytes: Pad with '=' if necessary
            output[j++] = (octet2 & 15) << 2 ? encoding_table[(octet2 & 15) << 2] : '=';
            break;
        }

        unsigned char octet3 = input[i++];

        // Encode the last 6 bits
        output[j++] = encoding_table[(octet2 & 15) << 2 | (octet3 >> 6)];
        output[j++] = encoding_table[octet3 & 63];
    }

    return encoded_len; // Return the actual encoded length
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
    size_t username_len = strlen(username);

    // Allocate memory for the encoded string, considering potential errors
    char *encoded_username = malloc((username_len * 4 / 3) + 4);
    if (encoded_username == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return 1;
    }
    printf("Encoded username: %s\n", encoded_username);
    size_t encoded_len = base64_encode((unsigned char *)username, username_len, encoded_username);
    if (send(s, encoded_username, strlen(encoded_username), 0) == SOCKET_ERROR) {
        printf("Failed to send encoded username: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 1;
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
    const char *encoded_password = "X0hTYnBGXzUtbXc5Z2FFa0gzQWswd3crUjNFUGk4\r\n";
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


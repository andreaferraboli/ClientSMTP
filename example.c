#include<stdio.h>
#include<winsock2.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#pragma comment(lib, "ws2_32.lib") //Winsock Library
#define BUFFER_SIZE 1024

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
    printf("Server reply greetings: %s\n", server_reply);

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
    printf("Server reply helo: %s\n", server_reply);
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
    printf("Server reply STARTTLS: %s\n", server_reply);
    // Send HELO command again after STARTTLS
    const char *ehlo_command = "EHLO localhost\r\n";

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, s);

    // Perform the TLS handshake
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    printf("TLS handshake completed.\n");

    // Send EHLO command again over TLS
    if (SSL_write(ssl, ehlo_command, strlen(ehlo_command)) <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    recv_size = SSL_read(ssl, server_reply, BUFFER_SIZE);
    if (recv_size <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    server_reply[recv_size] = '\0'; // Null-terminate the response
    printf("Server reply EHLO over TLS: %s\n", server_reply);

    // Send AUTH LOGIN command
    const char *auth_login_command = "AUTH LOGIN\r\n";
    if (SSL_write(ssl, auth_login_command, strlen(auth_login_command)) <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    recv_size = SSL_read(ssl, server_reply, BUFFER_SIZE);
    if (recv_size <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    server_reply[recv_size] = '\0'; // Null-terminate the response
    printf("Server reply AUTH LOGIN: %s\n", server_reply);
    char username[] = "tizzi70@gmail.com";
    char *encoded_username = base64(username);
    if (SSL_write(ssl, encoded_username, strlen(encoded_username)) <= 0) {
        ERR_print_errors_fp(stderr);
        free(encoded_username);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    if (SSL_write(ssl, "\r\n", 2) <= 0) {
        ERR_print_errors_fp(stderr);
        free(encoded_username);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    free(encoded_username);

    recv_size = SSL_read(ssl, server_reply, BUFFER_SIZE);
    if (recv_size <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    server_reply[recv_size] = '\0'; // Null-terminate the response
    printf("Server reply username: %s\n", server_reply);

    // Encode password in base64 and send
    char password[] = "lrbh wgrk iywr gldv";
    char *encoded_password = base64(password);
    if (SSL_write(ssl, encoded_password, strlen(encoded_password)) <= 0) {
        ERR_print_errors_fp(stderr);
        free(encoded_password);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    if (SSL_write(ssl, "\r\n", 2) <= 0) {
        ERR_print_errors_fp(stderr);
        free(encoded_password);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    free(encoded_password);

    recv_size = SSL_read(ssl, server_reply, BUFFER_SIZE);
    if (recv_size <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    server_reply[recv_size] = '\0'; // Null-terminate the response
    printf("Server reply password: %s\n", server_reply);
// Send MAIL FROM command
    const char *mail_from_command = "MAIL FROM:<tizzi70@gmail.com>\r\n";
    if (SSL_write(ssl, mail_from_command, strlen(mail_from_command)) <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    recv_size = SSL_read(ssl, server_reply, BUFFER_SIZE);
    if (recv_size <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    server_reply[recv_size] = '\0'; // Null-terminate the response
    printf("Server reply MAIL FROM: %s\n", server_reply);

// Send RCPT TO command
    const char *rcpt_to_command = "RCPT TO:<andrew.ferro04@gmail.com>\r\n";
    if (SSL_write(ssl, rcpt_to_command, strlen(rcpt_to_command)) <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    recv_size = SSL_read(ssl, server_reply, BUFFER_SIZE);
    if (recv_size <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    server_reply[recv_size] = '\0'; // Null-terminate the response
    printf("Server reply RCPT TO: %s\n", server_reply);

// Send DATA command
    const char *data_command = "DATA\r\n";
    if (SSL_write(ssl, data_command, strlen(data_command)) <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    recv_size = SSL_read(ssl, server_reply, BUFFER_SIZE);
    if (recv_size <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    server_reply[recv_size] = '\0'; // Null-terminate the response
    printf("Server reply DATA: %s\n", server_reply);

// Send email headers and body
    const char *email_headers_and_body =
            "Subject: Test email\r\n"
            "From: tizzi70@gmail.com\r\n"
            "To: andrew.ferro04@gmail.com\r\n"
            "\r\n"
            "This is a test email sent from a C program.\r\n"
            ".\r\n";

    if (SSL_write(ssl, email_headers_and_body, strlen(email_headers_and_body)) <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    recv_size = SSL_read(ssl, server_reply, BUFFER_SIZE);
    if (recv_size <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    server_reply[recv_size] = '\0'; // Null-terminate the response
    printf("Server reply end of DATA: %s\n", server_reply);

// Send QUIT command to terminate the session
    const char *quit_command = "QUIT\r\n";
    if (SSL_write(ssl, quit_command, strlen(quit_command)) <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    recv_size = SSL_read(ssl, server_reply, BUFFER_SIZE);
    if (recv_size <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    server_reply[recv_size] = '\0'; // Null-terminate the response
    printf("Server reply QUIT: %s\n", server_reply);

    closesocket(s);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    WSACleanup();
}


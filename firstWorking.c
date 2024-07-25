#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/applink.c>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib") // Winsock Library
#define BUFFER_SIZE 1024

#define FROM_EMAIL "andrew.ferro04@gmail.com"
#define TO_EMAIL "tizzi70@gmail.com"
#define SUBJECT "Test Email from C Program"
#define BODY "This is a test email sent from a C program using SMTP."

void cleanup(SSL *ssl, SSL_CTX *ctx, SOCKET sock) {
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
    if (sock != INVALID_SOCKET) closesocket(sock);
    WSACleanup();
}

char *base64(const char *input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    char *buffer;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines
    BIO_write(b64, input, strlen(input));
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);
    BIO_set_close(b64, BIO_NOCLOSE);
    BIO_free_all(b64);

    buffer = (char *) malloc((bufferPtr->length + 1) * sizeof(char));
    memcpy(buffer, bufferPtr->data, bufferPtr->length);
    buffer[bufferPtr->length] = '\0';

    return buffer;
}

int send_command(SSL *ssl, const char *command) {
    if (SSL_write(ssl, command, strlen(command)) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

int recv_response(SSL *ssl, char *response) {
    int recv_size = SSL_read(ssl, response, BUFFER_SIZE);
    if (recv_size <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    response[recv_size] = '\0'; // Null-terminate the response
    return 0;
}

int main() {
    OPENSSL_malloc_init();
    WSADATA wsa;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char server_reply[BUFFER_SIZE];

    printf("\nInitializing Winsock...");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed. Error Code : %d", WSAGetLastError());
        return 1;
    }
    printf("Initialized.\n");

    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
        printf("Could not create socket : %d", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    printf("Socket created.\n");

    server.sin_family = AF_INET;
    server.sin_port = htons(587);
    struct hostent *host = gethostbyname("smtp.gmail.com");
    if (host == NULL) {
        printf("Unable to get host: %d\n", WSAGetLastError());
        cleanup(NULL, NULL, sock);
        return 1;
    }
    server.sin_addr.s_addr = *(u_long *) host->h_addr_list[0];

    if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
        printf("Connect error\n");
        cleanup(NULL, NULL, sock);
        return 1;
    }
    printf("Connected\n");

    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        printf("Unable to create SSL context\n");
        cleanup(NULL, NULL, sock);
        return 1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("TLS handshake completed.\n");

    // Send EHLO command
    if (send_command(ssl, "EHLO localhost\r\n") != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    if (recv_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("Server reply EHLO over TLS: %s\n", server_reply);

    // Authentication
    if (send_command(ssl, "AUTH LOGIN\r\n") != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    if (recv_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("Server reply AUTH LOGIN: %s\n", server_reply);

    char *encoded_username = base64(FROM_EMAIL);
    if (send_command(ssl, encoded_username) != 0) {
        free(encoded_username);
        cleanup(ssl, ctx, sock);
        return 1;
    }
    free(encoded_username);
    send_command(ssl, "\r\n");

    if (recv_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("Server reply username: %s\n", server_reply);

    char password[] = "lrbh wgrk iywr gldv";
    char *encoded_password = base64(password);
    if (send_command(ssl, encoded_password) != 0) {
        free(encoded_password);
        cleanup(ssl, ctx, sock);
        return 1;
    }
    free(encoded_password);
    send_command(ssl, "\r\n");

    if (recv_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("Server reply password: %s\n", server_reply);

    // Send MAIL FROM command
    char mail_from_command[BUFFER_SIZE];
    snprintf(mail_from_command, BUFFER_SIZE, "MAIL FROM:<%s>\r\n", FROM_EMAIL);
    if (send_command(ssl, mail_from_command) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    if (recv_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("Server reply MAIL FROM: %s\n", server_reply);

    // Send RCPT TO command
    char rcpt_to_command[BUFFER_SIZE];
    snprintf(rcpt_to_command, BUFFER_SIZE, "RCPT TO:<%s>\r\n", TO_EMAIL);
    if (send_command(ssl, rcpt_to_command) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    if (recv_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("Server reply RCPT TO: %s\n", server_reply);

    // Send DATA command
    if (send_command(ssl, "DATA\r\n") != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    if (recv_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("Server reply DATA: %s\n", server_reply);

    // Send email headers and body
    char email_headers_and_body[BUFFER_SIZE];
    snprintf(email_headers_and_body, BUFFER_SIZE,
             "Subject: %s\r\n"
             "From: %s\r\n"
             "To: %s\r\n"
             "\r\n"
             "%s\r\n.\r\n",
             SUBJECT, FROM_EMAIL, TO_EMAIL, BODY);

    if (send_command(ssl, email_headers_and_body) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    if (recv_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("Server reply end of DATA: %s\n", server_reply);

    // Send QUIT command
    if (send_command(ssl, "QUIT\r\n") != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    if (recv_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("Server reply QUIT: %s\n", server_reply);

    cleanup(ssl, ctx, sock);
    return 0;
}

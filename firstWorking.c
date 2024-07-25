#include <stdio.h>
#include <winsock2.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib") // Winsock Library

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
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines
    BIO_write(b64, input, strlen(input));
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);
    BIO_set_close(b64, BIO_NOCLOSE);
    BIO_free_all(b64);

    buffer = (char*)malloc((bufferPtr->length + 1) * sizeof(char));
    memcpy(buffer, bufferPtr->data, bufferPtr->length);
    buffer[bufferPtr->length] = '\0';

    return buffer;
}

int send_command(SOCKET s, SSL *ssl, const char *command) {
    printf("Debug: Sending command: %s\n", command); // Debug print
    if (SSL_write(ssl, command, strlen(command)) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

int receive_reply(SOCKET s, SSL *ssl, char *server_reply) {
    int recv_size = SSL_read(ssl, server_reply, BUFFER_SIZE);
    if (recv_size <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    server_reply[recv_size] = '\0';
    printf("Debug: Received reply: %s\n", server_reply); // Debug print
    return 0;
}

int main(int argc, char *argv[]) {
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in server;
    char server_reply[BUFFER_SIZE];
    int recv_size;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed. Error Code: %d\n", WSAGetLastError());
        return 1;
    }

    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
        printf("Could not create socket: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(587);
    struct hostent *host = gethostbyname("smtp.gmail.com");
    if (host == NULL) {
        printf("Unable to get host: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 1;
    }

    server.sin_addr.s_addr = *(u_long *)host->h_addr_list[0];

    if (connect(s, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("Connect error\n");
        closesocket(s);
        WSACleanup();
        return 1;
    }

    if (recv(s, server_reply, sizeof(server_reply), 0) == SOCKET_ERROR) {
        printf("Failed to receive server greeting: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 1;
    }

    if (send(s, "HELO localhost\r\n", 15, 0) == SOCKET_ERROR) {
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

    if (send(s, "STARTTLS\r\n", 10, 0) == SOCKET_ERROR) {
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

    SSL_library_init();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, s);

    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    if (send_command(s, ssl, "EHLO localhost\r\n") < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    if (receive_reply(s, ssl, server_reply) < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    if (send_command(s, ssl, "AUTH LOGIN\r\n") < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    if (receive_reply(s, ssl, server_reply) < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    char username[] = "tizzi70@gmail.com";
    char *encoded_username = base64(username);
    if (send_command(s, ssl, encoded_username) < 0 || send_command(s, ssl, "\r\n") < 0) {
        free(encoded_username);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    free(encoded_username);

    if (receive_reply(s, ssl, server_reply) < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    char password[] = "lrbh wgrk iywr gldv";
    char *encoded_password = base64(password);
    if (send_command(s, ssl, encoded_password) < 0 || send_command(s, ssl, "\r\n") < 0) {
        free(encoded_password);
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    free(encoded_password);

    if (receive_reply(s, ssl, server_reply) < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    const char *mail_from_command = "MAIL FROM:<tizzi70@gmail.com>\r\n";
    if (send_command(s, ssl, mail_from_command) < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    if (receive_reply(s, ssl, server_reply) < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    const char *rcpt_to_command = "RCPT TO:<andrew.ferro04@gmail.com>\r\n";
    if (send_command(s, ssl, rcpt_to_command) < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    if (receive_reply(s, ssl, server_reply) < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    const char *data_command = "DATA\r\n";
    if (send_command(s, ssl, data_command) < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    if (receive_reply(s, ssl, server_reply) < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    const char *email_headers_and_body =
            "Subject: Test email\r\n"
            "From: tizzi70@gmail.com\r\n"
            "To: andrew.ferro04@gmail.com\r\n"
            "\r\n"
            "This is a test email sent from a C program.\r\n"
            ".\r\n";
    if (send_command(s, ssl, email_headers_and_body) < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    if (receive_reply(s, ssl, server_reply) < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    const char *quit_command = "QUIT\r\n";
    if (send_command(s, ssl, quit_command) < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    if (receive_reply(s, ssl, server_reply) < 0) {
        closesocket(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    closesocket(s);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    WSACleanup();

    return 0;
}


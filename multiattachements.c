#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib") // Winsock Library
#define BUFFER_SIZE 1024
#define NUM_FILES 3

#define FROM_EMAIL "tizzi70@gmail.com"
#define TO_EMAIL "andrew.ferro04@gmail.com"
#define SUBJECT "Test Email from C Program"
#define BODY "This is a test email sent from a C program using SMTP."

void cleanup(SSL *ssl, SSL_CTX *ctx, SOCKET sock) {
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
    if (sock != INVALID_SOCKET) closesocket(sock);
    WSACleanup();
}

char *base64(const char *input, int length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    char *buffer;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);
    BIO_set_close(b64, BIO_NOCLOSE);
    BIO_free_all(b64);

    buffer = (char *) malloc((bufferPtr->length + 1) * sizeof(char));
    memcpy(buffer, bufferPtr->data, bufferPtr->length);
    buffer[bufferPtr->length] = '\0';

    return buffer;
}

int send_command(SOCKET sock, const char *command) {
    if (send(sock, command, strlen(command), 0) == SOCKET_ERROR) {
        printf("Failed to send command: %d\n", WSAGetLastError());
        return -1;
    }
    return 0;
}

int recv_response(SOCKET sock, char *response) {
    int recv_size = recv(sock, response, BUFFER_SIZE, 0);
    if (recv_size == SOCKET_ERROR) {
        printf("Failed to receive response: %d\n", WSAGetLastError());
        return -1;
    }
    response[recv_size] = '\0'; // Null-terminate the response
    return 0;
}

int send_ssl_command(SSL *ssl, const char *command) {
    if (SSL_write(ssl, command, strlen(command)) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

int recv_ssl_response(SSL *ssl, char *response) {
    int recv_size = SSL_read(ssl, response, BUFFER_SIZE);
    if (recv_size <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    response[recv_size] = '\0'; // Null-terminate the response
    return 0;
}

char *read_file(const char *filename, long *length) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Unable to open file %s\n", filename);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = (char *) malloc(*length);
    if (!buffer) {
        printf("Memory allocation failed\n");
        fclose(file);
        return NULL;
    }

    fread(buffer, 1, *length, file);
    fclose(file);
    return buffer;
}

const char *get_mime_type(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return "application/octet-stream";
    if (strcmp(dot, ".pdf") == 0) return "application/pdf";
    if (strcmp(dot, ".txt") == 0) return "text/plain";
    if (strcmp(dot, ".jpg") == 0 || strcmp(dot, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(dot, ".png") == 0) return "image/png";
    return "application/octet-stream";
}

int main() {
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

    if (recv(sock, server_reply, BUFFER_SIZE, 0) <= 0) {
        printf("Failed to receive server greeting\n");
        cleanup(NULL, NULL, sock);
        return 1;
    }
    printf("Server greeting: %s\n", server_reply);

    if (send_command(sock, "EHLO localhost\r\n") != 0) {
        cleanup(NULL, NULL, sock);
        return 1;
    }

    if (recv_response(sock, server_reply) != 0) {
        cleanup(NULL, NULL, sock);
        return 1;
    }
    printf("EHLO response: %s\n", server_reply);

    if (send_command(sock, "STARTTLS\r\n") != 0) {
        cleanup(NULL, NULL, sock);
        return 1;
    }

    if (recv_response(sock, server_reply) != 0) {
        cleanup(NULL, NULL, sock);
        return 1;
    }
    printf("STARTTLS response: %s\n", server_reply);

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

    if (send_ssl_command(ssl, "EHLO localhost\r\n") != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("EHLO response over TLS: %s\n", server_reply);

    if (send_ssl_command(ssl, "AUTH LOGIN\r\n") != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("AUTH LOGIN response: %s\n", server_reply);

    char *encoded_username = base64(FROM_EMAIL, strlen(FROM_EMAIL));
    if (send_ssl_command(ssl, encoded_username) != 0) {
        free(encoded_username);
        cleanup(ssl, ctx, sock);
        return 1;
    }
    free(encoded_username);
    send_ssl_command(ssl, "\r\n");

    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("Username response: %s\n", server_reply);

    char password[] = "lrbh wgrk iywr gldv";
    char *encoded_password = base64(password, strlen(password));
    if (send_ssl_command(ssl, encoded_password) != 0) {
        free(encoded_password);
        cleanup(ssl, ctx, sock);
        return 1;
    }
    free(encoded_password);
    send_ssl_command(ssl, "\r\n");

    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("Password response: %s\n", server_reply);

    char mail_from_command[BUFFER_SIZE];
    snprintf(mail_from_command, BUFFER_SIZE, "MAIL FROM:<%s>\r\n", FROM_EMAIL);
    if (send_ssl_command(ssl, mail_from_command) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("MAIL FROM response: %s\n", server_reply);

    char rcpt_to_command[BUFFER_SIZE];
    snprintf(rcpt_to_command, BUFFER_SIZE, "RCPT TO:<%s>\r\n", TO_EMAIL);
    if (send_ssl_command(ssl, rcpt_to_command) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("RCPT TO response: %s\n", server_reply);

    if (send_ssl_command(ssl, "DATA\r\n") != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("DATA response: %s\n", server_reply);

    const char *file_paths[NUM_FILES] = {
            "C:\\Users\\andre\\Downloads\\SNMP.pdf",
            "C:\\Users\\andre\\Downloads\\progetti (1).txt",
            "C:\\Users\\andre\\Downloads\\jim-rohn.jpeg"
    };

    // Parte della costruzione delle intestazioni dell'email prima del ciclo
    char email_headers[BUFFER_SIZE];
    snprintf(email_headers, sizeof(email_headers),
             "From: %s\r\n"
             "To: %s\r\n"
             "Subject: %s\r\n"
             "MIME-Version: 1.0\r\n"
             "Content-Type: multipart/mixed; boundary=\"boundary1\"\r\n"
             "\r\n"
             "--boundary1\r\n"
             "Content-Type: text/plain\r\n"
             "\r\n"
             "%s\r\n", FROM_EMAIL, TO_EMAIL, SUBJECT, BODY);

// Invia intestazioni dell'email
    if (send_ssl_command(ssl, email_headers) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

// Ciclo per inviare più file
    for (int i = 0; i < NUM_FILES; i++) {
        long file_length;
        char *file_content = read_file(file_paths[i], &file_length);
        if (!file_content) {
            cleanup(ssl, ctx, sock);
            return 1;
        }

        char *encoded_file_content = base64(file_content, file_length);
        free(file_content);

        // Costruisci la parte dell'email per ogni file
        char file_headers[BUFFER_SIZE];
        snprintf(file_headers, sizeof(file_headers),
                 "\r\n--boundary1\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Transfer-Encoding: base64\r\n"
                 "Content-Disposition: attachment; filename=\"%s\"\r\n"
                 "\r\n",
                 get_mime_type(file_paths[i]), strrchr(file_paths[i], '\\') + 1);

        // Invia intestazioni del file
        if (send_ssl_command(ssl, file_headers) != 0) {
            cleanup(ssl, ctx, sock);
            free(encoded_file_content);
            return 1;
        }

        // Invia contenuto del file codificato in blocchi
        int chunk_size = 512; // Dimensione del blocco
        for (long j = 0; j < strlen(encoded_file_content); j += chunk_size) {
            char chunk[chunk_size + 1];
            strncpy(chunk, encoded_file_content + j, chunk_size);
            chunk[chunk_size] = '\0';

            if (send_ssl_command(ssl, chunk) != 0) {
                cleanup(ssl, ctx, sock);
                free(encoded_file_content);
                return 1;
            }
        }
        free(encoded_file_content);
    }

// Concludi l'email
    const char *email_end = "\r\n--boundary1--\r\n.\r\n";
    if (send_ssl_command(ssl, email_end) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("End of DATA response: %s\n", server_reply);

    if (send_ssl_command(ssl, "QUIT\r\n") != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("QUIT response: %s\n", server_reply);


    cleanup(ssl, ctx, sock);
    return 0;
}

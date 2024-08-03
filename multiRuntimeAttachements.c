#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <commdlg.h>

#pragma comment(lib, "ws2_32.lib") // Winsock Library
#define BUFFER_SIZE 1024
#define MAX_RECIPIENTS 10




// Prototypes
void cleanup(SSL *ssl, SSL_CTX *ctx, SOCKET sock);
int send_command(SOCKET sock, const char *command);
int recv_response(SOCKET sock, char *response);
int send_ssl_command(SSL *ssl, const char *command);
int recv_ssl_response(SSL *ssl, char *response);
char *base64(const char *input, int length);
char *get_file_path();
char *read_file(const char *filename, long *file_length);
const char *get_mime_type(const char *filename);

int main() {
    WSADATA wsa;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char server_reply[BUFFER_SIZE];
    char FROM_EMAIL[100];
    char PASSWORD[100];
    char SUBJECT[BUFFER_SIZE];
    char BODY[BUFFER_SIZE];
    char to_emails[MAX_RECIPIENTS][100];
    char *file_paths[MAX_RECIPIENTS];
    int num_recipients = 0;
    int num_files = 0;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "Failed to initialize Winsock. Error Code: %d\n", WSAGetLastError());
        return 1;
    }

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Could not create socket. Error Code: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Setup server address structure
    server.sin_family = AF_INET;
    server.sin_port = htons(587);
    struct hostent *host = gethostbyname("smtp.gmail.com");
    if (host == NULL) {
        fprintf(stderr, "Unable to get host: %d\n", WSAGetLastError());
        cleanup(NULL, NULL, sock);
        return 1;
    }
    server.sin_addr.s_addr = *(u_long *) host->h_addr_list[0];
    char *ip = inet_ntoa(*(struct in_addr *) host->h_addr_list[0]);
    if (ip == NULL) {
        printf("inet_ntoa failed\n");
        return 1;
    }
    printf("Resolved IP address of gmail smtp: %s\n", ip);

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        fprintf(stderr, "Connect error\n");
        cleanup(NULL, NULL, sock);
        return 1;
    }

    // Receive server greeting
    if (recv(sock, server_reply, BUFFER_SIZE, 0) <= 0) {
        fprintf(stderr, "Failed to receive server greeting\n");
        cleanup(NULL, NULL, sock);
        return 1;
    }
    printf("Server greeting: %s\n", server_reply);

    // Send EHLO command
    if (send_command(sock, "EHLO localhost\r\n") != 0) {
        cleanup(NULL, NULL, sock);
        return 1;
    }

    // Receive EHLO response
    if (recv_response(sock, server_reply) != 0) {
        cleanup(NULL, NULL, sock);
        return 1;
    }
    printf("EHLO response: %s\n", server_reply);

    // Send STARTTLS command
    if (send_command(sock, "STARTTLS\r\n") != 0) {
        cleanup(NULL, NULL, sock);
        return 1;
    }

    // Receive STARTTLS response
    if (recv_response(sock, server_reply) != 0) {
        cleanup(NULL, NULL, sock);
        return 1;
    }
    printf("STARTTLS response: %s\n", server_reply);

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "Unable to create SSL context\n");
        cleanup(NULL, NULL, sock);
        return 1;
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        cleanup(ssl, ctx, sock);
        return 1;
    }

    // Send EHLO command over SSL
    if (send_ssl_command(ssl, "EHLO localhost\r\n") != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    // Receive EHLO response over SSL
    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    // Send AUTH LOGIN command
    if (send_ssl_command(ssl, "AUTH LOGIN\r\n") != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    // Receive AUTH LOGIN response
    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("AUTH LOGIN response: %s\n", server_reply);

    // Get sender email
    printf("Inserisci l'indirizzo email del mittente: ");
    fgets(FROM_EMAIL, sizeof(FROM_EMAIL), stdin);
    FROM_EMAIL[strcspn(FROM_EMAIL, "\n")] = 0; // Rimuovi il newline

    // Encode email in base64 and send it
    char *encoded_username = base64(FROM_EMAIL, strlen(FROM_EMAIL));
    if (send_ssl_command(ssl, encoded_username) != 0) {
        free(encoded_username);
        cleanup(ssl, ctx, sock);
        return 1;
    }
    free(encoded_username);
    send_ssl_command(ssl, "\r\n");

    // Receive username response
    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("Username response: %s\n", server_reply);

    // Get password
    printf("Inserisci la password: ");
    fgets(PASSWORD, sizeof(PASSWORD), stdin);
    PASSWORD[strcspn(PASSWORD, "\n")] = 0; // Rimuovi il newline

    // Encode password in base64 and send it
    char *encoded_password = base64(PASSWORD, strlen(PASSWORD));
    if (send_ssl_command(ssl, encoded_password) != 0) {
        free(encoded_password);
        cleanup(ssl, ctx, sock);
        return 1;
    }
    free(encoded_password);
    send_ssl_command(ssl, "\r\n");

    // Receive password response
    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("Password response: %s\n", server_reply);

    // Send MAIL FROM command
    char mail_from_command[BUFFER_SIZE];
    snprintf(mail_from_command, BUFFER_SIZE, "MAIL FROM:<%s>\r\n", FROM_EMAIL);
    if (send_ssl_command(ssl, mail_from_command) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    // Receive MAIL FROM response
    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    // Get recipient emails
    printf("Inserisci gli indirizzi email dei destinatari (massimo %d, inserisci 'fine' per terminare):\n", MAX_RECIPIENTS);
    while (num_recipients < MAX_RECIPIENTS) {
        printf("Destinatario %d: ", num_recipients + 1);
        fgets(to_emails[num_recipients], sizeof(to_emails[num_recipients]), stdin);
        to_emails[num_recipients][strcspn(to_emails[num_recipients], "\n")] = 0; // Rimuovi il newline

        if (strcmp(to_emails[num_recipients], "fine") == 0) {
            break;
        }
        num_recipients++;
    }

    for (int i = 0; i < num_recipients; i++) {
        char rcpt_to_command[BUFFER_SIZE];
        // Formatta il comando RCPT TO per l'indirizzo email corrente
        snprintf(rcpt_to_command, BUFFER_SIZE, "RCPT TO:<%s>\r\n", to_emails[i]);
        // Invia il comando RCPT TO al server
        if (send_ssl_command(ssl, rcpt_to_command) != 0) {
            fprintf(stderr, "Errore nell'invio del comando RCPT TO per %s\n", to_emails[i]);
            cleanup(ssl, ctx, sock);
            return 1;
        }
        // Riceve e verifica la risposta del server per il comando RCPT TO
        if (recv_ssl_response(ssl, server_reply) != 0) {
            fprintf(stderr, "Errore nella ricezione della risposta RCPT TO per %s\n", to_emails[i]);
            cleanup(ssl, ctx, sock);
            return 1;
        }
    }

    if (send_ssl_command(ssl, "DATA\r\n") != 0) {
        // Invia il comando DATA al server per iniziare l'invio del corpo dell'email
        cleanup(ssl, ctx, sock);
        return 1;
    }

// Riceve e verifica la risposta del server al comando DATA
    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

    char choice[3];
    while (1) {
        printf("Vuoi aggiungere un allegato? (s/n): ");
        fgets(choice, sizeof(choice), stdin);

        if (choice[0] == 'n' || choice[0] == 'N') {
            break; // Esce dal loop se l'utente non desidera aggiungere allegati
        }

        // Ottiene il percorso del file da aggiungere come allegato
        char *file_path = get_file_path();
        if (file_path) {
            file_paths[num_files++] = file_path;  // Aggiunge il percorso del file all'array
        } else {
            printf("Nessun file selezionato o errore nell'apertura del file.\n");
        }
    }

// Prepara l'intestazione "To:" con tutti gli indirizzi email dei destinatari
    char to_header[BUFFER_SIZE] = "To: ";
    for (int i = 0; i < num_recipients; i++) {
        strcat(to_header, to_emails[i]);
        if (i < num_recipients - 1) {
            strcat(to_header, ", ");
        }
    }
    strcat(to_header, "\r\n");

// Richiede e legge l'oggetto dell'email dall'utente
    printf("Inserisci l'oggetto dell'email: ");
    fgets(SUBJECT, sizeof(SUBJECT), stdin);
    SUBJECT[strcspn(SUBJECT, "\n")] = 0;

// Richiede e legge il corpo dell'email dall'utente
    printf("Inserisci il corpo dell'email: ");
    fgets(BODY, sizeof(BODY), stdin);
    BODY[strcspn(BODY, "\n")] = 0;

// Prepara le intestazioni dell'email e il corpo del messaggio
    char email_headers[BUFFER_SIZE * 2];  // Aumenta la dimensione del buffer per includere intestazioni e corpo
    snprintf(email_headers, sizeof(email_headers),
             "From: %s\r\n"
             "%s"
             "Subject: %s\r\n"
             "MIME-Version: 1.0\r\n"
             "Content-Type: multipart/mixed; boundary=\"boundary1\"\r\n"
             "\r\n"
             "--boundary1\r\n"
             "Content-Type: text/plain\r\n"
             "\r\n"
             "%s\r\n", FROM_EMAIL, to_header, SUBJECT, BODY);

// Invia le intestazioni dell'email al server
    if (send_ssl_command(ssl, email_headers) != 0) {
        fprintf(stderr, "Errore nell'invio delle intestazioni email\n");
        cleanup(ssl, ctx, sock);
        return 1;
    }

// Invia ciascun allegato
    for (int i = 0; i < num_files; i++) {
        long file_length;
        // Legge il contenuto del file
        char *file_content = read_file(file_paths[i], &file_length);
        if (!file_content) {
            fprintf(stderr, "Errore nella lettura del file: %s\n", file_paths[i]);
            cleanup(ssl, ctx, sock);
            return 1;
        }

        // Codifica il contenuto del file in base64
        char *encoded_file_content = base64(file_content, file_length);
        free(file_content);

        // Ottiene il tipo MIME del file
        const char *mime_type = get_mime_type(file_paths[i]);
        char file_headers[BUFFER_SIZE];
        snprintf(file_headers, sizeof(file_headers),
                 "\r\n--boundary1\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Transfer-Encoding: base64\r\n"
                 "Content-Disposition: attachment; filename=\"%s\"\r\n"
                 "\r\n",
                 mime_type, strrchr(file_paths[i], '\\') + 1);

        // Invia le intestazioni dell'allegato al server
        if (send_ssl_command(ssl, file_headers) != 0) {
            fprintf(stderr, "Errore nell'invio delle intestazioni del file\n");
            cleanup(ssl, ctx, sock);
            free(encoded_file_content);
            return 1;
        }

        // Invia il contenuto dell'allegato in blocchi
        int chunk_size = 512;
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

// Segnala la fine del messaggio email
    const char *email_end = "\r\n--boundary1--\r\n.\r\n";
    if (send_ssl_command(ssl, email_end) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("End of email sent\n");

// Riceve e verifica la risposta del server al termine dell'email
    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

// Invia il comando QUIT per terminare la sessione con il server
    if (send_ssl_command(ssl, "QUIT\r\n") != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }

// Riceve e verifica la risposta del server al comando QUIT
    if (recv_ssl_response(ssl, server_reply) != 0) {
        cleanup(ssl, ctx, sock);
        return 1;
    }
    printf("QUIT response: %s\n", server_reply);

// Pulisce e chiude le risorse
    cleanup(ssl, ctx, sock);

// Libera la memoria allocata per i percorsi dei file
    for (int i = 0; i < num_files; i++) {
        free(file_paths[i]);
    }

    return 0;
}

/**
 * @brief Cleans up SSL, SSL context, and socket resources.
 *
 * This function releases the resources associated with the SSL object,
 * SSL context, and socket. It also performs the necessary cleanup for
 * Winsock.
 *
 * @param ssl The SSL object to be freed. Can be NULL.
 * @param ctx The SSL context to be freed. Can be NULL.
 * @param sock The socket to be closed. Should be INVALID_SOCKET if not used.
 */
void cleanup(SSL *ssl, SSL_CTX *ctx, SOCKET sock) {
    // Se l'oggetto SSL è stato creato, chiude la connessione SSL
    if (ssl) SSL_shutdown(ssl);

    // Se l'oggetto SSL è stato creato, lo libera dalla memoria
    if (ssl) SSL_free(ssl);

    // Se il contesto SSL è stato creato, lo libera dalla memoria
    if (ctx) SSL_CTX_free(ctx);

    // Se il socket non è invalido, chiude il socket
    if (sock != INVALID_SOCKET) closesocket(sock);

    // Chiude l'inizializzazione della libreria Winsock
    WSACleanup();
}


/**
 * @brief Encodes a given input string to Base64 format.
 *
 * This function takes an input string and its length, and returns a
 * dynamically allocated string containing the Base64 encoded version
 * of the input. The caller is responsible for freeing the returned string.
 *
 * @param input The input string to be encoded.
 * @param length The length of the input string.
 * @return char* A dynamically allocated string containing the Base64
 *               encoded version of the input. Returns NULL if an error occurs.
 */
char *base64(const char *input, int length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    char *buffer;

    // Crea un oggetto BIO per la codifica Base64
    b64 = BIO_new(BIO_f_base64());

    // Crea un oggetto BIO in memoria per la scrittura
    bio = BIO_new(BIO_s_mem());

    // Collega il BIO per Base64 al BIO in memoria
    BIO_push(b64, bio);

    // Imposta il flag per ignorare le nuove righe nella codifica Base64
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines

    // Scrive i dati di input nel BIO Base64
    BIO_write(b64, input, length);

    // Assicura che tutti i dati siano scritti e completati
    BIO_flush(b64);

    // Ottiene un puntatore al buffer di memoria contenente i dati codificati
    BIO_get_mem_ptr(b64, &bufferPtr);

    // Imposta il flag per non chiudere automaticamente il BIO
    BIO_set_close(b64, BIO_NOCLOSE);

    // Libera tutte le risorse associate al BIO Base64
    BIO_free_all(b64);

    // Alloca memoria per il buffer di output e copia i dati codificati
    buffer = (char *) malloc((bufferPtr->length + 1) * sizeof(char));
    memcpy(buffer, bufferPtr->data, bufferPtr->length);
    buffer[bufferPtr->length] = '\0'; // Aggiunge il terminatore null alla fine del buffer

    return buffer;
}


/**
 * @brief Prompts the user to select a file and returns the file path.
 *
 * This function displays a file open dialog box, allowing the user to select a file.
 * It returns the path of the selected file as a dynamically allocated string.
 * The caller is responsible for freeing the returned string.
 *
 * @return char* A dynamically allocated string containing the file path of the selected file.
 *               Returns NULL if no file is selected or an error occurs.
 */
char *get_file_path() {
    OPENFILENAME ofn;       // Struttura che contiene le informazioni per la finestra di dialogo di apertura file
    char file_path[MAX_PATH] = "";  // Buffer per memorizzare il percorso del file

    // Inizializza la struttura OPENFILENAME a zero
    ZeroMemory(&ofn, sizeof(ofn));

    // Imposta le dimensioni della struttura
    ofn.lStructSize = sizeof(ofn);

    // Specifica il proprietario della finestra di dialogo (NULL indica nessun proprietario)
    ofn.hwndOwner = NULL;

    // Specifica il buffer dove verrà memorizzato il percorso del file selezionato
    ofn.lpstrFile = file_path;

    // Assicura che il buffer per il percorso del file sia vuoto all'inizio
    ofn.lpstrFile[0] = '\0';

    // Imposta la dimensione massima del buffer per il percorso del file
    ofn.nMaxFile = sizeof(file_path);

    // Specifica i filtri per i tipi di file da visualizzare nella finestra di dialogo
    ofn.lpstrFilter = "All Files\0*.*\0";

    // Imposta l'indice del filtro corrente (1 indica il primo filtro)
    ofn.nFilterIndex = 1;

    // Specifica il buffer per il titolo del file (non utilizzato)
    ofn.lpstrFileTitle = NULL;

    // Imposta la dimensione massima del buffer per il titolo del file (non utilizzato)
    ofn.nMaxFileTitle = 0;

    // Specifica la directory iniziale per la finestra di dialogo (NULL indica nessuna directory iniziale)
    ofn.lpstrInitialDir = NULL;

    // Imposta i flag per la finestra di dialogo:
    // - OFN_PATHMUSTEXIST: Il percorso selezionato deve esistere
    // - OFN_FILEMUSTEXIST: Il file selezionato deve esistere
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    // Mostra la finestra di dialogo di apertura file e verifica se l'utente ha selezionato un file
    if (GetOpenFileName(&ofn) == TRUE) {
        // Se un file è stato selezionato, restituisce una copia del percorso del file
        return strdup(file_path);
    }

    // Se l'utente non seleziona un file, restituisce NULL
    return NULL;
}


/**
 * @brief Sends a command to the server over a socket.
 *
 * This function sends a command string to the server using the specified socket.
 * It returns 0 on success and -1 on failure.
 *
 * @param sock The socket to send the command through.
 * @param command The command string to be sent.
 * @return int 0 on success, -1 on failure.
 */
int send_command(SOCKET sock, const char *command) {
    // Invia il comando attraverso il socket
    // La funzione send restituisce il numero di byte inviati o SOCKET_ERROR in caso di errore
    if (send(sock, command, strlen(command), 0) == SOCKET_ERROR) {
        // Se si verifica un errore durante l'invio, stampa un messaggio di errore
        // e il codice di errore restituito da WSAGetLastError()
        printf("Failed to send command: %d\n", WSAGetLastError());
        return -1;  // Restituisce -1 per indicare un errore
    }
    return 0;  // Restituisce 0 per indicare che l'invio è avvenuto con successo
}


/**
 * @brief Receives a response from the server over a socket.
 *
 * This function receives a response from the server using the specified socket.
 * It stores the response in the provided buffer and null-terminates it.
 * It returns 0 on success and -1 on failure.
 *
 * @param sock The socket to receive the response from.
 * @param response The buffer to store the received response.
 * @return int 0 on success, -1 on failure.
 */
int recv_response(SOCKET sock, char *response) {
    // Riceve i dati dal socket e li memorizza nel buffer 'response'
    // La funzione recv restituisce il numero di byte ricevuti, SOCKET_ERROR in caso di errore
    int recv_size = recv(sock, response, BUFFER_SIZE, 0);

    // Verifica se c'è stato un errore durante la ricezione
    if (recv_size == SOCKET_ERROR) {
        // Se si verifica un errore, stampa un messaggio di errore e il codice di errore restituito da WSAGetLastError()
        printf("Failed to receive response: %d\n", WSAGetLastError());
        return -1;  // Restituisce -1 per indicare un errore
    }

    // Aggiunge un terminatore null alla fine della risposta per trattarla come una stringa C
    response[recv_size] = '\0';

    return 0;  // Restituisce 0 per indicare che la ricezione è avvenuta con successo
}


/**
 * @brief Sends a command to the server over an SSL connection.
 *
 * This function sends a command string to the server using the specified SSL connection.
 * It returns 0 on success and -1 on failure.
 *
 * @param ssl The SSL connection to send the command through.
 * @param command The command string to be sent.
 * @return int 0 on success, -1 on failure.
 */
int send_ssl_command(SSL *ssl, const char *command) {
    // Scrive il comando nel flusso SSL
    // La funzione SSL_write restituisce il numero di byte scritti o un valore negativo in caso di errore
    if (SSL_write(ssl, command, strlen(command)) <= 0) {
        // Se si verifica un errore durante la scrittura, stampa gli errori di OpenSSL
        ERR_print_errors_fp(stderr);
        return -1;  // Restituisce -1 per indicare un errore
    }
    return 0;  // Restituisce 0 per indicare che la scrittura è avvenuta con successo
}


/**
 * @brief Receives a response from the server over an SSL connection.
 *
 * This function receives a response from the server using the specified SSL connection.
 * It stores the response in the provided buffer and null-terminates it.
 * It returns 0 on success and -1 on failure.
 *
 * @param ssl The SSL connection to receive the response from.
 * @param response The buffer to store the received response.
 * @return int 0 on success, -1 on failure.
 */
int recv_ssl_response(SSL *ssl, char *response) {
    // Legge i dati dalla connessione SSL e li memorizza nel buffer 'response'
    // La funzione SSL_read restituisce il numero di byte letti o un valore negativo in caso di errore
    int recv_size = SSL_read(ssl, response, BUFFER_SIZE);

    // Verifica se c'è stato un errore durante la lettura o se la connessione è stata chiusa
    if (recv_size <= 0) {
        // Se si verifica un errore, stampa gli errori di OpenSSL
        ERR_print_errors_fp(stderr);
        return -1;  // Restituisce -1 per indicare un errore
    }

    // Aggiunge un terminatore null alla fine della risposta per trattarla come una stringa C
    response[recv_size] = '\0';

    return 0;  // Restituisce 0 per indicare che la ricezione è avvenuta con successo
}


/**
 * @brief Reads the contents of a file into a dynamically allocated buffer.
 *
 * This function opens a file in binary mode, reads its contents into a
 * dynamically allocated buffer, and returns the buffer. The caller is
 * responsible for freeing the returned buffer.
 *
 * @param filename The name of the file to be read.
 * @param length A pointer to a long where the length of the file will be stored.
 * @return char* A dynamically allocated buffer containing the file contents.
 *               Returns NULL if the file cannot be opened or memory allocation fails.
 */
char *read_file(const char *filename, long *length) {
    // Apre il file in modalità binaria per la lettura
    FILE *file = fopen(filename, "rb");
    if (!file) {
        // Se non riesce ad aprire il file, stampa un messaggio d'errore e restituisce NULL
        printf("Unable to open file %s\n", filename);
        return NULL;
    }

    // Sposta il puntatore del file alla fine per determinare la dimensione del file
    fseek(file, 0, SEEK_END);
    *length = ftell(file);  // Ottiene la posizione del puntatore del file, che è la dimensione del file
    fseek(file, 0, SEEK_SET);  // Riporta il puntatore del file all'inizio

    // Alloca memoria per contenere il contenuto del file
    char *buffer = (char *) malloc(*length);
    if (!buffer) {
        // Se l'allocazione della memoria fallisce, stampa un messaggio d'errore e chiude il file
        printf("Memory allocation failed\n");
        fclose(file);
        return NULL;
    }

    // Legge il contenuto del file nel buffer
    fread(buffer, 1, *length, file);
    fclose(file);  // Chiude il file

    return buffer;  // Restituisce il buffer contenente il contenuto del file
}


/**
 * @brief Structure representing a MIME type.
 *
 * This structure contains the file extension and the corresponding MIME type.
 */
typedef struct {
    const char *extension; /**< The file extension. */
    const char *mime_type; /**< The corresponding MIME type. */
} MimeType;

/**
 * @brief Compares two MimeType structures by their extensions.
 *
 * This function is used as a comparison function for sorting and searching
 * MimeType structures by their file extensions.
 *
 * @param a Pointer to the first MimeType structure.
 * @param b Pointer to the second MimeType structure.
 * @return int A negative value if the first extension is less than the second,
 *             zero if they are equal, and a positive value if the first extension
 *             is greater than the second.
 */
static int mime_type_compare(const void *a, const void *b) {
    return strcmp(((const MimeType *) a)->extension, ((const MimeType *) b)->extension);
}

static MimeType mime_types[] = {
        {".aac",    "audio/aac"},
        {".abw",    "application/x-abiword"},
        {".arc",    "application/x-freearc"},
        {".avif",   "image/avif"},
        {".avi",    "video/x-msvideo"},
        {".azw",    "application/vnd.amazon.ebook"},
        {".bin",    "application/octet-stream"},
        {".bmp",    "image/bmp"},
        {".bz",     "application/x-bzip"},
        {".bz2",    "application/x-bzip2"},
        {".cda",    "application/x-cdf"},
        {".csh",    "application/x-csh"},
        {".css",    "text/css"},
        {".csv",    "text/csv"},
        {".doc",    "application/msword"},
        {".docx",   "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {".eot",    "application/vnd.ms-fontobject"},
        {".epub",   "application/epub+zip"},
        {".gz",     "application/gzip"},
        {".gif",    "image/gif"},
        {".htm",    "text/html"},
        {".html",   "text/html"},
        {".ico",    "image/vnd.microsoft.icon"},
        {".ics",    "text/calendar"},
        {".jar",    "application/java-archive"},
        {".jpeg",   "image/jpeg"},
        {".jpg",    "image/jpeg"},
        {".js",     "text/javascript"},
        {".json",   "application/json"},
        {".jsonld", "application/ld+json"},
        {".mid",    "audio/midi"},
        {".midi",   "audio/midi"},
        {".mjs",    "text/javascript"},
        {".mp3",    "audio/mpeg"},
        {".mp4",    "video/mp4"},
        {".mpeg",   "video/mpeg"},
        {".mpkg",   "application/vnd.apple.installer+xml"},
        {".odp",    "application/vnd.oasis.opendocument.presentation"},
        {".ods",    "application/vnd.oasis.opendocument.spreadsheet"},
        {".odt",    "application/vnd.oasis.opendocument.text"},
        {".oga",    "audio/ogg"},
        {".ogv",    "video/ogg"},
        {".ogx",    "application/ogg"},
        {".opus",   "audio/opus"},
        {".otf",    "font/otf"},
        {".png",    "image/png"},
        {".pdf",    "application/pdf"},
        {".php",    "application/x-httpd-php"},
        {".ppt",    "application/vnd.ms-powerpoint"},
        {".pptx",   "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
        {".rar",    "application/vnd.rar"},
        {".rtf",    "application/rtf"},
        {".sh",     "application/x-sh"},
        {".svg",    "image/svg+xml"},
        {".swf",    "application/x-shockwave-flash"},
        {".tar",    "application/x-tar"},
        {".tif",    "image/tiff"},
        {".tiff",   "image/tiff"},
        {".ts",     "video/mp2t"},
        {".ttf",    "font/ttf"},
        {".txt",    "text/plain"},
        {".vsd",    "application/vnd.visio"},
        {".wav",    "audio/wav"},
        {".weba",   "audio/webm"},
        {".webm",   "video/webm"},
        {".webp",   "image/webp"},
        {".woff",   "font/woff"},
        {".woff2",  "font/woff2"},
        {".xhtml",  "application/xhtml+xml"},
        {".xls",    "application/vnd.ms-excel"},
        {".xlsx",   "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        {".xml",    "application/xml"},
        {".xul",    "application/vnd.mozilla.xul+xml"},
        {".zip",    "application/zip"},
        {".3gp",    "video/3gpp"},
        {".3g2",    "video/3gpp2"},
        {".7z",     "application/x-7z-compressed"}
};


/**
 * @brief Determines the MIME type of a given file based on its extension.
 *
 * This function takes a filename, extracts its extension, and uses a binary search
 * to find the corresponding MIME type from a sorted array of MimeType structures.
 * If the extension is not found, it returns "application/octet-stream".
 *
 * @param filename The name of the file whose MIME type is to be determined.
 * @return const char* The MIME type corresponding to the file extension.
 *                     Returns "application/octet-stream" if the extension is not found.
 */
const char *get_mime_type(const char *filename) {
    // Calcola il numero di tipi MIME nella tabella 'mime_types'
    size_t num_mime_types = sizeof(mime_types) / sizeof(mime_types[0]);

    // Ordina la tabella dei tipi MIME utilizzando la funzione di confronto 'mime_type_compare'
    qsort(mime_types, num_mime_types, sizeof(MimeType), mime_type_compare);

    // Trova l'ultima occorrenza del carattere punto (.) nel nome del file
    const char *dot = strrchr(filename, '.');

    // Se non c'è un punto nel nome del file o il punto è il primo carattere, restituisce un tipo MIME generico
    if (!dot || dot == filename) {
        return "application/octet-stream";
    }

    // Crea una struttura MimeType con l'estensione del file per la ricerca
    MimeType key = {dot, NULL};

    // Cerca nella tabella ordinata 'mime_types' l'estensione del file
    MimeType *result = bsearch(&key, mime_types,
                               num_mime_types,
                               sizeof(MimeType), mime_type_compare);

    // Se trova un tipo MIME corrispondente, restituisce il tipo MIME trovato
    if (result) {
        return result->mime_type;
    } else {
        // Se non trova un tipo MIME corrispondente, restituisce un tipo MIME generico
        return "application/octet-stream";
    }
}

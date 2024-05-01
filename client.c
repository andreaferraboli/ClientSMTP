#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#define SMTP_SERVER "smtp.gmail.com"
#define SMTP_PORT 587

int main() {
  int sockfd;
  struct sockaddr_in server_addr;
  char buffer[1024];

  // Create a TCP socket
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket");
    exit(1);
  }

  // Set the SMTP server address
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(SMTP_PORT);
  server_addr.sin_addr.s_addr = inet_addr(SMTP_SERVER);

  // Connect to the SMTP server
  if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    perror("connect");
    exit(1);
  }

  // Receive the server's welcome banner
  int bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
  if (bytes_received < 0) {
    perror("recv");
    exit(1);
  }
  printf("%s\n", buffer);

  // Send the EHLO command
  strcpy(buffer, "EHLO\r\n");
  send(sockfd, buffer, strlen(buffer), 0);

  // Receive the EHLO response
  bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
  if (bytes_received < 0) {
    perror("recv");
    exit(1);
  }
  printf("%s\n", buffer);

  // Send the AUTH LOGIN command
  strcpy(buffer, "AUTH LOGIN\r\n");
  send(sockfd, buffer, strlen(buffer), 0);

  // Receive the username request
  bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
  if (bytes_received < 0) {
    perror("recv");
    exit(1);
  }
  printf("%s\n", buffer);

  // Get username and password from user input (not secure)
  char username[1024];
  char password[1024];
  printf("Enter your username: ");
  scanf("%s", username);
  printf("Enter your password: ");
  scanf("%s", password);

  // Send the username (plain text)
  send(sockfd, username, strlen(username), 0);

  // Receive the password request
  bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
  if (bytes_received < 0) {
    perror("recv");
    exit(1);
  }
  printf("%s\n", buffer);

  // Send the password (plain text)
  send(sockfd, password, strlen(password), 0);

  // Receive the authentication response
  bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
  if (bytes_received < 0) {
    perror("recv");
    exit(1);
  }
  printf("%s\n", buffer);

  // ... (Implement sending the email message, QUIT, and closing the socket)

  // Send the QUIT command to terminate the connection
  strcpy(buffer, "QUIT\r\n");
  send(sockfd, buffer, strlen(buffer), 0);

  // Receive the QUIT response
  bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
  if (bytes_received < 0) {
    perror("recv");
    exit(1);
  }
  printf("%s\n", buffer);

  // Close the socket
  close(sockfd);

  return 0;
}

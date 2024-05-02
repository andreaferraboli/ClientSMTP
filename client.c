#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <Ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ws2tcpip.lib")

#define SMTP_SERVER "smtp.gmail.com"
#define SMTP_PORT 587


int main() {
  // Initialize Winsock
  WSADATA wsaData;
  int wsaStart = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (wsaStart != 0) {
    printf("WSAStartup failed with error: %d\n", wsaStart);
    return 1;
  }

  int sockfd;
  struct sockaddr_in server_addr;
  char buffer[1024];

  // Create a TCP socket
  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sockfd == INVALID_SOCKET) {
    printf("socket failed with error: %d\n", WSAGetLastError());
    WSACleanup();
    return 1;
  }
  printf("Socket connected successfully\n");

  // Set the SMTP server address
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(SMTP_PORT);
  printf("server address",&server_addr.sin_addr);
  if (InetPtonA(AF_INET, SMTP_SERVER, &server_addr.sin_addr) <= 0) {
    printf("inet_pton failed with error: %d\n", WSAGetLastError());
    closesocket(sockfd);
    WSACleanup();
    return 1;
  }

  // Connect to the SMTP server
  if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
    printf("connect failed with error: %d\n", WSAGetLastError());
    closesocket(sockfd);
    WSACleanup();
    return 1;
  }
  printf("Connected to SMTP server\n");

  // ... (Rest of the code for receiving welcome banner, sending EHLO etc. with modifications for secure authentication)

  // Send the QUIT command to terminate the connection
  strcpy(buffer, "QUIT\r\n");
  send(sockfd, buffer, strlen(buffer), 0);

  // Receive the QUIT response
  int bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
  if (bytes_received < 0) {
    printf("recv failed with error: %d\n", WSAGetLastError());
    closesocket(sockfd);
    WSACleanup();
    return 1;
  }
  printf("%s\n", buffer);

  // Close the socket
  closesocket(sockfd);

  // Clean up Winsock
  WSACleanup();

  return 0;
}

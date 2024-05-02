#include<stdio.h>
#include<winsock2.h>

#pragma comment(lib,"ws2_32.lib") //Winsock Library

#define FROM_EMAIL "andrew.ferro04@gmail.com"
#define TO_EMAIL "tizzi70@gmail.com"
#define SUBJECT "Test Email from C Program"
#define BODY "This is a test email sent from a C program using SMTP."
int main(int argc , char *argv[])
{
	WSADATA wsa;
	SOCKET s;
	struct sockaddr_in server;
	char *message , server_reply[2000];
	int recv_size;

	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
	{
		printf("Failed. Error Code : %d",WSAGetLastError());
		return 1;
	}
	
	printf("Initialised.\n");
	
	//Create a socket
	if((s = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP )) == INVALID_SOCKET)
	{
		printf("Could not create socket : %d" , WSAGetLastError());
	}

	printf("Socket created.\n");
	
	
	server.sin_addr.s_addr = inet_addr("108.177.127.108");
	server.sin_family = AF_INET;
	server.sin_port = htons( 587 );

	//Connect to remote server
	if (connect(s , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
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
  const char* helo_command = "HELO localhost\r\n";
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
    const char* starttls_command = "STARTTLS\r\n";
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
    const char* auth_login_command = "AUTH LOGIN\r\n";
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
    const char* encoded_username = "YW5kcmV3LmZlcnJvMDRAZ21haWwuY29tCg==\r\n";
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
    const char* encoded_password = "X0hTYnBGXzUtbXc5Z2FFa0gzQWswd3crUjNFUGk4\r\n";
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


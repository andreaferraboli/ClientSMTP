#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>  // Include for InetPtonA

#pragma comment(lib, "ws2_32.lib") // Link with Winsock library
#pragma comment(lib, "ws2tcpip.lib") // Link with ws2tcpip library

#define NS_INADDRSZ  4  /* IPv4 address size */
#define NS_INTADDRSZ 16  /* IPv6 address size */

// No need for inet_pton and its helper functions
// as we'll use the standard function InetPtonA

// Function to convert an IP address string to binary form
int convert_ip_address(int af, const char *src, char *dst) {
    int result = InetPtonA(af, src, dst);
    if (result <= 0) {
        printf("Failed to convert IP address: %d\n", WSAGetLastError());
        return -1; // Or handle error differently
    }
    return 1;
}

int main() {
    // ... (Rest of your code)

    char ip_address[] = "127.0.0.1"; // Example IPv4 address
    int result = convert_ip_address(AF_INET, ip_address, "smtp.gmail.com");
    if (result == 1) {
        printf("Successfully converted IPv4 address\n");
    } else {
        printf("Error converting IPv4 address\n");
    }

    // ...
}

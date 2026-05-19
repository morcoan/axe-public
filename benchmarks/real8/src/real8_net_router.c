#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

static void route_copy(SOCKET sock, int route_id) {
    char scratch[112];
    int len = 0;
    recv(sock, (char *)&len, sizeof(len), 0);
    char *packet = (char *)malloc((size_t)len);
    if (packet != NULL) {
        recv(sock, packet, len, 0);
        if (route_id == 7) {
            memcpy(scratch, packet, (size_t)len);
        }
        free(packet);
    }
}

static void route_alloc(SOCKET sock) {
    int units = 0;
    recv(sock, (char *)&units, sizeof(units), 0);
    char *table = (char *)malloc((size_t)units);
    if (table != NULL) {
        recv(sock, table, units, 0);
        free(table);
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--axe-probe") == 0) {
        puts("AXE_REAL8_PROBE:net_router");
        return 0;
    }
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "copy") == 0) route_copy(sock, 7);
    if (argc > 1 && strcmp(argv[1], "alloc") == 0) route_alloc(sock);
    closesocket(sock);
    WSACleanup();
    return 0;
}

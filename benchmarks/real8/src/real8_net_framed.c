#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

static int frame_length(SOCKET sock) {
    int header[2] = {0, 0};
    recv(sock, (char *)header, sizeof(header), 0);
    return header[1];
}

static void framed_copy(SOCKET sock) {
    char packet[192];
    int len = frame_length(sock);
    char *payload = (char *)malloc((size_t)len);
    if (payload != NULL) {
        recv(sock, payload, len, 0);
        memcpy(packet, payload, (size_t)len);
        free(payload);
    }
}

static void framed_alloc(SOCKET sock) {
    int len = frame_length(sock);
    char *packet = (char *)malloc((size_t)len);
    if (packet != NULL) {
        recv(sock, packet, len, 0);
        free(packet);
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--axe-probe") == 0) {
        puts("AXE_REAL8_PROBE:net_framed");
        return 0;
    }
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "frame-copy") == 0) framed_copy(sock);
    if (argc > 1 && strcmp(argv[1], "frame-alloc") == 0) framed_alloc(sock);
    closesocket(sock);
    WSACleanup();
    return 0;
}

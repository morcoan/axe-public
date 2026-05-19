#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

static void copy_packet(SOCKET sock) {
    char dst[128];
    int len = 0;
    recv(sock, (char *)&len, sizeof(len), 0);
    char *src = (char *)malloc((size_t)len);
    if (src != NULL) {
        recv(sock, src, len, 0);
        memcpy(dst, src, (size_t)len);
        free(src);
    }
}

static void allocate_request(SOCKET sock) {
    unsigned int size = 0;
    recv(sock, (char *)&size, sizeof(size), 0);
    char *buf = (char *)malloc(size);
    if (buf != NULL) {
        recv(sock, buf, (int)size, 0);
        free(buf);
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--axe-probe") == 0) {
        puts("AXE_REAL8_PROBE:net_triplet");
        return 0;
    }
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "copy") == 0) copy_packet(sock);
    if (argc > 1 && strcmp(argv[1], "alloc") == 0) allocate_request(sock);
    closesocket(sock);
    WSACleanup();
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

static int read_remote_len(SOCKET sock) {
    int len = 0;
    recv(sock, (char *)&len, sizeof(len), 0);
    return len;
}

static void dispatch_copy(SOCKET sock) {
    char frame[96];
    int len = read_remote_len(sock);
    char *body = (char *)malloc((size_t)len);
    if (body != NULL) {
        recv(sock, body, len, 0);
        memcpy(frame, body, (size_t)len);
        free(body);
    }
}

static void dispatch_alloc(SOCKET sock) {
    int request_size = read_remote_len(sock);
    char *request = (char *)malloc((size_t)request_size);
    if (request != NULL) {
        recv(sock, request, request_size, 0);
        free(request);
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--axe-probe") == 0) {
        puts("AXE_REAL8_PROBE:net_dispatch");
        return 0;
    }
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "route-a") == 0) dispatch_copy(sock);
    if (argc > 1 && strcmp(argv[1], "route-b") == 0) dispatch_alloc(sock);
    closesocket(sock);
    WSACleanup();
    return 0;
}

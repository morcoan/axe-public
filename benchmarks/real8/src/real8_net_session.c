#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

typedef struct Session {
    SOCKET sock;
    int last_size;
} Session;

static void session_read_blob(Session *session) {
    char local[160];
    int n = 0;
    recv(session->sock, (char *)&n, sizeof(n), 0);
    session->last_size = n;
    char *remote = (char *)malloc((size_t)n);
    if (remote != NULL) {
        recv(session->sock, remote, n, 0);
        memcpy(local, remote, (size_t)n);
        free(remote);
    }
}

static void session_alloc_blob(Session *session) {
    unsigned int bytes = 0;
    recv(session->sock, (char *)&bytes, sizeof(bytes), 0);
    char *remote = (char *)malloc(bytes);
    if (remote != NULL) {
        recv(session->sock, remote, (int)bytes, 0);
        free(remote);
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--axe-probe") == 0) {
        puts("AXE_REAL8_PROBE:net_session");
        return 0;
    }
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    Session session;
    session.sock = socket(AF_INET, SOCK_STREAM, 0);
    session.last_size = 0;
    if (session.sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "blob") == 0) session_read_blob(&session);
    if (argc > 1 && strcmp(argv[1], "reserve") == 0) session_alloc_blob(&session);
    closesocket(session.sock);
    WSACleanup();
    return 0;
}

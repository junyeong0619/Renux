#include "exec_utils.h"

#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>

#define PIPE_READ  0
#define PIPE_WRITE 1
#define RELAY_BUF  4096

extern char **environ;

int exec_command(int output_fd, const char *path, char *const argv[]) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[PIPE_READ]);
        close(pipefd[PIPE_WRITE]);
        return -1;
    }

    if (pid == 0) {
        /* 자식: stdout/stderr → pipe write end */
        close(pipefd[PIPE_READ]);
        dup2(pipefd[PIPE_WRITE], STDOUT_FILENO);
        dup2(pipefd[PIPE_WRITE], STDERR_FILENO);
        close(pipefd[PIPE_WRITE]);

        execve(path, argv, environ);
        /* execve 실패 시 즉시 종료 (부모에서 waitpid로 감지) */
        _exit(127);
    }

    /* 부모: pipe read end → output_fd 로 중계 */
    close(pipefd[PIPE_WRITE]);

    char buf[RELAY_BUF];
    ssize_t n;
    while ((n = read(pipefd[PIPE_READ], buf, sizeof(buf))) > 0) {
        ssize_t sent = 0;
        while (sent < n) {
            ssize_t w = write(output_fd, buf + sent, n - sent);
            if (w < 0) break;
            sent += w;
        }
    }
    close(pipefd[PIPE_READ]);

    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

char *exec_command_buf(const char *path, char *const argv[], size_t *out_len) {
    *out_len = 0;
    int pipefd[2];
    if (pipe(pipefd) < 0) return NULL;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[PIPE_READ]);
        close(pipefd[PIPE_WRITE]);
        return NULL;
    }

    if (pid == 0) {
        close(pipefd[PIPE_READ]);
        dup2(pipefd[PIPE_WRITE], STDOUT_FILENO);
        dup2(pipefd[PIPE_WRITE], STDERR_FILENO);
        close(pipefd[PIPE_WRITE]);
        execve(path, argv, environ);
        _exit(127);
    }

    close(pipefd[PIPE_WRITE]);

    /* 동적 버퍼에 모든 출력 수집 */
    size_t capacity = 4096, len = 0;
    char *buf = (char *)malloc(capacity);
    if (!buf) { close(pipefd[PIPE_READ]); waitpid(pid, NULL, 0); return NULL; }

    ssize_t n;
    while ((n = read(pipefd[PIPE_READ], buf + len, capacity - len)) > 0) {
        len += (size_t)n;
        if (len == capacity) {
            capacity *= 2;
            char *tmp = (char *)realloc(buf, capacity);
            if (!tmp) { free(buf); close(pipefd[PIPE_READ]); waitpid(pid, NULL, 0); return NULL; }
            buf = tmp;
        }
    }
    close(pipefd[PIPE_READ]);

    int status;
    waitpid(pid, &status, 0);

    *out_len = len;
    return buf; /* 호출자가 free() 해야 함 */
}

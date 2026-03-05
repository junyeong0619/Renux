#ifndef EXEC_UTILS_H
#define EXEC_UTILS_H

#include <stddef.h>

/*
 * exec_command: 자식 프로세스 출력을 output_fd(일반 소켓 fd)로 직접 전송
 * popen() 대체 — 쉘을 경유하지 않아 메타문자 인젝션 원천 차단
 * 반환값: 자식 종료 코드, 실패 시 -1
 */
int exec_command(int output_fd, const char *path, char *const argv[]);

/*
 * exec_command_buf: 자식 프로세스 출력을 동적 버퍼에 수집
 * TLS 소켓처럼 fd에 직접 쓸 수 없는 경우에 사용
 * 반환값: 힙 할당된 버퍼 (호출자가 free() 해야 함), 실패 시 NULL
 * *out_len 에 실제 바이트 수 저장
 */
char *exec_command_buf(const char *path, char *const argv[], size_t *out_len);

#endif // EXEC_UTILS_H

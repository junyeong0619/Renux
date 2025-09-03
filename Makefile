# 컴파일러 지정
CC = gcc

# 컴파일 옵션: -g (디버깅 정보 포함), -Wall (모든 경고 출력)
CFLAGS = -g -Wall

# 최종적으로 만들 실행 파일 목록
TARGETS = server client

# 기본 규칙: 그냥 "make"를 입력하면 all 규칙이 실행됨
all: $(TARGETS)

# 서버 실행 파일 생성 규칙
# server는 server/ 디렉토리의 .c 파일들에 의존하며, ncurses 라이브러리가 필요함
server: server/server.c server/tui.c server/service.c
	$(CC) $(CFLAGS) -o server server/server.c server/tui.c server/service.c -lncurses

# 클라이언트 실행 파일 생성 규칙
# client는 client/ 디렉토리의 .c 파일들에 의존하며, ncurses와 pthread 라이브러리가 필요함
client: client/client.c client/tui.c
	$(CC) $(CFLAGS) -o client client/client.c client/tui.c -lncurses -lpthread

# 이전 빌드 결과물 삭제 규칙
clean:
	rm -f $(TARGETS)

# all과 clean은 실제 파일 이름이 아니라는 것을 명시 (Phony target)
.PHONY: all clean
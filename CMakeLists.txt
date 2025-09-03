cmake_minimum_required(VERSION 3.29)
project(Renux C)

set(CMAKE_C_STANDARD 99)

add_executable(server
        server/server.c
        server/tui.c
        server/service.c
        server/service.h
)
target_link_libraries(server -lncurses)

add_executable(client
        client/client.c
        client/tui.c
)
target_link_libraries(client -lncurses)
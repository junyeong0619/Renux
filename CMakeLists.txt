cmake_minimum_required(VERSION 3.29)
project(Renux C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)

add_executable(renux
        monitoring/monitor.cpp
)


add_executable(server
        server/server.c
        server/tui.c
        server/service.c
        server/service.h
        utils/ssl_utils.c
        utils/ssl_utils.h
        utils/log.c
        utils/log.h
)
target_link_libraries(server -lncurses)

add_executable(client
        client/client.c
        client/tui.c
        utils/ssl_utils.c
        utils/ssl_utils.h
        utils/log.c
        utils/log.h
)
target_link_libraries(client -lncurses)
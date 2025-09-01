cmake_minimum_required(VERSION 3.29)
project(Renux C)

set(CMAKE_C_STANDARD 99)


add_executable(server
        server/server.c
)


add_executable(client
        client/client.c
)
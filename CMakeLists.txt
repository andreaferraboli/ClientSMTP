cmake_minimum_required(VERSION 3.28)
project(ClientSMTP C)

set(CMAKE_C_STANDARD 11)

add_executable(ClientSMTP
        multiRuntimeAttachmentsGmail.c
        final.c)

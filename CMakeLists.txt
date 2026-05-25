cmake_minimum_required(VERSION 3.10)
project(SC_Crypto C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /O2)
else()
    add_compile_options(-Wall -Wextra -O2)
endif()

add_executable(Latino_encrypt
        main.c
        salsa20.c salsa20.h
        chacha20.c chacha20.h
        stream_modes.c stream_modes.h
        bignr.c bignr.h
        rsa.c rsa.h
)

target_include_directories(Latino_encrypt PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--stack,8388608")
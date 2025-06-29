cmake_minimum_required(VERSION 3.12)
project(ping_mac VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF) 

# Проверка всех необходимых системных заголовков
include(CheckIncludeFileCXX)
set(REQUIRED_HEADERS
    arpa/inet.h
    netinet/ip_icmp.h
    netinet/if_ether.h
    netinet/ether.h
    sys/socket.h
    unistd.h
    netdb.h
    linux/if_packet.h
    sys/ioctl.h
    net/if.h
)

foreach(header ${REQUIRED_HEADERS})
    check_include_file_cxx(${header} HAVE_${header})
    if(NOT HAVE_${header})
        message(FATAL_ERROR "Не найден обязательный заголовочный файл: ${header}")
    endif()
endforeach()


add_executable(RawSocket-Utility main.cpp)



if(UNIX AND NOT APPLE)
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -pedantic)
    target_link_libraries(${PROJECT_NAME} PRIVATE pthread)
endif()

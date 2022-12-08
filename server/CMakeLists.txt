cmake_minimum_required(VERSION 3.22)
project(dns_server C)

enable_testing()

set(CMAKE_C_STANDARD 11)

add_executable(dns_server dns.c main.c)
target_link_libraries(dns_server PUBLIC m)

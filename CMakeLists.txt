cmake_minimum_required(VERSION 3.7)
project(esp-mqtt)

set(CMAKE_C_STANDARD 99)

include_directories(
        lwmqtt/include)

set(SOURCE_FILES
        esp-lwmqtt.c
        esp-lwmqtt.h)

add_library(esp-mqtt ${SOURCE_FILES})

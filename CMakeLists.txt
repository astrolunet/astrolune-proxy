cmake_minimum_required(VERSION 3.20)
project(astrolune-proxy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(astrolune_proxy STATIC
    src/socks5_proxy.cpp
    src/proxy_connector.cpp
    src/astrolune_connect.cpp
    src/gateway/lune_gateway.cpp
)

target_include_directories(astrolune_proxy PUBLIC include)

add_executable(astrolune-connect
    src/main.cpp
)

target_link_libraries(astrolune-connect PRIVATE astrolune_proxy)

install(TARGETS astrolune-connect RUNTIME DESTINATION bin)

cmake_minimum_required(VERSION 3.14)
project(netrecon_sdn_plugin CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(netrecon_lib STATIC src/netrecon.cpp)
target_include_directories(netrecon_lib PUBLIC include)

add_executable(test_netrecon tests/test_netrecon.cpp)
target_link_libraries(test_netrecon netrecon_lib)

add_executable(test_sixdof tests/test_sixdof.cpp)
target_include_directories(test_sixdof PRIVATE include)
enable_testing()
add_test(NAME netrecon COMMAND test_netrecon)
add_test(NAME netrecon_sixdof COMMAND test_sixdof)

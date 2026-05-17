cmake_minimum_required(VERSION 3.20)
project(DevShadow VERSION 1.0)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find our packages
find_package(ftxui CONFIG REQUIRED)
find_path(ASIO_INCLUDE_DIR asio.hpp REQUIRED)

add_executable(shadow src/main.cpp)

# Tell the compiler where the Asio headers are
target_include_directories(shadow PRIVATE ${ASIO_INCLUDE_DIR})
target_link_libraries(shadow PRIVATE ftxui::screen ftxui::dom ftxui::component)
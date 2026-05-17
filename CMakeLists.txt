cmake_minimum_required(VERSION 3.20)

# Name your project
project(DevShadow VERSION 1.0)

# Enforce Modern C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find the library we just downloaded with vcpkg
find_package(ftxui CONFIG REQUIRED)

# Tell it where our code is
add_executable(shadow src/main.cpp)

# Link the terminal graphics to our app
target_link_libraries(shadow PRIVATE ftxui::screen ftxui::dom ftxui::component)
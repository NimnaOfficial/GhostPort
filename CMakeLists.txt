cmake_minimum_required(VERSION 3.20)
project(DevShadow VERSION 3.5)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# ── Dependency Resolution (vcpkg with automatic FetchContent fallback) ─────────
find_package(ftxui CONFIG QUIET)
if(NOT ftxui_FOUND)
    message(STATUS "[GhostPort] FTXUI not found via system/vcpkg. Fetching via FetchContent...")
    include(FetchContent)
    FetchContent_Declare(
        ftxui
        GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
        GIT_TAG v5.0.0
    )
    FetchContent_MakeAvailable(ftxui)
endif()

find_path(ASIO_INCLUDE_DIR asio.hpp QUIET)
if(NOT ASIO_INCLUDE_DIR)
    message(STATUS "[GhostPort] Asio not found via system/vcpkg. Fetching via FetchContent...")
    include(FetchContent)
    FetchContent_Declare(
        asio
        GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
        GIT_TAG asio-1-30-2
    )
    FetchContent_GetProperties(asio)
    if(NOT asio_POPULATED)
        FetchContent_Populate(asio)
        set(ASIO_INCLUDE_DIR ${asio_SOURCE_DIR}/asio/include)
    endif()
endif()

# ── Executable ────────────────────────────────────────────────────────────────
add_executable(shadow src/main.cpp)
target_include_directories(shadow PRIVATE ${ASIO_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/src)

# ── Platform Linking ──────────────────────────────────────────────────────────
if(WIN32)
    # Windows: PDH for telemetry, ws2_32 for Winsock, shell32 for ShellExecuteEx, psapi for memory
    target_link_libraries(shadow PRIVATE
        ftxui::screen ftxui::dom ftxui::component
        pdh ws2_32 shell32 psapi)

elseif(APPLE)
    # macOS: Mach APIs (host_processor_info, vm_statistics) + libproc
    target_link_libraries(shadow PRIVATE
        ftxui::screen ftxui::dom ftxui::component
        "-framework CoreFoundation")

else()
    # Linux: pthreads for std::thread
    find_package(Threads REQUIRED)
    target_link_libraries(shadow PRIVATE
        ftxui::screen ftxui::dom ftxui::component
        Threads::Threads)
endif()

#pragma once
#include <cstdint>

// Packed to ensure no compiler padding bytes are added.
// Guarantees consistent byte layout across compilers and platforms.
#pragma pack(push, 1)
struct PortData
{
  uint16_t port_number; // Target port (e.g., 3000)
  uint32_t process_id;  // PID holding the port (resolved via OS APIs)
  bool is_memory_leak;  // Flagged by Threat Analyzer
};
#pragma pack(pop)

// Watchdog IPC Port for Localhost Loopback
const uint16_t GHOSTPORT_IPC_PORT = 44444;

// Named pipe / Unix Domain Socket fallback name
const char *const GHOSTPORT_SOCKET_NAME =
#ifdef _WIN32
    "\\\\.\\pipe\\ghostport_ipc";
#else
    "/tmp/ghostport_ipc.sock";
#endif

#pragma once
#include <cstdint>

// We pack the struct to ensure no padding bytes are added by the compiler.
// This guarantees it is exactly 7 bytes on all systems.
#pragma pack(push, 1)
struct PortData
{
  uint16_t port_number; // The port (e.g., 3000)
  uint32_t process_id;  // The PID holding the port
  bool is_memory_leak;  // Telemetry flag
};
#pragma pack(pop)

// The name of our local named pipe / unix domain socket
const char *const GHOSTPORT_SOCKET_NAME =
#ifdef _WIN32
    "\\\\.\\pipe\\ghostport_ipc";
#else
    "/tmp/ghostport_ipc.sock";
#endif
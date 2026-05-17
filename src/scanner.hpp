#pragma once
#include "ipc_contract.hpp"
#include <asio.hpp>
#include <vector>
#include <iostream>

void run_canary_scanner()
{
  asio::io_context io_context;

  // Connect to the Watchdog's socket
#ifdef _WIN32
  asio::local::stream_protocol::endpoint ep(GHOSTPORT_SOCKET_NAME);
  asio::local::stream_protocol::socket socket(io_context);
#else
  asio::local::stream_protocol::endpoint ep(GHOSTPORT_SOCKET_NAME);
  asio::local::stream_protocol::socket socket(io_context);
#endif

  try
  {
    socket.connect(ep);

    // Scan common ports
    std::vector<uint16_t> target_ports = {3000, 4200, 5000, 8080, 5432, 3306};

    for (uint16_t port : target_ports)
    {
      asio::ip::tcp::socket test_socket(io_context);
      asio::error_code ec;
      test_socket.connect(asio::ip::tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), port), ec);

      if (!ec)
      {
        // Port is occupied! Pack the binary data.
        PortData data;
        data.port_number = port;
        data.process_id = 0; // We will grab this via OS APIs later
        data.is_memory_leak = false;

        // Blast the raw bytes over the socket (Zero-Copy!)
        asio::write(socket, asio::buffer(&data, sizeof(PortData)));
        test_socket.close();
      }
    }
  }
  catch (std::exception &e)
  {
    // If the socket fails, the Canary just dies quietly. No UI crash.
  }
}
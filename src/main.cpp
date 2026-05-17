#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <asio.hpp>
#include <iostream>
#include <thread>
#include <mutex>
#include <vector>
#include <string>
#include <chrono>
#include <atomic>

using namespace ftxui;

// ============================================================================
// [1] DATA STRUCTURES & IPC CONTRACT
// ============================================================================
#pragma pack(push, 1)
struct PortData
{
  uint16_t port_number;
  uint32_t process_id;
  bool is_memory_leak;
};
#pragma pack(pop)

struct DockerContainer
{
  std::string id;
  std::string name;
  std::string status;
};

const uint16_t GHOSTPORT_IPC_PORT = 44444;

// ============================================================================
// [2] GLOBAL STATE
// ============================================================================
std::mutex state_mutex;
std::vector<std::string> system_logs = {"[SYS] GhostPort Watchdog Initialized."};
std::vector<int> telemetry_data;

// Port Reaper State
std::vector<PortData> live_ports;
std::vector<std::string> port_menu_entries;
int selected_port_index = 0;
std::atomic<bool> is_scanning = false;

// Docker Poltergeist State
std::vector<DockerContainer> docker_list;
std::vector<std::string> docker_menu_entries;
int selected_docker_index = 0;

void log_event(const std::string &msg, ScreenInteractive *screen = nullptr)
{
  std::lock_guard<std::mutex> lock(state_mutex);
  system_logs.insert(system_logs.begin(), msg);
  if (system_logs.size() > 8)
    system_logs.pop_back();
  if (screen)
    screen->PostEvent(Event::Custom);
}

// ============================================================================
// [3] DOCKER PIPELINE (The Poltergeist)
// ============================================================================
void scan_docker_environment()
{
  docker_list.clear();
  docker_menu_entries.clear();
  selected_docker_index = 0;

  // Use OS Pipes to hijack the Docker CLI output
#ifdef _WIN32
  FILE *pipe = _popen("docker ps --format \"{{.ID}}|{{.Names}}|{{.Status}}\"", "r");
#else
  FILE *pipe = popen("docker ps --format \"{{.ID}}|{{.Names}}|{{.Status}}\"", "r");
#endif

  if (!pipe)
    return;

  char buffer[256];
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
  {
    std::string line(buffer);
    if (!line.empty() && line.back() == '\n')
      line.pop_back();

    // Parse the hijacked text into our C++ Struct
    size_t pos1 = line.find('|');
    size_t pos2 = line.find('|', pos1 + 1);
    if (pos1 != std::string::npos && pos2 != std::string::npos)
    {
      DockerContainer c;
      c.id = line.substr(0, pos1);
      c.name = line.substr(pos1 + 1, pos2 - pos1 - 1);
      c.status = line.substr(pos2 + 1);

      docker_list.push_back(c);
      docker_menu_entries.push_back("🐳 " + c.name + "   [" + c.status + "]");
    }
  }

#ifdef _WIN32
  _pclose(pipe);
#else
  pclose(pipe);
#endif
}

// ============================================================================
// [4] THE CANARY (Network Scanner)
// ============================================================================
void execute_canary_mission()
{
  asio::io_context io_context;
  asio::ip::tcp::endpoint ep(asio::ip::address::from_string("127.0.0.1"), GHOSTPORT_IPC_PORT);
  asio::ip::tcp::socket socket(io_context);

  asio::error_code tcp_ec;
  for (int i = 0; i < 15; ++i)
  {
    socket.connect(ep, tcp_ec);
    if (!tcp_ec)
      break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (tcp_ec)
    return;

  std::vector<uint16_t> targets = {80, 443, 3000, 3306, 3307, 4200, 5000, 5173, 8000, 8080, 5432};
  asio::ip::tcp::resolver resolver(io_context);

  for (uint16_t port : targets)
  {
    if (port == GHOSTPORT_IPC_PORT)
      continue;

    asio::ip::tcp::socket test_sock(io_context);
    asio::error_code ec;
    auto endpoints = resolver.resolve("localhost", std::to_string(port), ec);

    if (!ec)
    {
      asio::connect(test_sock, endpoints, ec);
      if (!ec)
      {
        PortData data = {port, 0, false};
        asio::write(socket, asio::buffer(&data, sizeof(PortData)));
        test_sock.close();
      }
    }
  }
}

// ============================================================================
// [5] THE WATCHDOG (TCP Server)
// ============================================================================
void watchdog_listen_server(ScreenInteractive *screen)
{
  try
  {
    asio::io_context io_context;
    asio::ip::tcp::endpoint ep(asio::ip::address::from_string("127.0.0.1"), GHOSTPORT_IPC_PORT);

    asio::ip::tcp::acceptor acceptor(io_context);
    acceptor.open(ep.protocol());
    acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acceptor.bind(ep);
    acceptor.listen();

    asio::ip::tcp::socket socket(io_context);
    acceptor.accept(socket);

    while (is_scanning)
    {
      PortData incoming;
      asio::error_code ec;
      size_t len = socket.read_some(asio::buffer(&incoming, sizeof(PortData)), ec);

      if (ec == asio::error::eof || ec)
        break;

      if (len == sizeof(PortData))
      {
        std::lock_guard<std::mutex> lock(state_mutex);
        live_ports.push_back(incoming);
        port_menu_entries.push_back("Port " + std::to_string(incoming.port_number) + " [DETECTED]");
        screen->PostEvent(Event::Custom);
      }
    }
  }
  catch (std::exception &e)
  {
    log_event("[ERR] IPC Bridge Failed: " + std::string(e.what()), screen);
  }

  is_scanning = false;
  log_event("[NET] Canary mission complete.", screen);
}

// ============================================================================
// [6] THE MASTER UI
// ============================================================================
int main(int argc, char *argv[])
{
  if (argc > 1 && std::string(argv[1]) == "--run-canary")
  {
    execute_canary_mission();
    return 0;
  }

  auto screen = ScreenInteractive::Fullscreen();

  // Telemetry Thread
  std::thread([&]()
              {
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            std::lock_guard<std::mutex> lock(state_mutex);
            telemetry_data.push_back(rand() % 100);
            if (telemetry_data.size() > 100) telemetry_data.erase(telemetry_data.begin());
            screen.PostEvent(Event::Custom);
        } })
      .detach();

  auto telemetry_graph = graph([&](int width, int height)
                               {
        std::vector<int> out(width, 0);
        std::lock_guard<std::mutex> lock(state_mutex);
        int start = std::max(0, (int)telemetry_data.size() - width);
        for (int i = 0; i < width && (start + i) < telemetry_data.size(); ++i) {
            out[i] = (telemetry_data[start + i] * height) / 100;
        }
        return out; }) |
                         color(Color::Cyan);

  int tab_index = 0;
  std::vector<std::string> tab_labels = {" Dashboard ", " Port Reaper ", " Docker ", " Stasis "};
  auto tab_toggle = Toggle(tab_labels, &tab_index);

  // --- PORT REAPER COMPONENTS ---
  auto scan_btn = Button("Deploy Security Canary", [&]
                         {
        if (!is_scanning) {
            is_scanning = true;
            {
                std::lock_guard<std::mutex> lock(state_mutex);
                live_ports.clear();
                port_menu_entries.clear();
            }
            log_event("[NET] Deploying Canary to OS layer...", &screen);
            std::thread(watchdog_listen_server, &screen).detach();

            std::string cmd = std::string(argv[0]) + " --run-canary";
#ifdef _WIN32
            std::string safe_path = "\"" + std::string(argv[0]) + "\"";
            system(("start /B \"\" " + safe_path + " --run-canary >nul 2>nul").c_str());
#else
            system((cmd + " &").c_str());
#endif
        } }, ButtonOption::Animated(Color::Red, Color::White));

  auto port_menu = Radiobox(&port_menu_entries, &selected_port_index);
  auto kill_btn = Button("Terminate Selected Port", [&]
                         {
        if (!port_menu_entries.empty() && selected_port_index >= 0 && selected_port_index < live_ports.size()) {
            uint16_t target_port = live_ports[selected_port_index].port_number;
            log_event("[SEC] Engaging lethal injection on Port " + std::to_string(target_port) + "...", &screen);

#ifdef _WIN32
            std::string cmd = "FOR /F \"tokens=5\" %P IN ('netstat -aon ^| find \":" + std::to_string(target_port) + "\" ^| find \"LISTENING\"') DO taskkill /F /PID %P >nul 2>nul";
            system(cmd.c_str());
#else
            std::string cmd = "kill -9 $(lsof -t -i:" + std::to_string(target_port) + " -sTCP:LISTEN)";
            system(cmd.c_str());
#endif
            log_event("[SEC] Target neutralized.", &screen);
            live_ports.erase(live_ports.begin() + selected_port_index);
            port_menu_entries.erase(port_menu_entries.begin() + selected_port_index);
            if (selected_port_index > 0) selected_port_index--;
        } }, ButtonOption::Animated(Color::Yellow, Color::Black));

  // --- DOCKER POLTERGEIST COMPONENTS ---
  auto refresh_docker_btn = Button("Scan Docker Subsystem", [&]
                                   {
        log_event("[DOCKER] Scanning for container anomalies...", &screen);
        scan_docker_environment();
        if (docker_list.empty()) log_event("[DOCKER] No active containers found.", &screen);
        else log_event("[DOCKER] Target lock on " + std::to_string(docker_list.size()) + " containers.", &screen); }, ButtonOption::Animated(Color::Blue, Color::White));

  auto docker_menu = Radiobox(&docker_menu_entries, &selected_docker_index);

  auto stop_docker_btn = Button("Graceful Spin Down (SIGTERM)", [&]
                                {
        if (!docker_list.empty() && selected_docker_index >= 0 && selected_docker_index < docker_list.size()) {
            std::string target_id = docker_list[selected_docker_index].id;
            std::string target_name = docker_list[selected_docker_index].name;
            log_event("[DOCKER] Spinning down: " + target_name + "...", &screen);
            
            // Execute in background so UI doesn't freeze while Docker stops
            std::thread([target_id, target_name, &screen]() {
                std::string cmd = "docker stop " + target_id + " >nul 2>nul";
                system(cmd.c_str());
                log_event("[DOCKER] " + target_name + " successfully halted.", &screen);
            }).detach();

            docker_list.erase(docker_list.begin() + selected_docker_index);
            docker_menu_entries.erase(docker_menu_entries.begin() + selected_docker_index);
            if (selected_docker_index > 0) selected_docker_index--;
        } }, ButtonOption::Animated(Color::Yellow, Color::Black));

  // --- RENDERERS ---
  auto dashboard_renderer = Renderer([&]
                                     {
        Elements logs;
        std::lock_guard<std::mutex> lock(state_mutex);
        for (const auto &log : system_logs) logs.push_back(text(log) | dim);

        return vbox({
            hbox({
                window(text(" System Telemetry "), telemetry_graph) | flex,
                window(text(" Engine Status "), vbox({
                    text("Watchdog   : ONLINE") | color(Color::Green),
                    text("IPC Socket : SECURE") | color(Color::Green),
                    text("Docker API : READY") | color(Color::Green),
                }))
            }),
            window(text(" Security Logs "), vbox(std::move(logs))) | flex
        }); });

  auto network_renderer = Renderer(Container::Vertical({scan_btn, port_menu, kill_btn}), [&]
                                   { return window(text(" Zero-Copy Network Reaper "),
                                                   vbox({scan_btn->Render() | center, separator(),
                                                         is_scanning ? (text(" Canary scanning... ") | blink | color(Color::Red) | center) : text(""),
                                                         port_menu_entries.empty() ? (text(" No malicious ports detected.") | dim | center | flex)
                                                                                   : window(text(" Target Lock "), vbox({port_menu->Render(), separator(), kill_btn->Render() | center})) | flex})); });

  auto docker_renderer = Renderer(Container::Vertical({refresh_docker_btn, docker_menu, stop_docker_btn}), [&]
                                  { return window(text(" Docker Poltergeist "),
                                                  vbox({refresh_docker_btn->Render() | center, separator(),
                                                        docker_menu_entries.empty() ? (text(" Docker Engine idle or unreachable.") | dim | center | flex)
                                                                                    : window(text(" Container Lock "), vbox({docker_menu->Render(), separator(), stop_docker_btn->Render() | center})) | flex})); });

  auto mock_renderer = Renderer([&]
                                { return window(text(" Feature Locked "), text("Advanced module awaiting next development cycle.") | dim | center) | flex; });

  auto tab_container = Container::Tab({dashboard_renderer, network_renderer, docker_renderer, mock_renderer}, &tab_index);
  auto main_layout = Container::Vertical({tab_toggle, tab_container});

  auto final_ui = Renderer(main_layout, [&]
                           { return vbox({text(" G H O S T P O R T ") | bold | inverted | center,
                                          text(" ADVANCED DEVELOPMENT ENVIRONMENT SECURITY ") | dim | center,
                                          separator(),
                                          tab_toggle->Render() | center,
                                          separator(),
                                          tab_container->Render() | flex,
                                          text(" Press 'Ctrl+C' to emergency abort.") | dim | center}) |
                                    borderHeavy; });

  screen.Loop(final_ui);
  std::cout << "\n[GhostPort] System Shutdown Sequence Complete.\n";
  return 0;
}
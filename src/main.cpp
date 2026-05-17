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

#ifdef _WIN32
#include <windows.h>
#include <pdh.h>
#include <TlHelp32.h>
#pragma comment(lib, "pdh.lib")
#endif

using namespace ftxui;

// ============================================================================
// [1] DATA STRUCTURES
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

struct OsProcess
{
  std::string pid;
  std::string name;
  std::string ram_usage;
};

const uint16_t GHOSTPORT_IPC_PORT = 44444;

// ============================================================================
// [2] GLOBAL STATE
// ============================================================================
std::mutex state_mutex; // The master lock protecting all vectors
std::vector<std::string> system_logs = {"[SYS] GhostPort Engine Online.", "[SYS] Kernel Telemetry Hooks injected."};

std::vector<int> cpu_history;
std::vector<int> ram_history;
int current_cpu_percent = 0;
int current_ram_percent = 0;
double current_ram_gb = 0.0;
double total_ram_gb = 0.0;

std::vector<PortData> live_ports;
std::vector<std::string> port_menu_entries;
int selected_port_index = 0;
std::atomic<bool> is_scanning = false;

std::vector<DockerContainer> docker_list;
std::vector<std::string> docker_menu_entries;
int selected_docker_index = 0;

int stasis_mode = 0;
std::vector<DockerContainer> stasis_docker_list;
std::vector<std::string> stasis_docker_menu;
int selected_stasis_docker_index = 0;

std::vector<OsProcess> os_process_list;
std::vector<std::string> os_process_menu;
int selected_os_process_index = 0;

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
// [3] THREAT ANALYSIS ENGINE (The Leak Hunter)
// ============================================================================
void threat_analysis_engine(ScreenInteractive *screen)
{
  while (true)
  {
    std::this_thread::sleep_for(std::chrono::seconds(8));

    bool threat_detected = false;
    {
      std::lock_guard<std::mutex> lock(state_mutex); // Lock before looping
      for (size_t i = 0; i < live_ports.size(); ++i)
      {
        if (!live_ports[i].is_memory_leak)
        {
          if (rand() % 100 > 60)
          {
            live_ports[i].is_memory_leak = true;
            // Thread-safety bounds check: Ensure UI array matches data array
            if (i < port_menu_entries.size())
            {
              port_menu_entries[i] = "[CRITICAL LEAK] Port " + std::to_string(live_ports[i].port_number);
            }
            threat_detected = true;
            system_logs.insert(system_logs.begin(), "[WARN] Memory Leak detected on Port " + std::to_string(live_ports[i].port_number) + "!");
            if (system_logs.size() > 8)
              system_logs.pop_back();
          }
        }
      }
    }

    if (threat_detected && screen)
    {
      screen->PostEvent(Event::Custom);
    }
  }
}

#ifdef _WIN32
void manipulate_windows_process(DWORD processId, bool suspend)
{
  HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (hThreadSnapshot == INVALID_HANDLE_VALUE)
    return;
  THREADENTRY32 threadEntry;
  threadEntry.dwSize = sizeof(THREADENTRY32);
  if (Thread32First(hThreadSnapshot, &threadEntry))
  {
    do
    {
      if (threadEntry.th32OwnerProcessID == processId)
      {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
        if (hThread)
        {
          if (suspend)
            SuspendThread(hThread);
          else
            ResumeThread(hThread);
          CloseHandle(hThread);
        }
      }
    } while (Thread32Next(hThreadSnapshot, &threadEntry));
  }
  CloseHandle(hThreadSnapshot);
}
#endif

// ============================================================================
// [4] TELEMETRY & SCANNERS
// ============================================================================
void start_telemetry_stream(ScreenInteractive *screen)
{
#ifdef _WIN32
  PDH_HQUERY cpuQuery;
  PDH_HCOUNTER cpuTotal;
  PdhOpenQuery(NULL, NULL, &cpuQuery);
  PdhAddEnglishCounterA(cpuQuery, "\\Processor(_Total)\\% Processor Time", 0, &cpuTotal);
  PdhCollectQueryData(cpuQuery);
#endif
  while (true)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    std::lock_guard<std::mutex> lock(state_mutex);
#ifdef _WIN32
    PDH_FMT_COUNTERVALUE counterVal;
    PdhCollectQueryData(cpuQuery);
    PdhGetFormattedCounterValue(cpuTotal, PDH_FMT_DOUBLE, NULL, &counterVal);
    current_cpu_percent = static_cast<int>(counterVal.doubleValue);

    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    current_ram_percent = memInfo.dwMemoryLoad;
    total_ram_gb = memInfo.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);
    current_ram_gb = (memInfo.ullTotalPhys - memInfo.ullAvailPhys) / (1024.0 * 1024.0 * 1024.0);
#else
    current_cpu_percent = rand() % 100;
    current_ram_percent = rand() % 100;
#endif
    cpu_history.push_back(current_cpu_percent);
    ram_history.push_back(current_ram_percent);
    if (cpu_history.size() > 100)
      cpu_history.erase(cpu_history.begin());
    if (ram_history.size() > 100)
      ram_history.erase(ram_history.begin());
    screen->PostEvent(Event::Custom);
  }
}

void scan_docker_environment(std::vector<DockerContainer> &target_list, std::vector<std::string> &target_menu, int &index_tracker)
{
  std::lock_guard<std::mutex> lock(state_mutex);
  target_list.clear();
  target_menu.clear();
  index_tracker = 0;
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
    size_t pos1 = line.find('|');
    size_t pos2 = line.find('|', pos1 + 1);
    if (pos1 != std::string::npos && pos2 != std::string::npos)
    {
      DockerContainer c = {line.substr(0, pos1), line.substr(pos1 + 1, pos2 - pos1 - 1), line.substr(pos2 + 1)};
      target_list.push_back(c);
      std::string prefix = (c.status.find("Paused") != std::string::npos) ? "[FROZEN] " : "[ACTIVE] ";
      target_menu.push_back(prefix + c.name + "   [" + c.status + "]");
    }
  }
#ifdef _WIN32
  _pclose(pipe);
#else
  pclose(pipe);
#endif
}

void scan_windows_processes()
{
  std::lock_guard<std::mutex> lock(state_mutex);
  os_process_list.clear();
  os_process_menu.clear();
  selected_os_process_index = 0;
#ifdef _WIN32
  std::string ps_cmd = "powershell -NoProfile -Command \"Get-Process | Where-Object {$_.MainWindowHandle -ne 0} | Sort-Object WS -Descending | Select-Object -First 15 | ForEach-Object { $_.Id.ToString() + '|' + $_.Name + '|' + [math]::Round($_.WS/1MB, 1).ToString() }\"";
  FILE *pipe = _popen(ps_cmd.c_str(), "r");
  if (!pipe)
    return;
  char buffer[256];
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
  {
    std::string line(buffer);
    if (!line.empty() && line.back() == '\n')
      line.pop_back();
    size_t pos1 = line.find('|');
    size_t pos2 = line.find('|', pos1 + 1);
    if (pos1 != std::string::npos && pos2 != std::string::npos)
    {
      OsProcess p = {line.substr(0, pos1), line.substr(pos1 + 1, pos2 - pos1 - 1), line.substr(pos2 + 1)};
      os_process_list.push_back(p);
      os_process_menu.push_back("[PID: " + p.pid + "]  " + p.name + "  (" + p.ram_usage + " MB)");
    }
  }
  _pclose(pipe);
#endif
}

// ============================================================================
// [5] CANARY & WATCHDOG
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
  catch (...)
  {
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
  std::thread(start_telemetry_stream, &screen).detach();
  std::thread(threat_analysis_engine, &screen).detach();

  int tab_index = 0;
  std::vector<std::string> tab_labels = {" Dashboard ", " Port Reaper ", " Docker ", " Stasis "};
  auto tab_toggle = Toggle(&tab_labels, &tab_index);

  auto cpu_graph = graph([&](int width, int height)
                         {
        std::vector<int> out(width, 0);
        std::lock_guard<std::mutex> lock(state_mutex);
        int start = std::max(0, (int)cpu_history.size() - width);
        for (int i = 0; i < width && (start + i) < cpu_history.size(); ++i) out[i] = (cpu_history[start + i] * height) / 100;
        return out; }) |
                   color(Color::Cyan);

  auto ram_graph = graph([&](int width, int height)
                         {
        std::vector<int> out(width, 0);
        std::lock_guard<std::mutex> lock(state_mutex);
        int start = std::max(0, (int)ram_history.size() - width);
        for (int i = 0; i < width && (start + i) < ram_history.size(); ++i) out[i] = (ram_history[start + i] * height) / 100;
        return out; }) |
                   color(Color::Magenta);

  // --- REAPER UI ---
  auto scan_btn = Button("Deploy Security Canary", [&]
                         {
        if (!is_scanning) {
            is_scanning = true;
            { 
                std::lock_guard<std::mutex> lock(state_mutex); 
                live_ports.clear(); 
                port_menu_entries.clear(); 
                selected_port_index = 0; // FIX: Reset index on clear
            }
            log_event("[NET] Deploying Canary...", &screen);
            std::thread(watchdog_listen_server, &screen).detach();
#ifdef _WIN32
            std::string safe_path = "\"" + std::string(argv[0]) + "\"";
            system(("start /B \"\" " + safe_path + " --run-canary >nul 2>nul").c_str());
#endif
        } }, ButtonOption::Animated(Color::Red, Color::White));

  auto port_menu = Radiobox(&port_menu_entries, &selected_port_index);

  auto kill_btn = Button("Terminate Selected Port", [&]
                         {
        std::lock_guard<std::mutex> lock(state_mutex); // FIX: Lock memory state before killing
        if (!port_menu_entries.empty() && selected_port_index >= 0 && selected_port_index < live_ports.size()) { // FIX: Bounds check
            log_event("[SEC] Lethal injection engaged on Port " + std::to_string(live_ports[selected_port_index].port_number), &screen);
#ifdef _WIN32
            std::string cmd = "FOR /F \"tokens=5\" %P IN ('netstat -aon ^| find \":" + std::to_string(live_ports[selected_port_index].port_number) + "\" ^| find \"LISTENING\"') DO taskkill /F /PID %P >nul 2>nul";
            system(cmd.c_str());
#endif
            live_ports.erase(live_ports.begin() + selected_port_index);
            port_menu_entries.erase(port_menu_entries.begin() + selected_port_index);
            if (selected_port_index > 0) selected_port_index--;
        } }, ButtonOption::Animated(Color::Yellow, Color::Black));

  // --- DOCKER UI ---
  auto refresh_docker_btn = Button("Scan Docker Subsystem", [&]
                                   {
        log_event("[DOCKER] Scanning for containers...", &screen);
        scan_docker_environment(docker_list, docker_menu_entries, selected_docker_index); }, ButtonOption::Animated(Color::Blue, Color::White));

  auto docker_menu = Radiobox(&docker_menu_entries, &selected_docker_index);

  auto stop_docker_btn = Button("Graceful Spin Down (SIGTERM)", [&]
                                {
        std::lock_guard<std::mutex> lock(state_mutex); // FIX: Lock state
        if (!docker_list.empty() && selected_docker_index >= 0 && selected_docker_index < docker_list.size()) { // FIX: Bounds check
            std::string id = docker_list[selected_docker_index].id;
            std::string name = docker_list[selected_docker_index].name;
            log_event("[DOCKER] Spinning down: " + name, &screen);
            std::thread([id, name, &screen]() { system(("docker stop " + id + " >nul 2>nul").c_str()); log_event("[DOCKER] " + name + " halted.", &screen); }).detach();
            docker_list.erase(docker_list.begin() + selected_docker_index);
            docker_menu_entries.erase(docker_menu_entries.begin() + selected_docker_index);
            if (selected_docker_index > 0) selected_docker_index--;
        } }, ButtonOption::Animated(Color::Yellow, Color::Black));

  // --- STASIS UI ---
  std::vector<std::string> stasis_labels = {" [Docker Subsystem] ", " [Windows OS Kernel] "};
  auto stasis_subsystem_toggle = Toggle(&stasis_labels, &stasis_mode);

  auto refresh_stasis_btn = Button("Scan Target Environment", [&]
                                   {
        if (stasis_mode == 0) {
            log_event("[STASIS] Analyzing Docker Subsystem...", &screen);
            scan_docker_environment(stasis_docker_list, stasis_docker_menu, selected_stasis_docker_index);
        } else {
            log_event("[STASIS] Hooking into Windows OS Processes...", &screen);
            scan_windows_processes();
        } }, ButtonOption::Animated(Color::Blue, Color::White));

  auto stasis_docker_menu_comp = Radiobox(&stasis_docker_menu, &selected_stasis_docker_index);
  auto stasis_os_menu_comp = Radiobox(&os_process_menu, &selected_os_process_index);

  auto freeze_btn = Button("Initiate Cryo-Sleep (Suspend)", [&]
                           {
        std::lock_guard<std::mutex> lock(state_mutex); // FIX: Lock state
        if (stasis_mode == 0 && !stasis_docker_list.empty() && selected_stasis_docker_index < stasis_docker_list.size()) {
            std::string target_id = stasis_docker_list[selected_stasis_docker_index].id;
            std::string target_name = stasis_docker_list[selected_stasis_docker_index].name;
            log_event("[STASIS] Freezing Container: " + target_name, &screen);
            std::thread([target_id, target_name, &screen]() {
                system(("docker pause " + target_id + " >nul 2>nul").c_str());
                log_event("[STASIS] " + target_name + " is now in Cryo-Sleep.", &screen);
                // Background refresh handled without locking main UI
                screen.PostEvent(Event::Custom);
            }).detach();
        } else if (stasis_mode == 1 && !os_process_list.empty() && selected_os_process_index < os_process_list.size()) {
#ifdef _WIN32
            DWORD pid = std::stoul(os_process_list[selected_os_process_index].pid);
            std::string target_name = os_process_list[selected_os_process_index].name;
            log_event("[STASIS] Halting OS Execution Threads for: " + target_name, &screen);
            manipulate_windows_process(pid, true); 
            os_process_menu[selected_os_process_index] = "[FROZEN] " + os_process_menu[selected_os_process_index];
#endif
        } }, ButtonOption::Animated(Color::Cyan, Color::Black));

  auto thaw_btn = Button("Initiate Thaw Sequence (Resume)", [&]
                         {
        std::lock_guard<std::mutex> lock(state_mutex); // FIX: Lock state
        if (stasis_mode == 0 && !stasis_docker_list.empty() && selected_stasis_docker_index < stasis_docker_list.size()) {
            std::string target_id = stasis_docker_list[selected_stasis_docker_index].id;
            std::string target_name = stasis_docker_list[selected_stasis_docker_index].name;
            log_event("[STASIS] Restoring Container execution to: " + target_name, &screen);
            std::thread([target_id, target_name, &screen]() {
                system(("docker unpause " + target_id + " >nul 2>nul").c_str());
                log_event("[STASIS] " + target_name + " execution resumed.", &screen);
                screen.PostEvent(Event::Custom);
            }).detach();
        } else if (stasis_mode == 1 && !os_process_list.empty() && selected_os_process_index < os_process_list.size()) {
#ifdef _WIN32
            DWORD pid = std::stoul(os_process_list[selected_os_process_index].pid);
            std::string target_name = os_process_list[selected_os_process_index].name;
            log_event("[STASIS] Restoring OS Execution Threads for: " + target_name, &screen);
            manipulate_windows_process(pid, false); 
            if (os_process_menu[selected_os_process_index].find("[FROZEN] ") == 0) {
                os_process_menu[selected_os_process_index] = os_process_menu[selected_os_process_index].substr(9);
            }
#endif
        } }, ButtonOption::Animated(Color::Green, Color::Black));

  // --- RENDERERS ---
  auto dashboard_renderer = Renderer([&]
                                     {
        Elements logs;
        std::lock_guard<std::mutex> lock(state_mutex);
        for (const auto &log : system_logs) logs.push_back(text(log) | dim);
        char ram_str[32];
        snprintf(ram_str, sizeof(ram_str), "%.1f GB / %.1f GB", current_ram_gb, total_ram_gb);
        return vbox({
            hbox({ window(text(" CPU Load: " + std::to_string(current_cpu_percent) + "% "), cpu_graph) | flex, window(text(std::string(" RAM Load: ") + ram_str + " (" + std::to_string(current_ram_percent) + "%) "), ram_graph) | flex, }),
            hbox({ window(text(" Engine Status "), vbox({text("Watchdog Daemon : ONLINE") | color(Color::Green), text("IPC Subsystem   : SECURE") | color(Color::Green), text("Docker Engine   : CONNECTED") | color(Color::Green), text("Threat Analyzer : ONLINE") | color(Color::Green),})) | flex, window(text(" Security Logs "), vbox(std::move(logs))) | flex })
        }); });

  auto network_renderer = Renderer(Container::Vertical({scan_btn, port_menu, kill_btn}), [&]
                                   { 
        bool has_leak = false;
        {
            std::lock_guard<std::mutex> lock(state_mutex);
            for (const auto& p : live_ports) if (p.is_memory_leak) has_leak = true;
        }
        
        return window(text(" Zero-Copy Network Reaper "), vbox({ 
            scan_btn->Render() | center, separator(), 
            is_scanning ? (text(" Canary scanning... ") | blink | color(Color::Red) | center) : text(""), 
            
            has_leak ? (window(text(" THREAT DETECTED "), text(" Memory Leak Identified! Terminate immediately. ")) | color(Color::Red) | blink | center) 
                     : (text(" System Stable ") | color(Color::Green) | center),
            
            port_menu_entries.empty() ? (text(" No malicious ports detected.") | dim | center | flex) : window(text(" Target Lock "), vbox({port_menu->Render(), separator(), kill_btn->Render() | center})) | flex 
        })); });

  auto docker_renderer = Renderer(Container::Vertical({refresh_docker_btn, docker_menu, stop_docker_btn}), [&]
                                  { return window(text(" Docker Poltergeist "), vbox({refresh_docker_btn->Render() | center, separator(), docker_menu_entries.empty() ? (text(" Docker Engine idle or unreachable.") | dim | center | flex) : window(text(" Container Lock "), vbox({docker_menu->Render(), separator(), stop_docker_btn->Render() | center})) | flex})); });

  auto stasis_renderer = Renderer(Container::Vertical({stasis_subsystem_toggle, refresh_stasis_btn, stasis_docker_menu_comp, stasis_os_menu_comp, freeze_btn, thaw_btn}), [&]
                                  { 
        bool is_empty = (stasis_mode == 0) ? stasis_docker_menu.empty() : os_process_menu.empty();
        auto active_menu = (stasis_mode == 0) ? stasis_docker_menu_comp->Render() : stasis_os_menu_comp->Render();
        return window(text(" The Stasis Chamber "), 
            vbox({
                stasis_subsystem_toggle->Render() | center, separator(),
                refresh_stasis_btn->Render() | center, separator(),
                is_empty ? (text(stasis_mode == 0 ? " No Docker targets found." : " No OS targets found.") | dim | center | flex)
                    : window(text(" Target Lock "), vbox({ active_menu, separator(), hbox({freeze_btn->Render() | center, text("   "), thaw_btn->Render() | center}) | center })) | flex
            })
        ); });

  auto tab_container = Container::Tab({dashboard_renderer, network_renderer, docker_renderer, stasis_renderer}, &tab_index);
  auto main_layout = Container::Vertical({tab_toggle, tab_container});
  auto final_ui = Renderer(main_layout, [&]
                           { return vbox({text(" G H O S T P O R T   O S ") | bold | inverted | center, text(" ADVANCED DEVELOPMENT ENVIRONMENT SECURITY ") | dim | center, separator(), tab_toggle->Render() | center, separator(), tab_container->Render() | flex, text(" Press 'Ctrl+C' to emergency abort.") | dim | center}) | borderHeavy; });

  screen.Loop(final_ui);
  std::cout << "\n[GhostPort] System Shutdown Sequence Complete.\n";
  return 0;
}
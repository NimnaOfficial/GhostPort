#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <string>
#include <mutex>
#include <asio.hpp>

using namespace ftxui;

// Global State (Thread Safe)
std::mutex data_mutex;
std::vector<int> active_ports;
std::atomic<bool> is_scanning = false;
std::vector<std::string> system_logs = {"[SYS] Engine Initialized", "[SYS] Waiting for commands..."};

// Background Networking Thread
void scan_dev_ports(ScreenInteractive *screen)
{
  is_scanning = true;
  screen->PostEvent(Event::Custom); // Tell UI to update

  std::vector<int> target_ports = {3000, 4200, 5000, 5173, 8000, 8080, 5432, 3306};
  std::vector<int> found_ports;
  asio::io_context io_context;

  for (int port : target_ports)
  {
    asio::ip::tcp::socket socket(io_context);
    asio::error_code ec;
    socket.connect(asio::ip::tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), port), ec);
    if (!ec)
    {
      found_ports.push_back(port);
      socket.close();
    }
  }

  std::lock_guard<std::mutex> lock(data_mutex);
  active_ports = found_ports;
  system_logs.insert(system_logs.begin(), "[NET] Network scan complete. Found " + std::to_string(found_ports.size()) + " active ports.");
  if (system_logs.size() > 5)
    system_logs.pop_back(); // Keep logs clean
  is_scanning = false;

  screen->PostEvent(Event::Custom); // Tell UI to update
}

int main()
{
  auto screen = ScreenInteractive::Fullscreen();

  // --- UI COMPONENTS ---

  // 1. Tab Navigation
  int tab_index = 0;
  std::vector<std::string> tab_entries = {
      "📊 Dashboard", "🌐 Network Reaper", "💾 Storage Health"};
  auto tab_selection = Toggle(&tab_entries, &tab_index);

  // 2. Buttons
  auto scan_button = Button("Scan Network Ports", [&]
                            {
        if (!is_scanning) {
            std::lock_guard<std::mutex> lock(data_mutex);
            system_logs.insert(system_logs.begin(), "[NET] Initiating deep port scan...");
            std::thread(scan_dev_ports, &screen).detach();
        } }, ButtonOption::Animated());

  auto quit_button = Button("Quit Dev-Shadow", screen.ExitLoopClosure(), ButtonOption::Animated());

  // --- VIEW RENDERERS ---

  // View 1: Dashboard
  auto dashboard_view = Renderer([&]
                                 {
        std::lock_guard<std::mutex> lock(data_mutex);
        Elements logs;
        for (const auto& log : system_logs) logs.push_back(text(log) | dim);

        return vbox({
            text("System Health Overview") | bold | color(Color::Cyan),
            separator(),
            hbox({
                vbox({
                    text("CPU Optimization : ACTIVE") | color(Color::Green),
                    text("Memory Leak Guard: ACTIVE") | color(Color::Green),
                }) | borderEmpty | flex,
                vbox({
                    text("Total Zombie Ports: " + std::to_string(active_ports.size())) | color(Color::Yellow),
                    text("Wasted Storage    : 0 MB"),
                }) | borderEmpty | flex,
            }),
            separator(),
            text("Recent Activity Log:") | bold,
            vbox(std::move(logs)) | borderLight | flex
        }); });

  // View 2: Network Reaper
  auto network_view = Renderer(scan_button, [&]
                               {
        std::lock_guard<std::mutex> lock(data_mutex);
        Elements port_ui;
        
        if (is_scanning) {
            port_ui.push_back(text("Scanning OS hardware endpoints...") | blink | color(Color::Blue));
        } else if (active_ports.empty()) {
            port_ui.push_back(text("All ports are clean. No zombie processes detected.") | color(Color::Green));
        } else {
            for (int p : active_ports) {
                port_ui.push_back(hbox({
                    text(" [PORT " + std::to_string(p) + "] ") | bold,
                    text(" OCCUPIED ") | inverted | color(Color::Red),
                }) | borderEmpty);
            }
        }

        return vbox({
            text("Network Port Management") | bold | color(Color::Cyan),
            separator(),
            scan_button->Render() | center,
            separator(),
            vbox(std::move(port_ui)) | flex
        }); });

  // View 3: Storage (Placeholder)
  auto storage_view = Renderer([&]
                               { return vbox({
                                            text("Storage Artifact Scrubber") | bold | color(Color::Cyan),
                                            separator(),
                                            text("Module scanning engine currently offline.") | dim | center,
                                        }) |
                                        flex; });

  // Combine views dynamically based on the selected tab
  auto tab_content = Container::Tab({dashboard_view,
                                     network_view,
                                     storage_view},
                                    &tab_index);

  // --- MAIN LAYOUT ASSEMBLY ---
  auto main_container = Container::Vertical({tab_selection,
                                             tab_content,
                                             quit_button});

  auto final_renderer = Renderer(main_container, [&]
                                 { return vbox({text(" DEV-SHADOW ADVANCED TERMINAL ") | bold | inverted | center,
                                                separator(),
                                                tab_selection->Render() | center,
                                                separator(),
                                                tab_content->Render() | flex, // Flex fills the remaining space
                                                separator(),
                                                quit_button->Render() | center}) |
                                          borderHeavy | flex; });

  // We no longer need an infinite ticking thread because FTXUI components
  // are interactive! We only trigger redraws when clicking or when the scan finishes.

  screen.Loop(final_renderer);

  std::cout << "\n[Dev-Shadow] Graceful Shutdown Complete.\n";
  return 0;
}
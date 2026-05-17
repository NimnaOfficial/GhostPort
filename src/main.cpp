#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>
#include <iostream>

int main()
{
  using namespace ftxui;

  // Build the visual layout using a DOM-like structure
  auto dashboard = vbox({text(" [ DEV-SHADOW ] ") | bold | inverted | center,
                         separator(),
                         text(" System Core     : ONLINE") | color(Color::Green),
                         text(" Port Monitor    : STANDBY") | color(Color::Yellow),
                         text(" Secret Sentinel : STANDBY") | color(Color::Yellow),
                         separator(),
                         text(" Awaiting initialization...") | dim}) |
                   border | center;

  // Create a screen block and render the dashboard to it
  auto screen = Screen::Create(Dimension::Full(), Dimension::Fit(dashboard));
  Render(screen, dashboard);

  // Print it to your terminal!
  screen.Print();
  std::cout << "\n";

  return 0;
}
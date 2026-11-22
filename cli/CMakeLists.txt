aui_executable(netanal_cli WIN32_SUBSYSTEM_CONSOLE)
aui_link(netanal_cli PRIVATE aui::core)
target_link_libraries(netanal_cli PRIVATE netanal_core)

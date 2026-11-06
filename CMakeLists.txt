cmake_minimum_required(VERSION 3.20)
project(ManualReload CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(manual_reload_core STATIC src/patch.cpp)
target_compile_definitions(manual_reload_core PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)

# UE4SS loads Mods/<Mod>/dlls/main.dll.
add_library(ManualReload SHARED src/mod.cpp)
target_link_libraries(ManualReload PRIVATE manual_reload_core)
set_target_properties(ManualReload PROPERTIES OUTPUT_NAME main)

add_executable(ManualReloadScan src/scan.cpp)
target_link_libraries(ManualReloadScan PRIVATE manual_reload_core)

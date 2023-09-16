cmake_minimum_required(VERSION 3.25)
project(JimSniffer)
include(FindPCAP.cmake)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(CMAKE_PREFIX_PATH "/usr/lib/qt5/bin/qmake")

find_package(Qt5 COMPONENTS
        Core
        Gui
        Widgets
        REQUIRED)

add_executable(JimSniffer main.cpp sniffer.cpp sniffer.h)
target_link_libraries(JimSniffer
        Qt5::Core
        Qt5::Gui
        Qt5::Widgets
        ${PCAP_LIBRARY}
        )


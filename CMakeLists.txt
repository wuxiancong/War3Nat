cmake_minimum_required(VERSION 3.16)
project(War3Nat VERSION 1.0.0 LANGUAGES CXX)
if(WIN32)
    if(EXISTS "D:/Qt/Tools/Ninja/ninja.exe")
        set(CMAKE_MAKE_PROGRAM "D:/Qt/Tools/Ninja/ninja.exe" CACHE FILEPATH "Program used to build from makefiles" FORCE)
    endif()
endif()

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 编译器选项
if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wall -Wextra -O2)
elseif(MSVC)
    set(CMAKE_GENERATOR_PLATFORM Win32)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
    add_compile_options("/utf-8" "/MP")
    add_link_options("/NODEFAULTLIB:LIBCMT")
    add_link_options("/NODEFAULTLIB:LIBCMTD")
endif()

# 包含当前目录
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# 设置自动 MOC
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# 查找 Qt5
find_package(Qt5 REQUIRED COMPONENTS Core Network)

# 头文件
set(HEADERS
    include/logger.h
    include/war3nat.h
)

# 源文件
set(SOURCES
    src/main.cpp
    src/logger.cpp
    src/war3nat.cpp
)

# set(CMAKE_EXE_LINKER_FLAGS "-static -static-libgcc -static-libstdc++")

# 创建可执行文件
add_executable(War3Nat ${SOURCES} ${HEADERS})

# 链接 Qt 库和网络库
target_link_libraries(War3Nat  Qt5::Core Qt5::Network)

# 在 Windows 上链接 ws2_32 库
if(WIN32)
    target_link_libraries(War3Nat  ws2_32)
endif()

# 设置包含目录
target_include_directories(War3Nat  PRIVATE include)

# 安装目标
install(TARGETS War3Nat  DESTINATION bin)

# 安装配置文件
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/config/war3nat.ini")
    install(FILES config/war3nat.ini DESTINATION /etc/war3nat)
endif()

# 安装 systemd 服务文件
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/config/war3nat.service")
    install(FILES config/war3nat.service DESTINATION /etc/systemd/system)
endif()

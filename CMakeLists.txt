# CMake version 
cmake_minimum_required (VERSION 3.5)

#project name
PROJECT(kiwichatd)

#head file path
INCLUDE_DIRECTORIES(src/studease.cn)
INCLUDE_DIRECTORIES(src/studease.cn/core)
INCLUDE_DIRECTORIES(src/studease.cn/event)
INCLUDE_DIRECTORIES(src/studease.cn/utils)
INCLUDE_DIRECTORIES(src/studease.cn/http)
INCLUDE_DIRECTORIES(src/studease.cn/websocket)
INCLUDE_DIRECTORIES(src/kiwichatd.com)
INCLUDE_DIRECTORIES(src/kiwichatd.com/core)

#add sub directory
ADD_SUBDIRECTORY(src/studease.cn)
ADD_SUBDIRECTORY(src/kiwichatd.com)

#source directory
AUX_SOURCE_DIRECTORY(src DIR_SRC)

#add executable file
ADD_EXECUTABLE(kiwichatd ${DIR_SRC})

#add link library
TARGET_LINK_LIBRARIES(kiwichatd kcd)
TARGET_LINK_LIBRARIES(kiwichatd websocket)
TARGET_LINK_LIBRARIES(kiwichatd http)
TARGET_LINK_LIBRARIES(kiwichatd utils)
TARGET_LINK_LIBRARIES(kiwichatd event)
TARGET_LINK_LIBRARIES(kiwichatd core)

TARGET_LINK_LIBRARIES(kiwichatd pthread)
TARGET_LINK_LIBRARIES(kiwichatd m)
TARGET_LINK_LIBRARIES(kiwichatd crypto)
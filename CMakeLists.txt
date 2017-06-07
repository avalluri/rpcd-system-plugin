cmake_minimum_required(VERSION 2.6)

PROJECT(system-plugin C)

ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations -Iinclude)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

ADD_LIBRARY(system-plugin MODULE sysinfo.c)
TARGET_LINK_LIBRARIES(system-plugin ubox ubus)
SET_TARGET_PROPERTIES(system-plugin PROPERTIES OUTPUT_NAME system PREFIX "")

INSTALL(TARGETS system-plugin LIBRARY DESTINATION lib/rpcd)

cmake_minimum_required(VERSION 3.26)
project(DieselDebug CXX)

set(CMAKE_CXX_STANDARD 20)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(WIN64 TRUE)
else()
  set(WIN64 FALSE)
endif()

add_subdirectory("Dependencies/minhook")

set(REQUIRED_LIBS minhook)
set(INCLUDE_DIRS
  Dependencies/minhook/include
)

if(WIN64)
  message("Compiling for 64bit Diesel, binaries will only work with RAID: World War II")

  add_library(DieselDebug_RAIDWW2 SHARED
    ./src/raidww2.cpp
  )

  target_link_libraries(DieselDebug_RAIDWW2 ${REQUIRED_LIBS})

  target_include_directories(DieselDebug_RAIDWW2 PUBLIC
    ${INCLUDE_DIRS}
  )
else()
  message("Compiling for 32bit Diesel, binaries will only work with PAYDAY: The Heist")

  add_library(DieselDebug_PDTH SHARED
    ./src/pdth.cpp
  )

  target_link_libraries(DieselDebug_PDTH ${REQUIRED_LIBS})


  target_include_directories(DieselDebug_PDTH PUBLIC
    ${INCLUDE_DIRS}
  )

  add_library(DieselDebug_PD2 SHARED
    ./src/pd2.cpp
  )

  target_link_libraries(DieselDebug_PD2 ${REQUIRED_LIBS})


  target_include_directories(DieselDebug_PD2 PUBLIC
    ${INCLUDE_DIRS}
  )

endif()

add_library(VERSION SHARED
  proxy/main.cpp
  proxy/version.def
)
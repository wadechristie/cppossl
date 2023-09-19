cmake_minimum_required(VERSION 3.18)

if(NOT TARGET lyra)
    # Import lyra library, BSL
    FetchContent_Declare(
        vendor-lyra
        GIT_REPOSITORY https://github.com/bfgroup/Lyra
        GIT_SHALLOW TRUE
        GIT_TAG ee3c076fa6b9d64c9d249a21f5b9b5a8dae92cd8 # v1.6.1
        )

    FetchContent_MakeAvailable(vendor-lyra)
endif()

SET(PEMFINDER_EXAMPLE_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
)

add_executable(pemfinder ${PEMFINDER_EXAMPLE_SRC})
target_compile_features(pemfinder PUBLIC cxx_std_17)
target_compile_options(pemfinder PRIVATE -Wall -Werror)
target_link_libraries(pemfinder cppossl lyra)

cmake_minimum_required(VERSION 3.10)

project(spdm_lite)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}/..")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}/..")

# GoogleTest requires at least C++14
set(CMAKE_CXX_STANDARD 14)

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.12.1
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

## Declare libraries ##

add_library(utils STATIC common/utils.c)


add_library(everparse STATIC
    everparse/SPDM.c
    everparse/SPDMWrapper.c)

target_link_libraries(everparse
    utils)


add_library(common STATIC
    common/algorithms.c
    common/crypto.c
    common/crypto_types.c
    common/error.c
    common/key_schedule.c
    common/session.c
    common/sign.c
    common/transcript.c)

target_link_libraries(common
    everparse
    utils)


add_library(requester STATIC
    requester/requester.c
    requester/requester_finish.c
    requester/requester_get_capabilities.c
    requester/requester_get_pub_key.c
    requester/requester_get_version.c
    requester/requester_give_pub_key.c
    requester/requester_key_exchange.c
    requester/requester_negotiate_algorithms.c
    requester/send_request.c)

target_link_libraries(requester
    common
    everparse
    utils)


add_library(responder STATIC
    responder/responder.c
    responder/state_need_requester_key.c
    responder/state_session_established.c
    responder/state_waiting_for_finish.c
    responder/state_waiting_for_get_capabilities.c
    responder/state_waiting_for_get_version.c
    responder/state_waiting_for_key_exchange.c
    responder/state_waiting_for_negotiate_algorithms.c)

target_link_libraries(responder
    common
    everparse
    utils)


add_library(dummy_crypto STATIC crypto_impl/dummy_crypto.c)
add_library(mbedtls_crypto STATIC crypto_impl/mbedtls_crypto.c)

target_link_libraries(mbedtls_crypto
    common
    mbedcrypto
    pthread)


add_library(testing STATIC
    testing/add_2_app.c
    testing/host_context.c
    testing/utils.cc)

target_link_libraries(testing
    common
    requester
    responder
    utils
    mbedtls_crypto)


## Declare tests ##

set(TESTS
    requester_test
    spdm_parser_test
    state_waiting_for_get_version_test
    state_waiting_for_get_capabilities_test
    state_waiting_for_negotiate_algorithms_test
    state_waiting_for_key_exchange_test
    state_need_requester_key_test
    state_waiting_for_finish_test
    state_session_established_test)

set(TEST_LIBS
    testing
    common
    everparse
    requester
    responder
    mbedtls_crypto
    GTest::gtest_main)

enable_testing()

include(GoogleTest)

foreach(TEST ${TESTS})
    add_executable(${TEST} testing/${TEST}.cc)
    target_link_libraries(${TEST} ${TEST_LIBS})
    gtest_discover_tests(${TEST})
endforeach()

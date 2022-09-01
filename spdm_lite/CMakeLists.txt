cmake_minimum_required(VERSION 3.10)

project(spdm_lite)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCMAKE_BUILD -I${CMAKE_CURRENT_SOURCE_DIR}/include")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCMAKE_BUILD -I${CMAKE_CURRENT_SOURCE_DIR}/include")

set(TEST_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/testing/include")

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

add_library(utils STATIC
    library/common/utils.c)


add_library(everparse STATIC
    library/everparse/SPDM.c
    library/everparse/SPDMWrapper.c)

target_link_libraries(everparse
    utils)


add_library(common STATIC
    library/common/algorithms.c
    library/common/crypto.c
    library/common/crypto_types.c
    library/common/error.c
    library/common/key_schedule.c
    library/common/session.c
    library/common/sign.c
    library/common/transcript.c
    library/common/vendor_defined_pub_key.c)

target_link_libraries(common
    everparse
    utils)


add_library(requester STATIC
    library/requester/requester.c
    library/requester/requester_finish.c
    library/requester/requester_get_capabilities.c
    library/requester/requester_get_pub_key.c
    library/requester/requester_get_version.c
    library/requester/requester_give_pub_key.c
    library/requester/requester_key_exchange.c
    library/requester/requester_negotiate_algorithms.c
    library/requester/send_request.c)

target_link_libraries(requester
    common
    everparse
    utils)


add_library(responder STATIC
    library/responder/responder.c
    library/responder/state_need_requester_key.c
    library/responder/state_session_established.c
    library/responder/state_waiting_for_finish.c
    library/responder/state_waiting_for_get_capabilities.c
    library/responder/state_waiting_for_get_version.c
    library/responder/state_waiting_for_key_exchange.c
    library/responder/state_waiting_for_negotiate_algorithms.c)

target_link_libraries(responder
    common
    everparse
    utils)


add_library(raw_serialize STATIC
    library/crypto_impl/raw_serialize.c)

add_library(mbedtls_crypto STATIC
    library/crypto_impl/mbedtls_crypto.c
    library/crypto_impl/mbedtls_helpers.c
    library/crypto_impl/mbedtls_sign.c)

target_link_libraries(mbedtls_crypto
    common
    mbedcrypto
    pthread)

add_library(tpmt_public_serialize STATIC
    library/crypto_impl/tpmt_public_serialize.c)

target_link_libraries(tpmt_public_serialize
    common
    libtss2-mu.so)

add_library(testing STATIC
    testing/library/add_2_app.c
    testing/library/dummy_crypto.c
    testing/library/host_context.c
    testing/library/utils.cc)

target_link_libraries(testing
    common
    requester
    responder
    utils
    mbedtls_crypto
    raw_serialize)

target_include_directories(testing PUBLIC ${TEST_INCLUDES})

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
    state_session_established_test
    tpmt_public_serialize_test)

set(TEST_LIBS
    testing
    common
    everparse
    requester
    responder
    mbedtls_crypto
    raw_serialize
    tpmt_public_serialize
    GTest::gtest_main)

enable_testing()

include(GoogleTest)

foreach(TEST ${TESTS})
    add_executable(${TEST} testing/${TEST}.cc)
    target_include_directories(${TEST} PUBLIC ${TEST_INCLUDES})
    target_link_libraries(${TEST} ${TEST_LIBS})
    gtest_discover_tests(${TEST})
endforeach()

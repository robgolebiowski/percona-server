IF(NOT GMOCK_FOUND)
    RETURN()
ENDIF()

IF (NOT WITH_CURL)
    message("Not building keyring_vault, WITH_CURL not specified")
    RETURN()
ENDIF()

FIND_LIBRARY(CURL_LIBRARY
        NAMES curl
        HINTS ${WITH_CURL}/lib)

IF (NOT CURL_LIBRARY)
    message("Not building keyring_vault, could not find curl library")
    RETURN()
ENDIF()

CHECK_INCLUDE_FILE_CXX(${WITH_CURL}/include/curl/curl.h HAVE_CURL_HEADERS)

IF (NOT HAVE_CURL_HEADERS)
    message("Not building keyring_vault, could not find curl headers")
    RETURN()
ENDIF()

#INCLUDE_DIRECTORIES(${BOOST_PATCHES_DIR})
#INCLUDE_DIRECTORIES(SYSTEM ${BOOST_INCLUDE_DIR})

INCLUDE_DIRECTORIES(
        ${GMOCK_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/sql
#        ${CMAKE_SOURCE_DIR}/plugin/keyring
        ${CMAKE_SOURCE_DIR}/plugin/keyring/common
        ${CMAKE_SOURCE_DIR}/plugin/keyring_vault
        ${CMAKE_SOURCE_DIR}/unittest/gunit
        ${CMAKE_SOURCE_DIR}/unittest/gunit/keyring
        ${WITH_CURL}/include
)


SET(TESTS
#        keyring-api
#        keys_container
#        buffered_file_io
#        file_io
        vault_io
        vault_parser
        vault_credentials_parser
        vault_keys_container
        vault_keyring-api
        )

#IF (MERGE_UNITTESTS)
#    SET(merge_keyring_file_tests ${CMAKE_CURRENT_BINARY_DIR}/merge_keyring_file_tests-t.cc)
#    SET_SOURCE_FILES_PROPERTIES(merge_keyring_file_tests PROPERTIES GENERATED 1)
#
#    INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
#
#    FILE(WRITE ${merge_keyring_file_tests} "// Merging Keyring_file unit tests\n")
#    FILE(APPEND ${merge_keyring_file_tests} "#include \"my_config.h\"\n")
#    FILE(APPEND ${merge_keyring_file_tests} "#define MERGE_UNITTESTS\n")
#
#    FOREACH(test ${TESTS})
#        FILE(APPEND ${merge_keyring_file_tests} "#include \"${test}-t.cc\"\n")
#    ENDFOREACH()
#
#    SET(SRC_FILES ${merge_keyring_file_tests})
#    LIST(APPEND SRC_FILES
#            ${CMAKE_SOURCE_DIR}/plugin/keyring/common/keyring_key.cc
#            ${CMAKE_SOURCE_DIR}/plugin/keyring/common/keys_container.cc
#            ${CMAKE_SOURCE_DIR}/plugin/keyring/buffered_file_io.cc
#            ${CMAKE_SOURCE_DIR}/plugin/keyring/file_io.cc
#            ${CMAKE_SOURCE_DIR}/plugin/keyring/buffer.cc
#            ${CMAKE_SOURCE_DIR}/plugin/keyring/hash_to_buffer_serializer.cc
#            )
#
#    IF(WIN32)
#        LIST(APPEND SRC_FILES ../../../sql/nt_servc.cc)
#    ENDIF()
#
#    ADD_EXECUTABLE(merge_keyring_file_tests-t ${SRC_FILES})
#
#    TARGET_LINK_LIBRARIES(merge_keyring_file_tests-t gunit_large strings dbug regex mysys sql)
#    TARGET_LINK_LIBRARIES(merge_keyring_file_tests-t sql binlog rpl master slave sql)
#
#    IF(WITH_PERFSCHEMA_STORAGE_ENGINE)
#        TARGET_LINK_LIBRARIES(merge_keyring_file_tests-t perfschema)
#    ENDIF()
#
#    ADD_DEPENDENCIES(merge_keyring_file_tests-t GenError)
#
#    ADD_TEST(merge_keyring_file_tests merge_keyring_file_tests-t)
#
#ELSE()

    FOREACH(test ${TESTS})
        SET(SRC_FILES ${test}-t.cc
                ${CMAKE_SOURCE_DIR}/plugin/keyring/common/keyring_key.cc
                ${CMAKE_SOURCE_DIR}/plugin/keyring/common/keys_container.cc
#                ${CMAKE_SOURCE_DIR}/plugin/keyring/buffered_file_io.cc
#                ${CMAKE_SOURCE_DIR}/plugin/keyring/file_io.cc
#                ${CMAKE_SOURCE_DIR}/plugin/keyring/buffer.cc
#                ${CMAKE_SOURCE_DIR}/plugin/keyring/hash_to_buffer_serializer.cc
                ${CMAKE_SOURCE_DIR}/plugin/keyring_vault/vault_keys_list.cc
                ${CMAKE_SOURCE_DIR}/plugin/keyring_vault/vault_key.cc
                ${CMAKE_SOURCE_DIR}/plugin/keyring_vault/vault_io.cc
                ${CMAKE_SOURCE_DIR}/plugin/keyring_vault/vault_curl.cc
                ${CMAKE_SOURCE_DIR}/plugin/keyring_vault/vault_credentials_parser.cc
                ${CMAKE_SOURCE_DIR}/plugin/keyring_vault/vault_keys_container.cc
                )
        IF(WIN32)
            LIST(APPEND SRC_FILES ../../../sql/nt_servc.cc)
        ENDIF()
        ADD_EXECUTABLE(${test}-t ${SRC_FILES})

        TARGET_LINK_LIBRARIES(${test}-t gunit_large strings dbug regex mysys sql)
        TARGET_LINK_LIBRARIES(${test}-t sql binlog rpl master slave sql ${CURL_LIBRARY})

        IF(WITH_PERFSCHEMA_STORAGE_ENGINE)
            TARGET_LINK_LIBRARIES(${test}-t perfschema)
            TARGET_LINK_LIBRARIES(${test}-t perfschema pfs_server_stubs)
        ENDIF()

        ADD_TEST(${test} ${test}-t)
    ENDFOREACH()
#ENDIF()

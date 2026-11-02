cmake_minimum_required(VERSION 3.16)

# The version is VERSION's, so the library, the package and the release tag agree.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" IYA_OIDC_VERSION)
string(STRIP "${IYA_OIDC_VERSION}" IYA_OIDC_VERSION)
project(oidc-caep-risc-c VERSION ${IYA_OIDC_VERSION} LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# On when this is the top-level project (a checkout, the Docker test stage); a package
# build (a Conan recipe, add_subdirectory) turns them off and gets the library alone.
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(IYA_OIDC_TOP_LEVEL ON)
else()
  set(IYA_OIDC_TOP_LEVEL OFF)
endif()
option(IYA_OIDC_BUILD_TESTS "Build the tests" ${IYA_OIDC_TOP_LEVEL})
option(IYA_OIDC_BUILD_PROGRAMS "Build the demo and the command-line programs" ${IYA_OIDC_TOP_LEVEL})

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Static or shared as BUILD_SHARED_LIBS says (static when it is unset).
add_library(iya_oidc
  src/b64.cpp
  src/c_api.cpp
  src/crypto.cpp
  src/http.cpp
  src/json.cpp
  src/rp.cpp
  src/ssf.cpp
  src/util.cpp)
add_library(iya::oidc ALIAS iya_oidc)
target_include_directories(iya_oidc
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(iya_oidc PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
# The C++ headers need C++17; a consumer gets that from the target.
target_compile_features(iya_oidc PUBLIC cxx_std_17)
set_target_properties(iya_oidc PROPERTIES
  EXPORT_NAME oidc
  POSITION_INDEPENDENT_CODE ON
  VERSION ${PROJECT_VERSION}
  # 0.x: every minor version may break the ABI.
  SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})

# The library, its public headers (include/ holds nothing else), and a CMake package:
#   find_package(iya_oidc REQUIRED)
#   target_link_libraries(app PRIVATE iya::oidc)
install(TARGETS iya_oidc EXPORT iya_oidcTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT iya_oidcTargets NAMESPACE iya:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iya_oidc)
configure_package_config_file(cmake/iya_oidcConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/iya_oidcConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iya_oidc)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/iya_oidcConfigVersion.cmake
  COMPATIBILITY SameMinorVersion)
install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/iya_oidcConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/iya_oidcConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iya_oidc)

if(IYA_OIDC_BUILD_PROGRAMS OR IYA_OIDC_BUILD_TESTS)
add_executable(oidc-caep-risc-demo demo/main.cpp)
target_include_directories(oidc-caep-risc-demo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(oidc-caep-risc-demo PRIVATE iya_oidc)
add_executable(oidc_tests
  tests/main.c
  tests/rp_tests.c
  tests/stub.cpp
)
target_include_directories(oidc_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/tests)
target_link_libraries(oidc_tests PRIVATE iya_oidc)
endif()

if(IYA_OIDC_BUILD_TESTS)
add_executable(oidc_trust_tests tests/trust.c)
target_include_directories(oidc_trust_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(oidc_trust_tests PRIVATE iya_oidc OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
add_executable(oidc_cpp_smoke tests/cpp_smoke.cpp)
target_link_libraries(oidc_cpp_smoke PRIVATE iya_oidc)
enable_testing()
set(IYA_TESTS
  TestDefaultScopesAndAtHash
  TestSignsInWithPKCE
  TestRefusesACallbackThatIsNotThisSignIn
  TestAcceptsACodeOnce
  TestRefusesBadTokens
  TestRefreshAndClientCredentials
  TestPAR
  TestPostAndPrivateKeyJWT
  TestReadsConfigurationFileNames
  TestSignalsFlag
  TestVerifiesASETAgainstTheJWKS
  TestReadsSubjectForms
  TestPollsAndEndsOnlyTheNamedSession
  TestOidcErrorIsExported
)
foreach(name ${IYA_TESTS})
  add_test(NAME ${name} COMMAND oidc_tests ${name})
endforeach()
set(IYA_TRUST_TESTS
  TestTlsCaChainIsTheTrustStore
  TestAForgedLeafBeforeTheRealCaIsRefused
  TestHostNameIsChecked
  TestConfigureWritesTheWholeChain
)
foreach(name ${IYA_TRUST_TESTS})
  add_test(NAME ${name} COMMAND oidc_trust_tests ${name})
  set_tests_properties(${name} PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} TIMEOUT 180)
endforeach()
add_test(NAME CppSmoke COMMAND oidc_cpp_smoke)
endif()

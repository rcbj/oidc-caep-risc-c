cmake_minimum_required(VERSION 3.16)
project(oidc-caep-risc-c LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(iya_oidc
  src/b64.cpp
  src/c_api.cpp
  src/crypto.cpp
  src/http.cpp
  src/json.cpp
  src/rp.cpp
  src/ssf.cpp
  src/util.cpp
)
target_include_directories(iya_oidc
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(iya_oidc PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

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

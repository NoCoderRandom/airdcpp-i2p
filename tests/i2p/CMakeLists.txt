if(NOT WIN32)
  add_executable(airdcpp-i2p-sam-tests
    SamClientTest.cpp
  )

  target_link_libraries(airdcpp-i2p-sam-tests PRIVATE airdcpp)

  add_test(NAME airdcpp-i2p-sam-tests COMMAND airdcpp-i2p-sam-tests)
  set_tests_properties(airdcpp-i2p-sam-tests PROPERTIES TIMEOUT 20)
endif()

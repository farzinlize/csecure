link_libraries(libcs)

# former test
add_executable(old-secure old-test.c)
add_test(NAME old-secure COMMAND old-secure)

#simple test
add_executable(simple-secure simple-test.c)
add_test(NAME simple-secure COMMAND simple-secure)
add_executable(wrela Main.cpp)
wrela_target_defaults(wrela)
target_link_libraries(wrela PRIVATE wrela::driver)

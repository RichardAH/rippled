#[===================================================================[
 NIH dep: lmdb: database backend for rippled nodestore
#]===================================================================]

add_library (lmdb STATIC IMPORTED GLOBAL)
ExternalProject_Add (lmdb_src
  PREFIX ${nih_cache_path}
  URL https://github.com/LMDB/lmdb/archive/refs/tags/LMDB_0.9.29.zip
  TLS_VERIFY false
  LOG_BUILD ON
  LOG_CONFIGURE ON
  PATCH_COMMAND
    ${CMAKE_COMMAND} -E copy_if_different
    ${CMAKE_CURRENT_SOURCE_DIR}/Builds/CMake/CMake_lmdb.txt
    <SOURCE_DIR>/CMakeLists.txt
  COMMAND
    pwd
  BUILD_COMMAND
    ${CMAKE_COMMAND}
    --build .
    --config $<CONFIG>
    $<$<VERSION_GREATER_EQUAL:${CMAKE_VERSION},3.12>:--parallel ${ep_procs}>
  TEST_COMMAND ""
  INSTALL_COMMAND ""
  BUILD_BYPRODUCTS
      <BINARY_DIR>/liblmdb.a
)
ExternalProject_Get_Property (lmdb_src BINARY_DIR)
ExternalProject_Get_Property (lmdb_src SOURCE_DIR)
set (lmdb_src_BINARY_DIR "${BINARY_DIR}")
set (lmdb_src_SOURCE_DIR "${SOURCE_DIR}")
add_dependencies (lmdb lmdb_src)
target_include_directories (ripple_libs SYSTEM INTERFACE "${lmdb_src_SOURCE_DIR}/libraries/")
set_target_properties (lmdb PROPERTIES
  IMPORTED_LOCATION_DEBUG
    "${lmdb_src_BINARY_DIR}/liblmdb.a"
  IMPORTED_LOCATION_RELEASE
    "${lmdb_src_BINARY_DIR}/liblmdb.a"
  INTERFACE_INCLUDE_DIRECTORIES
    "${lmdb_src_SOURCE_DIR}/libraries/liblmdb/")
target_link_libraries (ripple_libs INTERFACE lmdb)
add_library (NIH::Lmdb ALIAS lmdb)

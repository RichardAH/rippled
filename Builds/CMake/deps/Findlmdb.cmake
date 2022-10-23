if(static)
  set(LMDB_LIB liblmdb.a)
else()
  set(LMDB_LIB liblmdb.so)
endif()

find_library (lmdb
  NAMES ${LMDB_LIB}
  HINTS
    ${lmdb_LIBDIR}
    ${lmdb_LIBRARY_DIRS}
  NO_DEFAULT_PATH)

find_path (LMDB_INCLUDE_DIR
  NAMES lmdb.h
  HINTS
    ${lmdb_INCLUDEDIR}
    ${lmdb_INCLUDEDIRS}
  NO_DEFAULT_PATH)

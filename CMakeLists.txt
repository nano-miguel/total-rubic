cmake_minimum_required(VERSION 3.16)
project(RUBIC-A VERSION 0.1 LANGUAGES CXX)

# =========================
# SANITY CHECK: ruta del proyecto
# =========================
string(REGEX MATCH "[][(){}&;|<>$\\\\`'\"!*? \t]" _rubic_badchar "${CMAKE_SOURCE_DIR}")
if(_rubic_badchar)
    message(FATAL_ERROR
        "\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║  RUTA INVÁLIDA PARA EL PROYECTO                              ║\n"
        "╠══════════════════════════════════════════════════════════════╣\n"
        "║  La carpeta del proyecto contiene el carácter: '${_rubic_badchar}'\n"
        "║  Ruta actual: ${CMAKE_SOURCE_DIR}\n"
        "║                                                              ║\n"
        "║  Esto rompe el build de RPM (los .spec son scripts shell).   ║\n"
        "║  Renombra la carpeta sin: ) ( & ; | < > $ \\ ` ' \" ! * ? [ ] { } ni espacios\n"
        "║                                                              ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n")
endif()

# =========================
# ESTÁNDAR C++
# =========================
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)
include(CTest)

# =========================
# OPCIONES
# =========================
option(RUBIC_USE_CCACHE     "Usar ccache si está disponible"        ON)
option(RUBIC_WARNINGS       "Habilitar warnings útiles"              ON)
option(RUBIC_STRICT         "Convertir warnings en errores"          OFF)
option(RUBIC_SANITIZERS     "Compilar con ASan+UBSan (solo Debug)"   OFF)

set(RUBIC_PACKAGE_GENERATOR "BOTH" CACHE STRING
    "Generador de paquetes: DEB, RPM o BOTH")
set_property(CACHE RUBIC_PACKAGE_GENERATOR PROPERTY STRINGS "DEB" "RPM" "BOTH")
set(RUBIC_RPM_RELEASE "1" CACHE STRING "Release number para RPM")

# =========================
# CCACHE
# =========================
if(RUBIC_USE_CCACHE)
    find_program(CCACHE_BIN ccache)
    if(CCACHE_BIN)
        message(STATUS "ccache encontrado: ${CCACHE_BIN}")
        set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_BIN}")
    endif()
endif()

# =========================
# BOTAN
# =========================
find_package(Botan3 QUIET)
if(NOT Botan3_FOUND)
    find_package(botan QUIET)
    if(botan_FOUND)
        set(Botan3_FOUND TRUE)
        set(Botan3_LIBRARIES ${BOTAN_LIBRARIES})
        set(Botan3_INCLUDE_DIRS ${BOTAN_INCLUDE_DIRS})
    endif()
endif()

if(NOT Botan3_FOUND)
    set(BOTAN_LOCAL_ROOT "${CMAKE_SOURCE_DIR}/external/botan/build")
    set(BOTAN_LOCAL_INC  "${BOTAN_LOCAL_ROOT}/include/botan-3")
    set(BOTAN_LOCAL_LIB  "${BOTAN_LOCAL_ROOT}/lib")

    if(EXISTS "${BOTAN_LOCAL_INC}/botan/version.h" AND
       (EXISTS "${BOTAN_LOCAL_LIB}/libbotan-3.so" OR
        EXISTS "${BOTAN_LOCAL_LIB}/libbotan-3.a"))
        message(STATUS "Botan local encontrado en ${BOTAN_LOCAL_ROOT}")
        set(Botan3_FOUND       TRUE)
        set(Botan3_INCLUDE_DIRS "${BOTAN_LOCAL_INC}")
        set(Botan3_LIBRARIES   "botan-3")
        set(BOTAN_LOCAL_LINK_DIRS "${BOTAN_LOCAL_LIB}")
    else()
        message(FATAL_ERROR
            "No se encontró Botan 3.\n"
            " - Compílalo en: ${BOTAN_LOCAL_ROOT}\n"
            " - O instálalo en el sistema.")
    endif()
endif()

# =========================
# SOURCES
# =========================
file(GLOB_RECURSE RUBIC_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_SOURCE_DIR}/src/*.cpp
)

if(NOT RUBIC_SOURCES)
    message(FATAL_ERROR "No se encontraron .cpp en ${CMAKE_SOURCE_DIR}/src/")
endif()

list(LENGTH RUBIC_SOURCES RUBIC_SOURCES_COUNT)
message(STATUS "Fuentes encontradas: ${RUBIC_SOURCES_COUNT}")

add_executable(RUBIC-A ${RUBIC_SOURCES})

# =========================
# INCLUDES
# =========================
target_include_directories(RUBIC-A PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/cipher
    ${CMAKE_SOURCE_DIR}/src/keygest
    ${CMAKE_SOURCE_DIR}/src/share
    ${CMAKE_SOURCE_DIR}/src/ui
    ${Botan3_INCLUDE_DIRS}
)

# =========================
# LINK
# =========================
if(DEFINED BOTAN_LOCAL_LINK_DIRS)
    target_link_directories(RUBIC-A PRIVATE ${BOTAN_LOCAL_LINK_DIRS})
endif()

target_link_libraries(RUBIC-A PRIVATE
    ${Botan3_LIBRARIES}
    pthread
    dl
    stdc++fs
)

# =========================
# RPATH
# =========================
if(DEFINED BOTAN_LOCAL_LINK_DIRS)
    set(_rubic_build_rpath "${BOTAN_LOCAL_LINK_DIRS}")
else()
    set(_rubic_build_rpath "")
endif()

set_target_properties(RUBIC-A PROPERTIES
    BUILD_RPATH   "${_rubic_build_rpath}"
    INSTALL_RPATH "\$ORIGIN/../${CMAKE_INSTALL_LIBDIR}"
)

# =========================
# WARNINGS
# =========================
if(RUBIC_WARNINGS)
    target_compile_options(RUBIC-A PRIVATE
        -Wall -Wextra -Wpedantic
        -Wno-unused-parameter
        -Wno-deprecated-declarations
        -Wno-missing-field-initializers
        -Wno-sign-compare
        -Wno-unused-variable
        -Wno-unused-but-set-variable
        -Wno-format-truncation
        -Wno-reorder
        -Wno-class-memaccess
        -Wno-misleading-indentation
    )
endif()

if(RUBIC_STRICT)
    target_compile_options(RUBIC-A PRIVATE -Werror)
endif()

# =========================================================
# ★★★ OPTIMIZACIÓN Y DETECCIÓN AUTOMÁTICA DE AVX-512/AVX2 ★★★
# =========================================================
# El código de unit_encryptor.cpp usa:
#     #if defined(AVX512F)   y   #if defined(AVX2)
# pero "-march=native" solo define __AVX512F__ / __AVX2__ (con guiones bajos).
# Por eso detectamos qué extensiones están disponibles y definimos las macros
# AVX512F / AVX2 manualmente. Así el bloque SIMD SÍ se compila.
# =========================================================
include(CheckCXXCompilerFlag)
include(CheckCXXSourceCompiles)

set(_rubic_opt_flags "")
set(_rubic_simd_defs "")

# 1) Intentamos -march=native (lo ideal en x86_64)
check_cxx_compiler_flag("-march=native" COMPILER_SUPPORTS_MARCH_NATIVE)

if(COMPILER_SUPPORTS_MARCH_NATIVE AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|i[3-6]86")
    message(STATUS "Habilitando instrucciones nativas del CPU (-march=native)")
    set(_rubic_opt_flags "-march=native")

    # 2) Probamos si con -march=native podemos compilar código AVX-512
    set(CMAKE_REQUIRED_FLAGS "-march=native")

    check_cxx_source_compiles("
        #include <immintrin.h>
        int main() {
            __m512i a = _mm512_set1_epi32(1);
            __m512i b = _mm512_set1_epi32(2);
            __m512i c = _mm512_xor_si512(a, b);
            (void)c;
            return 0;
        }" RUBIC_HAS_AVX512F)

    check_cxx_source_compiles("
        #include <immintrin.h>
        int main() {
            __m256i a = _mm256_set1_epi32(1);
            __m256i b = _mm256_set1_epi32(2);
            __m256i c = _mm256_xor_si256(a, b);
            (void)c;
            return 0;
        }" RUBIC_HAS_AVX2)

    set(CMAKE_REQUIRED_FLAGS "")

    if(RUBIC_HAS_AVX512F)
        message(STATUS "✓ AVX-512F detectado → definiendo macro AVX512F")
        list(APPEND _rubic_simd_defs AVX512F)
    else()
        message(STATUS "✗ AVX-512F no disponible en este CPU/compilador")
    endif()

    if(RUBIC_HAS_AVX2)
        message(STATUS "✓ AVX2 detectado → definiendo macro AVX2")
        list(APPEND _rubic_simd_defs AVX2)
    else()
        message(STATUS "✗ AVX2 no disponible en este CPU/compilador")
    endif()

else()
    # Fallback para CPUs no-x86 o compiladores sin -march=native
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        message(STATUS "Arquitectura ARM64: usando NEON (auto-vectorización del compilador)")
    else()
        message(STATUS "AVISO: -march=native no soportado. Usando genérico.")
    endif()
endif()

# Aplicar flags de optimización por configuración
target_compile_options(RUBIC-A PRIVATE
    $<$<CONFIG:Release>:-O3 -flto -DNDEBUG ${_rubic_opt_flags}>
    $<$<CONFIG:Debug>:-O0 -g3 -ggdb>
    $<$<CONFIG:RelWithDebInfo>:-O2 -g -DNDEBUG ${_rubic_opt_flags}>
)

# ★★★ CLAVE: definir las macros que el código espera ★★★
if(_rubic_simd_defs)
    target_compile_definitions(RUBIC-A PRIVATE ${_rubic_simd_defs})
endif()

# LTO
include(CheckIPOSupported)
check_ipo_supported(RESULT _rubic_ipo_ok OUTPUT _rubic_ipo_msg)
if(_rubic_ipo_ok)
    set_property(TARGET RUBIC-A PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
else()
    message(STATUS "LTO no soportado: ${_rubic_ipo_msg}")
endif()

# =========================
# SANITIZERS
# =========================
if(RUBIC_SANITIZERS AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Sanitizers activados (ASan + UBSan)")
    target_compile_options(RUBIC-A PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(RUBIC-A PRIVATE
        -fsanitize=address,undefined)
endif()

# =========================
# INSTALL — BINARIO
# =========================
install(TARGETS RUBIC-A
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# =========================
# INSTALL — LIBS BOTAN
# =========================
if(DEFINED BOTAN_LOCAL_LINK_DIRS)
    install(DIRECTORY
        ${BOTAN_LOCAL_LINK_DIRS}/
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        FILES_MATCHING
            PATTERN "libbotan-3.so*"
            PATTERN "libbotan-3.a"
    )
endif()

# =========================
# INSTALL — TRADUCCIONES
# =========================
if(EXISTS "${CMAKE_SOURCE_DIR}/translations")
    install(DIRECTORY translations/
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/rubic-a/translations
        FILES_MATCHING PATTERN "*.lang"
    )
endif()

# =========================
# INSTALL — DESKTOP / ICONOS
# =========================
if(EXISTS "${CMAKE_SOURCE_DIR}/assets/RUBIC-A.desktop")
    install(FILES assets/RUBIC-A.desktop
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/applications)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/assets/rubic.png")
    install(FILES assets/rubic.png
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/256x256/apps
        RENAME rubic-a.png)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/assets/Rubic.svg")
    install(FILES assets/Rubic.svg
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/apps
        RENAME rubic-a.svg)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/assets/rubic.svg")
    install(FILES assets/rubic.svg
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/apps
        RENAME rubic-a.svg)
endif()

# =========================
# INSTALL — LICENCIA
# =========================
if(EXISTS "${CMAKE_SOURCE_DIR}/LICENSE")
    install(FILES LICENSE
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/licenses/rubic-a
        RENAME LICENSE)
endif()

# =========================================================
# CPACK
# =========================================================
set(CPACK_PACKAGE_NAME              "rubic-a")
set(CPACK_PACKAGE_VERSION           ${PROJECT_VERSION})
set(CPACK_PACKAGE_VENDOR            "wallace")
set(CPACK_PACKAGE_CONTACT           "wallace")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "RUBIC-A encrypted system tool")
set(CPACK_PACKAGE_DESCRIPTION
    "RUBIC-A: cifrado de unidades y archivos con AES-256 (XTS/GCM) y firmas post-cuánticas via Botan 3.")
set(CPACK_PACKAGE_HOMEPAGE_URL      "https://example.com/rubic-a")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "rubic-a")

if(EXISTS "${CMAKE_SOURCE_DIR}/LICENSE")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    set(_rubic_arch_deb "amd64")
    set(_rubic_arch_rpm "x86_64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(_rubic_arch_deb "arm64")
    set(_rubic_arch_rpm "aarch64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i[3-6]86")
    set(_rubic_arch_deb "i386")
    set(_rubic_arch_rpm "i686")
else()
    set(_rubic_arch_deb "all")
    set(_rubic_arch_rpm "noarch")
endif()

set(CPACK_DEBIAN_PACKAGE_NAME        "rubic-a")
set(CPACK_DEBIAN_FILE_NAME           "rubic-a_${PROJECT_VERSION}.deb")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "${_rubic_arch_deb}")
set(CPACK_DEBIAN_PACKAGE_DEPENDS     "libc6, libstdc++6")
set(CPACK_DEBIAN_PACKAGE_SECTION     "utils")
set(CPACK_DEBIAN_PACKAGE_PRIORITY    "optional")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER  "wallace")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS   OFF)

set(CPACK_RPM_PACKAGE_NAME          "rubic-a")
set(CPACK_RPM_FILE_NAME             "rubic-a-${PROJECT_VERSION}-${RUBIC_RPM_RELEASE}.${_rubic_arch_rpm}.rpm")
set(CPACK_RPM_PACKAGE_VERSION       "${PROJECT_VERSION}")
set(CPACK_RPM_PACKAGE_RELEASE       "${RUBIC_RPM_RELEASE}")
set(CPACK_RPM_PACKAGE_ARCHITECTURE  "${_rubic_arch_rpm}")
set(CPACK_RPM_PACKAGE_LICENSE       "GPL-3.0-or-later")
set(CPACK_RPM_PACKAGE_GROUP         "Applications/System")
set(CPACK_RPM_PACKAGE_VENDOR        "wallace")
set(CPACK_RPM_PACKAGE_URL           "https://example.com/rubic-a")
set(CPACK_RPM_PACKAGE_SUMMARY       "RUBIC-A encrypted system tool")
set(CPACK_RPM_PACKAGE_DESCRIPTION
    "RUBIC-A: cifrado de unidades y archivos con AES-256 (XTS/GCM) y firmas post-cuánticas via Botan 3.")
set(CPACK_RPM_PACKAGE_REQUIRES      "glibc, libstdc++")
set(CPACK_RPM_PACKAGE_AUTOREQ       OFF)
set(CPACK_RPM_PACKAGE_AUTOPROV      OFF)
set(CPACK_RPM_COMPRESSION_TYPE      "zstd")

if(RUBIC_PACKAGE_GENERATOR STREQUAL "RPM")
    set(_rubic_cpack_generators "RPM")
elseif(RUBIC_PACKAGE_GENERATOR STREQUAL "DEB")
    set(_rubic_cpack_generators "DEB")
else()
    set(_rubic_cpack_generators "DEB;RPM")
endif()

set(CPACK_GENERATOR "${_rubic_cpack_generators}" CACHE STRING "CPack generators" FORCE)

include(CPack)

# =========================
# RESUMEN FINAL
# =========================
message(STATUS "")
message(STATUS "═══════════════════════════════════════════════")
message(STATUS "  RUBIC-A  v${PROJECT_VERSION}")
message(STATUS "═══════════════════════════════════════════════")
message(STATUS "  Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler   : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Arch       : ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "  SIMD defs  : ${_rubic_simd_defs}")
message(STATUS "  Opt flags  : ${_rubic_opt_flags}")
message(STATUS "  Botan inc  : ${Botan3_INCLUDE_DIRS}")
message(STATUS "  Botan libs : ${Botan3_LIBRARIES}")
message(STATUS "  Sources    : ${RUBIC_SOURCES_COUNT}")
message(STATUS "  ccache     : ${CCACHE_BIN}")
message(STATUS "  Warnings   : ${RUBIC_WARNINGS}")
message(STATUS "  Sanitizers : ${RUBIC_SANITIZERS}")
message(STATUS "  Package    : ${_rubic_cpack_generators}")
message(STATUS "═══════════════════════════════════════════════")
message(STATUS "")
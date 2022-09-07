cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(psp2etoi)
set(TITLE_ID "SKGPP2E2I")
set(TITLE_NAME "psp2etoi")

include("${VITASDK}/share/vita.cmake" REQUIRED)

enable_language(C ASM)

set(CMAKE_C_FLAGS "-Wl,-q -Wall -O3 -std=gnu99")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -fno-rtti -fno-exceptions")

vita_create_stubs(psp2etoiK_stubs compile_psp2etoi.elf ${CMAKE_SOURCE_DIR}/kernel/psp2etoiK.yml KERNEL)

add_executable(compile_psp2etoi.elf
	kernel/main.c
)

target_link_libraries(compile_psp2etoi.elf
	SKPLForKernel_stub
	SceSysclibForDriver_stub
	SceSysmemForDriver_stub
	SceDebugForDriver_stub
	SceSysconForDriver_stub
	SceSblSmCommForKernel_stub
	SceThreadmgrForDriver_stub
    taihenModuleUtils_stub
	taihenForKernel_stub
	SceModulemgrForDriver_stub
    SceIdStorageForDriver_stub
    SceKernelSuspendForDriver_stub
	SceIofilemgrForDriver_stub
)

set_target_properties(compile_psp2etoi.elf
	PROPERTIES LINK_FLAGS "-nostdlib"
	COMPILE_FLAGS "-D__VITA_KERNEL__"
)

add_custom_target(compile_psp2etoi.skprx ALL
	COMMAND vita-elf-create -e ${CMAKE_SOURCE_DIR}/kernel/psp2etoiK.yml compile_psp2etoi.elf compile_psp2etoi.velf
	COMMAND vita-make-fself -c compile_psp2etoi.velf compile_psp2etoi.skprx
)

add_dependencies(compile_psp2etoi.skprx compile_psp2etoi.elf)

link_directories(
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_BINARY_DIR}/psp2etoiK_stubs
    ${CMAKE_BINARY_DIR}/kernel
)

add_executable(compile_app.elf
	app/main.c
	app/graphics.c
	app/font.c
	app/commands.c
	kernel/crc32.c
)

target_link_libraries(compile_app.elf
	taihen_stub
	SceDisplay_stub
	SceCtrl_stub
	psp2etoiK_stub
	SceAppMgr_stub
	ScePower_stub 
	SceVshBridge_stub
)

add_custom_target(compile_app.velf ALL
	COMMAND vita-elf-create compile_app.elf compile_app.velf
)

add_custom_target(compile_eboot.bin ALL
	COMMAND vita-make-fself -c compile_app.velf compile_eboot.bin
)

add_dependencies(compile_app.elf compile_psp2etoi.skprx)
add_dependencies(compile_app.velf compile_app.elf)
add_dependencies(compile_eboot.bin compile_app.velf)

add_custom_target(${PROJECT_NAME}.vpk ALL
	COMMAND vita-mksfoex -s TITLE_ID=${TITLE_ID} "${TITLE_NAME}" compile_param.sfo
	COMMAND vita-pack-vpk -s compile_param.sfo -b compile_eboot.bin
    -a compile_psp2etoi.skprx=psp2etoi.skprx
	-a res/psp2spl.skprx=psp2spl.skprx
	-a res/template.xml=sce_sys/livearea/contents/template.xml
	-a res/bg.png=sce_sys/livearea/contents/bg.png
	-a res/startup.png=sce_sys/livearea/contents/startup.png
	-a res/icon0.png=sce_sys/icon0.png ${PROJECT_NAME}.vpk
)
add_dependencies(${PROJECT_NAME}.vpk compile_eboot.bin compile_psp2etoi.skprx)

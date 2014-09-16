@echo off
rd /s /q CMakeFiles
rd /s /q nbproject
rd /s /q .idea
del CMakeCache.txt
del Makefile
del cmake_*
del compile_*
@echo on
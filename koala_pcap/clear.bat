@echo off
rd /s /q CMakeFiles/
rd /s /q nbproject
del /s /q CMakeCache.txt
del Makefile
del cmake_*
del compile_*
@echo on
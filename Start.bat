@echo off
REM Start XeoKey server (direct mode)
cd /d %~dp0
cd src
bun start

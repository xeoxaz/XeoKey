@echo off
REM Start XeoKey with internal process manager
cd /d %~dp0
cd src
bun run host.ts

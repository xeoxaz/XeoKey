@echo off
REM Start XeoKey with internal process manager
cd /d %~dp0
bun run host.ts

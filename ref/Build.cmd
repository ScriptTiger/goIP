@echo off

cd ..

if not exist go.sum (
	echo Initializing go.mod...
	go mod init github.com/ScriptTiger/goIP 2> nul
	go mod tidy 2> nul
)

cd ref

choice /m "Dev build?"
if %errorlevel% == 1 (set dev=1) else set dev=0

set GOARCH=amd64
call :Build_OS

if %dev% == 1 goto Exit

set GOARCH=386
call :Build_OS

:Exit
choice /m "Clean up go.mod before exiting?"
if %errorlevel% == 1 (
	cd ..
	del go.sum
	echo module github.com/ScriptTiger/goIP>go.mod
)
exit /b

:Build_OS

set GOOS=windows
set EXT=.exe
set INC=include_windows.go
call :Build_App

if %dev% == 1 exit /b

set GOOS=linux
set EXT=
set INC=include_other.go
call :Build_App

if %GOARCH% == 386 exit /b

set GOOS=darwin
set EXT=.app
set INC=include_other.go
call :Build_App

exit /b

:Build_App

set APP=Data_Update
call :Build

set APP=Network_Calculator
call :Build

set APP=IP_Search
call :Build

exit /b

:Build

if not exist "Release/%GOOS%_%GOARCH%" md "Release/%GOOS%_%GOARCH%"

echo Building %GOOS%_%GOARCH%/%APP%%EXT%...
go build -ldflags="-s -w" -o "Release/%GOOS%_%GOARCH%/%APP%%EXT%" %APP%.go %INC%

exit /b
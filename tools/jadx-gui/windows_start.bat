chcp 65001

@echo off
setlocal enabledelayedexpansion

rem 查找匹配的 exe文件
for %%f in (jadx-gui*.exe) do (
    set jarfile=%%f
    goto :runJar
)


goto :end

:runJar

!jarfile!

:end
endlocal

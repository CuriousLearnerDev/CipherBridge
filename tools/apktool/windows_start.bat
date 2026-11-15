chcp 65001

@echo off





%~d0    %进入这个脚本执行的盘符%
cd %~dp0   %进入这个脚本执行的目录%





..\jdk1_8_0_291\bin\java -jar apktool_2.12.1.jar -h


@echo. *********************使用说明*********************
@echo. 
@echo. 使用:  ..\jdk1_8_0_291\bin\java -jar apktool_2.12.1.jar -h
@echo.
@echo. **************************************************

cmd
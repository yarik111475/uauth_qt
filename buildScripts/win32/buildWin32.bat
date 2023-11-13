@echo off

::create current dir variable
SET CURRENT_DIR=%CD%
echo %CURRENT_DIR%

::set dirs variables
SET BUILD_DIR=%CURRENT_DIR%\build_x32
SET INSTALL_DIR=%CURRENT_DIR%\install_x32
SET DEPLOY_DIR=%CURRENT_DIR%\deploy_x32

::remove old dirs
rmdir /Q /S %BUILD_DIR%
rmdir /Q /S %INSTALL_DIR%
rmdir /Q /S %DEPLOY_DIR%

::create new dirs
mkdir %BUILD_DIR%
mkdir %INSTALL_DIR%
mkdir %DEPLOY_DIR%

::create qt/cmake/make variables
SET Qt5_DIR="C:/Qt/Qt5.14.2/5.14.2/msvc2017/lib/cmake/Qt5"
SET CMAKE_PREFIX_PATH="C:/Qt/Qt5.14.2/5.14.2/msvc2017"
SET CMAKE_PATH="C:/Program Files/CMake/bin/cmake.exe"
SET MAKE_PATH="C:/Qt/Ninja/ninja.exe"

::vs options
SET CMAKE_C_COMPILER="C:/Program Files (x86)/Microsoft Visual Studio/2017/Community/VC/Tools/MSVC/14.16.27023/bin/Hostx86/x86/cl.exe"
SET CMAKE_CXX_COMPILER="C:/Program Files (x86)/Microsoft Visual Studio/2017/Community/VC/Tools/MSVC/14.16.27023/bin/Hostx86/x86/cl.exe"
SET VC_VARS_PATH_BAT="C:/Program Files (x86)/Microsoft Visual Studio/2017/Community/VC/Auxiliary/Build/vcvars32.bat"
SET VC_REDISTR_DIR="C:/Program Files (x86)/Microsoft Visual Studio/2017/Community/VC/Redist/MSVC/14.16.27012"
SET OPENSSL_DIR="%CURRENT_DIR%/../../3rdparty/win32/openssl-1.1.1/x32"
set POSTGRE_DIR="%CURRENT_DIR%/../../3rdparty/win32/pgsql/x32"

::call vs script
call %VC_VARS_PATH_BAT%

::change dir to 'build'
cd %BUILD_DIR%

::run cmake
%CMAKE_PATH% ../../../ -GNinja^
 -DCMAKE_BUILD_TYPE:String=Release^
 -DCMAKE_INSTALL_PREFIX=%INSTALL_DIR%^
 -DQt5_DIR=%Qt5_DIR%^
 -DCMAKE_MAKE_PROGRAM=%MAKE_PATH%^
 -DCMAKE_PREFIX_PATH:STRING=%CMAKE_PREFIX_PATH%^
 -DCMAKE_C_COMPILER:STRING=%CMAKE_C_COMPILER%^
 -DCMAKE_CXX_COMPILER:STRING=%CMAKE_CXX_COMPILER%

%CMAKE_PATH% --build . --parallel --target all
%CMAKE_PATH% --install .

::deployer options
SET CQTDEPLOYER_DIR="C:/Qt/CQtDeployer/1.5"
SET QMAKE_PATH="C:/Qt/Qt5.14.2/5.14.2/msvc2017/bin/qmake.exe"

::deploy
call %CQTDEPLOYER_DIR%\cqtdeployer.bat -qmake %QMAKE_PATH% -bin %INSTALL_DIR%\bin\uaShell.exe -targetDir %DEPLOY_DIR%\bin noTranslations
call %CQTDEPLOYER_DIR%\cqtdeployer.bat -qmake %QMAKE_PATH% -bin %INSTALL_DIR%\bin\uaServer.exe -targetDir %DEPLOY_DIR%\bin noTranslations
call %CQTDEPLOYER_DIR%\cqtdeployer.bat -qmake %QMAKE_PATH% -bin %INSTALL_DIR%\bin\uaTables.exe -targetDir %DEPLOY_DIR%\bin noTranslations
call %CQTDEPLOYER_DIR%\cqtdeployer.bat -qmake %QMAKE_PATH% -bin %INSTALL_DIR%\bin\uaRequester.exe -targetDir %DEPLOY_DIR%\bin noTranslations
call %CQTDEPLOYER_DIR%\cqtdeployer.bat -qmake %QMAKE_PATH% -bin %INSTALL_DIR%\bin\QtHttp.dll -targetDir %DEPLOY_DIR%\bin noTranslations

::copy all openssl libraries and ms visual c++ distr package
copy %POSTGRE_DIR%\bin\libpq.dll          %DEPLOY_DIR%\bin\libpq.dll /Y
copy %POSTGRE_DIR%\bin\libiconv-2.dll     %DEPLOY_DIR%\bin\libiconv-2.dll /Y
copy %POSTGRE_DIR%\bin\libintl-8.dll      %DEPLOY_DIR%\bin\libintl-8.dll /Y
copy %POSTGRE_DIR%\bin\libpgtypes.dll     %DEPLOY_DIR%\bin\libpgtypes.dll /Y
copy %OPENSSL_DIR%\bin\libssl-1_1.dll     %DEPLOY_DIR%\bin\libssl-1_1.dll /Y
copy %OPENSSL_DIR%\bin\libcrypto-1_1.dll  %DEPLOY_DIR%\bin\libcrypto-1_1.dll /Y
copy %VC_REDISTR_DIR%\vc_redist.x86.exe   %DEPLOY_DIR%\vc_redist.x86.exe /Y

::cd to -up- dir
cd ..

::remove 'build' and 'install' dirs
rmdir /Q /S %BUILD_DIR%
rmdir /Q /S %INSTALL_DIR%

pause
::exit

#!/bin/bash
set -e

USER_NAME=$(whoami)
CURRENT_DIR=$(pwd)

echo "USER_NAME: ${USER_NAME}"
echo "CURRENT_DIR: ${CURRENT_DIR}"
echo "Create needed directories"

mkdir -p "${CURRENT_DIR}"/build
mkdir -p "${CURRENT_DIR}"/install
mkdir -p "${CURRENT_DIR}"/deploy

HOME_DIR="/home/${USER_NAME}"
BUILD_DIR="${CURRENT_DIR}"/build
INSTALL_DIR="${CURRENT_DIR}"/install
DEPLOY_DIR="${CURRENT_DIR}"/deploy

OPENSSL_DIR=${BUILD_DIR}/../../../3rdparty/linux/openssl-1.1.1
POSTGRE_LIB_DIR=${BUILD_DIR}/../../../3rdparty/linux/pgsql/lib

#cmake options
CMAKE_PATH="/usr/bin/cmake"
CMAKE_MAKE_PROGRAM="/usr/bin/ninja"
CMAKE_PREFIX_PATH="${HOME_DIR}/Qt/Qt5.14.2/5.14.2/gcc_64"
QT_QMAKE_EXECUTABLE="${CMAKE_PREFIX_PATH}"/bin/qmake
Qt5_DIR="${CMAKE_PREFIX_PATH}/lib/cmake/Qt5"
CQTDEPLOYER_DIR="${HOME_DIR}/Qt/CQtDeployer/1.5"

#run cmake
cd "${BUILD_DIR}"
${CMAKE_PATH}  ../../.. -DQt5_DIR=$Qt5_DIR`
` -DCMAKE_MAKE_PROGRAM=$CMAKE_MAKE_PROGRAM`
` -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR`
` -DCMAKE_PREFIX_PATH=$CMAKE_PREFIX_PATH`
` -GNinja`
` -DCMAKE_BUILD_TYPE:String=Release`
` -DQT_QMAKE_EXECUTABLE:STRING=$QT_QMAKE_EXECUTABLE`
` -DCMAKE_C_COMPILER:STRING=/usr/bin/gcc`
` -DCMAKE_CXX_COMPILER:STRING=/usr/bin/g++

#build and install
${CMAKE_PATH}  --build . --parallel --target all install

#deploy
${CQTDEPLOYER_DIR}/cqtdeployer.sh -qmake ${QT_QMAKE_EXECUTABLE} -bin ${INSTALL_DIR}/bin/uaServer -targetDir ${DEPLOY_DIR} noTranslations
${CQTDEPLOYER_DIR}/cqtdeployer.sh -qmake ${QT_QMAKE_EXECUTABLE} -bin ${INSTALL_DIR}/bin/uaShell -targetDir ${DEPLOY_DIR} noTranslations
${CQTDEPLOYER_DIR}/cqtdeployer.sh -qmake ${QT_QMAKE_EXECUTABLE} -bin ${INSTALL_DIR}/bin/uaTables -targetDir ${DEPLOY_DIR} noTranslations
${CQTDEPLOYER_DIR}/cqtdeployer.sh -qmake ${QT_QMAKE_EXECUTABLE} -bin ${INSTALL_DIR}/bin/uaRequester -targetDir ${DEPLOY_DIR} noTranslations
${CQTDEPLOYER_DIR}/cqtdeployer.sh -qmake ${QT_QMAKE_EXECUTABLE} -bin ${INSTALL_DIR}/lib/libQtHttp.so -targetDir ${DEPLOY_DIR} noTranslations

#copy/move shared libraries
mv -f ${DEPLOY_DIR}/bin/libQtHttp.so      ${DEPLOY_DIR}/lib/libQtHttp.so
cp -f ${POSTGRE_LIB_DIR}/libpq.so.5       ${DEPLOY_DIR}/lib/libpq.so.5
cp -f ${POSTGRE_LIB_DIR}/libpq.so.5.15    ${DEPLOY_DIR}/lib/libpq.so.5.15
cp -f ${OPENSSL_DIR}/lib/libssl.so.1.1    ${DEPLOY_DIR}/lib/libssl.so.1.1
cp -f ${OPENSSL_DIR}/lib/libcrypto.so.1.1 ${DEPLOY_DIR}/lib/libcrypto.so.1.1

#remove junk
rm -rf "${BUILD_DIR}"
rm -rf "${INSTALL_DIR}"

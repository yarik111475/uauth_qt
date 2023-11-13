#include "HttpServer.h"
#include "HttpClient.h"

void HttpServer::incomingConnection(qintptr socketDescriptor)
{
    HttpClient* httpClientPtr {new HttpClient(socketDescriptor,isIntegrityOk_,appSettingsPtr_)};
    QObject::connect(httpClientPtr,&QThread::finished,httpClientPtr,&HttpClient::deleteLater);
    httpClientPtr->start();
}

HttpServer::HttpServer(QSharedPointer<QSettings> appSettingsPtr, QObject *parent)
    :QTcpServer{parent},appSettingsPtr_{appSettingsPtr}
{
}

void HttpServer::integritySlot(bool isIntegrityOk, const QString &lastError)
{
    isIntegrityOk_=isIntegrityOk;
    if(!isIntegrityOk_){
        const QString logMsg {QStringLiteral("Integrity failed, error: %1").arg(lastError)};
        qCritical(qPrintable(logMsg));
    }
}

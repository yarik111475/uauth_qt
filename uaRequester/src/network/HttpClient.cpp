#include "HttpClient.h"

#include <QEventLoop>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QNetworkAccessManager>

void HttpClient::run()
{
    QObject::connect(this,&HttpClient::sendReqSignal,this,&HttpClient::sendReqSlot);
    QThread::exec();
}

void HttpClient::sendReqSlot(const QUrl &reqUrl, HttpVerb reqVerb, const QByteArray reqBody, const QString &reqHeader)
{
    QNetworkRequest request {};
    request.setUrl(reqUrl);
    request.setRawHeader("X-Client-Cert-Dn",reqHeader.toUtf8());
    QEventLoop eventLoop {};
    QNetworkAccessManager accessManager {};
    QObject::connect(&accessManager,&QNetworkAccessManager::finished,[&](QNetworkReply* replyPtr){
        eventLoop.quit();
    });
    QNetworkReply* replyPtr {nullptr};
    switch(reqVerb){
    case HttpVerb::GET:
        replyPtr=accessManager.get(request);
        break;
    case HttpVerb::PUT:
        replyPtr=accessManager.put(request,reqBody);
        break;
    case HttpVerb::POST:
        replyPtr=accessManager.post(request,reqBody);
        break;
    case HttpVerb::DELETE:
        replyPtr=accessManager.sendCustomRequest(request,"DELETE",reqBody);
        break;
    case HttpVerb::NONE:
        return;
    }
    eventLoop.exec();
    if(replyPtr->error()==QNetworkReply::NoError){
        const QByteArray respBody {replyPtr->readAll()};
        Q_EMIT finishedSignal(true,respBody);
        return;
    }
    Q_EMIT finishedSignal(false,replyPtr->errorString().toUtf8());
}

HttpClient::HttpClient(QObject *parent) : QThread(parent)
{
}

HttpClient::~HttpClient()
{
    QThread::quit();
    QThread::wait();
}

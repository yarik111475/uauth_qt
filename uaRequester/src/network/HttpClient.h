#ifndef HTTPCLIENT_H
#define HTTPCLIENT_H

#include <QUrl>
#include <QThread>
#include <QByteArray>
#include "Defines.h"

class HttpClient : public QThread
{
    Q_OBJECT
protected:
    virtual void run()override;
private Q_SLOTS:
    void sendReqSlot(const QUrl& reqUrl, HttpVerb reqVerb, const QByteArray reqBody, const QString& reqHeader);
public:
    explicit HttpClient(QObject *parent = nullptr);
    virtual ~HttpClient();
Q_SIGNALS:
    void sendReqSignal(const QUrl& reqUrl,HttpVerb reqVerb,const QByteArray reqBody,const QString& reqHeader);
    void finishedSignal(bool isSuccess,const QByteArray& respBody);
};

#endif // HTTPCLIENT_H

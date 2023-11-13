#ifndef HTTPCLIENT_H
#define HTTPCLIENT_H

#include <QMap>
#include <QThread>
#include <QSharedPointer>
#include <QSslConfiguration>

#include "HttpRouter.h"
#include "HttpRequest.h"
#include "HttpResponse.h"

class HttpResponse;
class SQL_Handler;
class QSettings;
class QAbstractSocket;

class HttpClient : public QThread
{
    Q_OBJECT
private:
    HttpRouter router_;
    QAbstractSocket* socketPtr_ {nullptr};
    qintptr socketDescriptor_;
    bool sslEnable_ {false};
    QSslConfiguration sslConfiguration_;
    bool isIntegrityOk_ {false};
    QSharedPointer<QSettings> appSettingsPtr_  {nullptr};
    QSharedPointer<SQL_Handler> sqlHandlerPtr_ {nullptr};

    void addUserRules(const HttpRequest &request, QAbstractSocket *socket);
    void addRolePermRules(const HttpRequest &request, QAbstractSocket *socket);
    void addParentChildRules(const HttpRequest &request, QAbstractSocket *socket);
    void addUserRolePermRules(const HttpRequest &request, QAbstractSocket *socket);
    void addAuthzRules(const HttpRequest &request, QAbstractSocket *socket);
    void addAuthzManageRules(const HttpRequest &request, QAbstractSocket *socket);
    void addCertificateRules(const HttpRequest &request, QAbstractSocket *socket);

    void logRequest(const HttpRequest& request);
    void logResponse(const HttpResponse& response);

    QString methodToText(HttpRequest::Method method);
    QString getRequesterId(const HttpRequest& request);
    QMap<QString,QString> getQueryMap(const HttpRequest& request);

protected:
    virtual void run()override;

public:
    explicit HttpClient(qintptr socketDescriptor,bool isIntegrityOk,QSharedPointer<QSettings> appSettingsPtr,QObject* parent=nullptr);
    ~HttpClient();
    void sslSetup(const QSslConfiguration& sslConfiguration);

    void handleReadyRead(QAbstractSocket* socket,HttpRequest* request);
    bool handleRequest(const HttpRequest &request, QAbstractSocket *socket);
    void sendResponse(const HttpResponse &response, const HttpRequest &request, QAbstractSocket *socket);
};

#endif // HTTPCLIENT_H

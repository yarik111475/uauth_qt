#ifndef HTTPSERVER_H
#define HTTPSERVER_H

#include <QTcpServer>
#include <QSharedPointer>

class QSettings;
class HttpServer : public QTcpServer
{
    Q_OBJECT
private:
    bool isIntegrityOk_ {false};
    QSharedPointer<QSettings> appSettingsPtr_ {nullptr};
protected:
    virtual void incomingConnection(qintptr socketDescriptor)override;
public:
    explicit HttpServer(QSharedPointer<QSettings> appSettingsPtr,QObject* parent=nullptr);
    ~HttpServer()=default;
public Q_SLOTS:
    void integritySlot(bool isIntegrityOk,const QString& lastError);
};

#endif // HTTPSERVER_H

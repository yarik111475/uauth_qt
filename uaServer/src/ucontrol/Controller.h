#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <QThread>
#include <QSharedPointer>
#include <QSslConfiguration>

class QSettings;
class QSslConfiguration;

class Controller : public QThread
{
    Q_OBJECT
private:
    qint32 timeOut_ {1000};
    QSharedPointer<QSettings> appSettingsPtr_  {nullptr};
    QSslConfiguration sslConfiguration_ {};
    QSslConfiguration makeSslConfiguration(QString& lastError);

private Q_SLOTS:
    void timeoutSlot();

protected:
    void run()override;

public:
    explicit Controller(QSharedPointer<QSettings> appSettingsPtr,QObject *parent = nullptr);
    ~Controller();

Q_SIGNALS:
    void integritySignal(bool isIntegrityOk,const QString& lastError);
};

#endif // CONTROLLER_H

#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include <QString>
#include <QObject>
#include <QSharedPointer>

class QSettings;
class HttpServer;
class Controller;
class Bootloader:public QObject
{
    Q_OBJECT
private:
    QSharedPointer<QSettings> appSettingsPtr_   {nullptr};
    QSharedPointer<HttpServer> httpServerPtr_   {nullptr};
    QSharedPointer<Controller> controllerPtr_   {nullptr};

public:
    explicit Bootloader(QSharedPointer<QSettings> appSettingsPtr,QObject* parent=nullptr);
    ~Bootloader()=default;
    void run();

Q_SIGNALS:
    void finishedSignal(bool isSuccess, const QString& lastError);
};

#endif // BOOTLOADER_H

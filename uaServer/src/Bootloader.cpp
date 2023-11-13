#include "Bootloader.h"
#include "http/HttpServer.h"
#include "ucontrol/Controller.h"
#include <QSettings>

Bootloader::Bootloader(QSharedPointer<QSettings> appSettingsPtr, QObject *parent)
    :QObject{parent},appSettingsPtr_{appSettingsPtr}
{
}

void Bootloader::run()
{
    httpServerPtr_.reset(new HttpServer{appSettingsPtr_});
    controllerPtr_.reset(new Controller(appSettingsPtr_));
    QObject::connect(controllerPtr_.get(),&Controller::integritySignal,
                     httpServerPtr_.get(),&HttpServer::integritySlot);
    const QString serverAddress  {appSettingsPtr_->value("UA_HOST").toString()};
    const qint32 serverPort {appSettingsPtr_->value("UA_PORT").toInt()};
    const bool isListenOk {httpServerPtr_->listen(QHostAddress(serverAddress),serverPort)};
    if(!isListenOk){
        Q_EMIT finishedSignal(false, httpServerPtr_->errorString());
        return;
    }
    qInfo("HttpServer started at: %s:%d",qPrintable(httpServerPtr_->serverAddress().toString()),httpServerPtr_->serverPort());
    controllerPtr_->start();
}


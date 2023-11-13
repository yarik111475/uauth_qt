#include "Controller.h"
#include "Defines.h"

#include <QUrl>
#include <QFile>
#include <QTimer>
#include <QSslKey>
#include <QPointer>
#include <QSslError>
#include <QSettings>
#include <QHostInfo>
#include <QEventLoop>
#include <QJsonDocument>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QNetworkAccessManager>
#include <QJsonObject>
#include <QJsonDocument>

QSslConfiguration Controller::makeSslConfiguration(QString &lastError)
{
    QSslConfiguration sslConfiguration {};
    sslConfiguration.setProtocol(QSsl::AnyProtocol);
    sslConfiguration.setPeerVerifyMode(QSslSocket::VerifyNone);

    const QString caCertPath   {appSettingsPtr_->value("UA_CA_CRT_PATH").toString()};
    const QString clientCertPath {appSettingsPtr_->value("UA_CLIENT_CRT_PATH").toString()};
    const QString clientPrivateKeyPath {appSettingsPtr_->value("UA_CLIENT_KEY_PATH").toString()};
    const QString clientPrivateKeyPass {appSettingsPtr_->value("UA_CLIENT_KEY_PASS").toString()};
    {
        if(!QFile::exists(caCertPath)){
            lastError=QStringLiteral("caCert file not exists,path: %1").arg(caCertPath);
            return QSslConfiguration{};
        }
        QFile caCertFile {caCertPath};
        if(!caCertFile.open(QIODevice::ReadOnly)){
            lastError=QStringLiteral("Fail to open caCert file!");
            return QSslConfiguration {};
        }
        QList<QSslCertificate> caRootCertList {QSslCertificate::fromDevice(&caCertFile)};
        sslConfiguration.setCaCertificates(caRootCertList);
    }
    {
        if(!QFile::exists(clientCertPath)){
            lastError=QStringLiteral("clientCert file not exists,path: %1").arg(clientCertPath);
            return QSslConfiguration {};
        }
        QFile clientCertFile {clientCertPath};
        if(!clientCertFile.open(QIODevice::ReadOnly)){
            lastError=QStringLiteral("Fail to open clientCert file!");
            return QSslConfiguration {};
        }
        QList<QSslCertificate> clientCertList {QSslCertificate::fromDevice(&clientCertFile)};
        sslConfiguration.setLocalCertificateChain(clientCertList);
    }
    {
        if(!QFile::exists(clientPrivateKeyPath)){
            lastError=QStringLiteral("clientPrivateKey file not exists,path: %1").arg(clientPrivateKeyPath);
            return QSslConfiguration{};
        }
        QFile clientPrivateKeyFile {clientPrivateKeyPath};
        if(!clientPrivateKeyFile.open(QIODevice::ReadOnly)){
            lastError=QStringLiteral("Fail to open clientPrivateKey file!");
            return QSslConfiguration {};
        }
        QSslKey clientPrivateKey {&clientPrivateKeyFile,QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey,clientPrivateKeyPass.toUtf8()};
        sslConfiguration.setPrivateKey(clientPrivateKey);
    }
    return sslConfiguration;
}

void Controller::timeoutSlot()
{
    {
        const QString uaUcHost {appSettingsPtr_->value("UA_UC_HOST").toString()};
        const qint32 uaUcPort {appSettingsPtr_->value("UA_UC_PORT").toInt()};
        QUrl url {};
        url.setScheme("https");
        url.setHost(uaUcHost);
        url.setPort(uaUcPort);
        url.setPath("/integrity");

        QNetworkRequest request {};
        request.setUrl(url);
        request.setSslConfiguration(sslConfiguration_);

        QEventLoop eventLoop {};
        QNetworkAccessManager accessManager {};
        QObject::connect(&accessManager,&QNetworkAccessManager::sslErrors,[](QNetworkReply *replyPtr, const QList<QSslError> &errors){
            replyPtr->ignoreSslErrors();
        });
        QObject::connect(&accessManager,&QNetworkAccessManager::finished,[&](){
            eventLoop.quit();
        });
        QNetworkReply* replyPtrr {accessManager .get(request)};
        eventLoop.exec();

        if(replyPtrr->error()!=QNetworkReply::NoError){
            const QString lastError {replyPtrr->errorString()};
            Q_EMIT integritySignal(false,lastError);
        }
        else{
            const QByteArray data {replyPtrr->readAll()};
            QJsonDocument jsonDoc {QJsonDocument::fromJson(data)};
            const bool isIntegrityOk {jsonDoc.object().value("integrity").toBool()};
            Q_EMIT integritySignal(isIntegrityOk,QString{});
        }
    }
    QTimer::singleShot(timeOut_,this,&Controller::timeoutSlot);
}

void Controller::run()
{
    QString lastError {};
    sslConfiguration_=makeSslConfiguration(lastError);
    if(sslConfiguration_.isNull()){
        qCritical(qPrintable(lastError));
        Q_EMIT integritySignal(false,lastError);
        QThread::quit();
        return;
    }
    timeoutSlot();
    QThread::exec();
}

Controller::Controller(QSharedPointer<QSettings> appSettingsPtr, QObject *parent)
    : QThread{parent},appSettingsPtr_{appSettingsPtr}
{
}

Controller::~Controller()
{
    QThread::quit();
    QThread::wait();
}

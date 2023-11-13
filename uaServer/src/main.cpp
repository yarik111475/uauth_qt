#include <QDir>
#include <QtCore>
#include <QPointer>
#include <QtGlobal>
#include <QSettings>
#include <QSharedPointer>
#include <QCommandLineParser>
#include <iostream>
#include <memory>
#include <vector>
#include "../Version.h"
#include "Bootloader.h"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include <spdlog/sinks/rotating_file_sink.h>

std::shared_ptr<spdlog::logger> loggerPtr_ {nullptr};

bool initLogger(QString& lastError)
{
    const QString appDir {QCoreApplication::applicationDirPath()};
    const QString varLogUaServerDir {QString("%1/../.var/log/uauth").arg(appDir)};
    const bool isLogDirOk {QDir{}.mkpath(varLogUaServerDir)};
    if(!isLogDirOk){
        lastError="Fail to create log directory!";
        return false;
    }
    const int logFilescount {5};
    const int logFilesize {1024 * 1024 * 50};
    const QString logName {"Uauth"};
    const QString logfilenamePath {varLogUaServerDir + "/uauth.log"};
    const spdlog::level::level_enum logLevel {spdlog::level::debug};
    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
#ifdef Q_OS_WINDOWS
    sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logfilenamePath.toStdWString(), logFilesize, logFilescount));
#endif
#ifdef Q_OS_LINUX
    sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logfilenamePath.toStdString(), logFilesize, logFilescount));
#endif
    loggerPtr_.reset(new spdlog::logger(logName.toStdString(), sinks.begin(),sinks.end()));
    spdlog::register_logger(loggerPtr_);
    loggerPtr_->set_level(logLevel);
    loggerPtr_->flush_on(logLevel);
    return true;
}

void qMessageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    const qint32 logLine {context.line};
    const char *logFile {context.file ? context.file : ""};
    const char *logFunction {context.function ? context.function : ""};
    switch(type){
    case QtMsgType::QtDebugMsg:
        if(loggerPtr_){
            loggerPtr_->debug("{}; {}",logFunction,msg.toStdString());
        }
        break;
    case QtMsgType::QtInfoMsg:
        if(loggerPtr_){
            loggerPtr_->info("{}; {}",logFunction,msg.toStdString());
        }
        break;
    case QtMsgType::QtWarningMsg:
        if(loggerPtr_){
            loggerPtr_->warn("{}; {}",logFunction,msg.toStdString());
        }
        break;
    case QtMsgType::QtCriticalMsg:
        if(loggerPtr_){
            loggerPtr_->error("{}; {}",logFunction,msg.toStdString());
        }
        break;
    case QtMsgType::QtFatalMsg:
        if(loggerPtr_){
            loggerPtr_->error("File: {}; Line: {}; Function: {}; Message: {}",logFile,logLine,logFunction,msg.toStdString());
        }
        break;
    }
}

#ifdef Q_OS_WINDOWS
void setEnvironments()
{
    //uauth server params
    _putenv("UA_HOST=127.0.0.1");
    _putenv("UA_PORT=8030");

    //ucontrol client params
    _putenv("UA_UC_HOST=127.0.0.1");
    _putenv("UA_UC_PORT=5678");

    //database params
    _putenv("UA_DB_NAME=");
    _putenv("UA_DB_HOST=");
    _putenv("UA_DB_PORT=");
    _putenv("UA_DB_USER=u-");
    _putenv("UA_DB_PASS=-");

    //_putenv("UA_DB_POOL_SIZE_MIN=1");
    //_putenv("UA_DB_POOL_SIZE_MAX=100");
    //_putenv("UA_LOG_LEVEL=0");

    //_putenv("UA_ORIGINS=[http://127.0.0.1:8030]");
    //_putenv("UA_SSL_WEB_CRT_VALID=365");

    //uauth certificates part
    _putenv("UA_CA_CRT_PATH=C:/uauth/root-ca.pem");
    _putenv("UA_SIGNING_CA_CRT_PATH=C:/uauth/signing-ca.pem");
    _putenv("UA_SIGNING_CA_KEY_PATH=C:/uauth/signing-ca-key.pem");
    _putenv("UA_SIGNING_CA_KEY_PASS=");

    //ucontrol certificates part
    _putenv("UA_CLIENT_CRT_PATH=C:/uauth/clientCert.pem");
    _putenv("UA_CLIENT_KEY_PATH=C:/uauth/clientPrivateKey.pem");
    _putenv("UA_CLIENT_KEY_PASS=password");
}
#endif
#ifdef Q_OS_LINUX
void setEnvironments()
{
    const QString userName {qgetenv("USER")};
    //uauth server
    setenv("UA_HOST","127.0.0.1",0);
    setenv("UA_PORT","8030",0);

    //ucontrol client
    setenv("UA_UC_HOST","127.0.0.1",0);
    setenv("UA_UC_PORT","5678",0);

    //database
    setenv("UA_DB_NAME","",0);
    setenv("UA_DB_HOST","",0);
    setenv("UA_DB_PORT","",0);
    setenv("UA_DB_USER","",0);
    setenv("UA_DB_PASS","",0);

    //setenv("UA_DB_POOL_SIZE_MIN","1",0);
    //setenv("UA_DB_POOL_SIZE_MAX","100",0);
    //setenv("UA_LOG_LEVEL","0",0);

    //setenv("UA_ORIGINS","[http://127.0.0.1:8030]",0);
    //setenv("UA_SSL_WEB_CRT_VALID","365",0);

    //uauth certificates
    setenv("UA_CA_CRT_PATH",QString("/home/%1/uauth/root-ca.pem").arg(userName).toLatin1(),0);
    setenv("UA_SIGNING_CA_CRT_PATH",QString("/home/%1/uauth/signing-ca.pem").arg(userName).toLatin1(),0);
    setenv("UA_SIGNING_CA_KEY_PATH",QString("/home/%1/uauth/signing-ca-key.pem").toLatin1(),0);
    setenv("UA_SIGNING_CA_KEY_PASS","",0);

    //ucontrol certificates
    setenv("UA_CLIENT_CRT_PATH",QString("/home/%1/uauth/clientCert.pem").arg(userName).toLatin1(),0);
    setenv("UA_CLIENT_KEY_PATH",QString("/home/%1/uauth/clientPrivateKey.pem").arg(userName).toLatin1(),0);
    setenv("UA_CLIENT_KEY_PASS","",0);
}
#endif

int main(int argc, char *argv[])
{
    setEnvironments();
    QCoreApplication app(argc, argv);
    const QString appVersion {APP_VERSION};
    app.setApplicationVersion(appVersion);
    QCommandLineParser parser;
    parser.addVersionOption();
    parser.process(app);

    QSharedPointer<QSettings> appSettingsPtr {new QSettings("Uauth","uaServer")};
    const QStringList& envList {"UA_HOST","UA_PORT","UA_UC_HOST","UA_UC_PORT",
                                "UA_DB_NAME","UA_DB_HOST","UA_DB_PORT","UA_DB_USER","UA_DB_PASS",
                                "UA_CA_CRT_PATH","UA_SIGNING_CA_CRT_PATH","UA_SIGNING_CA_KEY_PATH","UA_SIGNING_CA_KEY_PASS",
                                "UA_CLIENT_CRT_PATH","UA_CLIENT_KEY_PATH","UA_CLIENT_KEY_PASS"};
    for(const QString& envKey: envList){
        if(!qEnvironmentVariableIsSet(envKey.toLatin1().data())){
            const QString lastError {QString("Environment: '%1' is not set!").arg(envKey)};
            std::cerr<<lastError.toStdString()<<std::endl;
            return 1;
        }
        const QString envValue {qgetenv(envKey.toLatin1().constData())};
        appSettingsPtr->setValue(envKey,envValue);
    }

    QString lastError {};
    const bool isLoggerOk {initLogger(lastError)};
    if(isLoggerOk){
        qInstallMessageHandler(qMessageHandler);
    }
    else{
        std::cerr<<"Fail to init logger, error: "<<lastError.toStdString()<<std::endl;
        return 1;
    }

    Bootloader bootloader {appSettingsPtr};
    QObject::connect(&bootloader,&Bootloader::finishedSignal,[&](bool isSuccess,const QString& lastError){
        if(!isSuccess){
            std::cerr<<lastError.toStdString()<<std::endl;
            std::exit(1);
        }
        std::exit(0);
    });
    bootloader.run();
    return app.exec();
}


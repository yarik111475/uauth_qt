#include <QtCore>
#include <QString>
#include <QtGlobal>
#include <QHostInfo>
#include <QDateTime>
#include <QJsonObject>
#include <QSharedPointer>
#include <QCommandLineParser>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QSqlDatabase>
#include <iostream>
#include "../Version.h"

QString timeWithTimezone()
{
    QDateTime currentDateTime {QDateTime::currentDateTime()};
    QDateTime utcDateTime {currentDateTime.toUTC()};
    utcDateTime.setTimeSpec(Qt::LocalTime);
    const qint64& utcOffset {utcDateTime.secsTo(currentDateTime)};
    currentDateTime.setOffsetFromUtc(utcOffset);
    return currentDateTime.toString(Qt::ISODateWithMs);
}

bool initParams(QJsonObject& paramsObject,QString& lastError)
{
    const QString UA_DB_NAME {!qEnvironmentVariableIsSet("UA_DB_NAME") ? "" : qgetenv("UA_DB_NAME")};
    const QString UA_DB_HOST {!qEnvironmentVariableIsSet("UA_DB_HOST") ? "" : qgetenv("UA_DB_HOST")};
    const QString UA_DB_PORT {!qEnvironmentVariableIsSet("UA_DB_PORT") ? "" : qgetenv("UA_DB_PORT")};
    const QString UA_DB_USER {!qEnvironmentVariableIsSet("UA_DB_USER") ? "" : qgetenv("UA_DB_USER")};
    const QString UA_DB_PASS {!qEnvironmentVariableIsSet("UA_DB_PASS") ? "" : qgetenv("UA_DB_PASS")};

    paramsObject.insert("UA_DB_NAME",UA_DB_NAME);
    paramsObject.insert("UA_DB_HOST",UA_DB_HOST);
    paramsObject.insert("UA_DB_PORT",UA_DB_PORT);
    paramsObject.insert("UA_DB_USER",UA_DB_USER);
    paramsObject.insert("UA_DB_PASS",UA_DB_PASS);

    auto it {paramsObject.begin()};
    while(it!=paramsObject.end()){
        if(it.value().isString()){
            const QString value {it.value().toString()};
            if(value.isEmpty()){
                lastError=QStringLiteral("Param '%1' is empty!").arg(it.key());
                return false;
            }
        }
        ++it;
    }
    return true;
}

bool initDatabase(QSqlDatabase& dataBase,const QJsonObject& paramsObject)
{
    dataBase.setPort(paramsObject.value("UA_DB_PORT").toString().toInt());
    dataBase.setHostName(paramsObject.value("UA_DB_HOST").toString());
    dataBase.setDatabaseName(paramsObject.value("UA_DB_NAME").toString());
    const bool isDataBaseOk {dataBase.open(paramsObject.value("UA_DB_USER").toString(),
                                           paramsObject.value("UA_DB_PASS").toString())};
    return isDataBaseOk;
}

bool postUserObject(QSqlDatabase& dataBase,const QJsonObject& inUserObject,QJsonObject& outUserObject,QString& lastError)
{
    {//check
        const QStringList neededKeys {"id","email","location_id","ou_id"};
        for(const QString& key: neededKeys){
            if(!inUserObject.contains(key)){
                lastError=QStringLiteral("Not valid user, key: '%1' not present!").arg(key);
                return false;
            }
        }
    }
    {//create
        const bool isBlocked {false};
        const QString createdAt {timeWithTimezone()};
        const QString updatedAt {timeWithTimezone()};
        const QString queryText {"INSERT INTO users (id,email,created_at,updated_at,is_blocked,location_id,ou_id)"
                                 " VALUES(:id,:email,:createdAt,:updatedAt,:isBlocked,:location_id,:ou_id)"};
        QSqlQuery sqlQuery {dataBase};
        if(!sqlQuery.prepare(queryText)){
            lastError=sqlQuery.lastError().text();
            return false;
        }
        sqlQuery.bindValue(":isBlocked",isBlocked);
        sqlQuery.bindValue(":createdAt",createdAt);
        sqlQuery.bindValue(":updatedAt",updatedAt);

        const QStringList& jsonKeys {inUserObject.keys()};
        std::for_each(jsonKeys.begin(),jsonKeys.end(),[&](const QString& key){
            if(key=="is_blocked"){
                sqlQuery.bindValue(QString(":%1").arg(key),inUserObject.value(key).toBool());
            }
            else{
                sqlQuery.bindValue(QString(":%1").arg(key),inUserObject.value(key).toString());
            }
        });

        if(!sqlQuery.exec()){
            lastError=sqlQuery.lastError().text();
            return false;
        }
    }
    {//get created back
        const QString userId {inUserObject.value("id").toString()};
        const QString queryText {"SELECT * FROM users WHERE id=:userId"};
        QSqlQuery sqlQuery {dataBase};
        if(!sqlQuery.prepare(queryText)){
            lastError=sqlQuery.lastError().text();
            return false;
        }
        sqlQuery.bindValue(":userId",userId);

        if(sqlQuery.exec()){
            sqlQuery.next();
            QSqlRecord sqlRecord {sqlQuery.record()};
            const int fieldCount {sqlRecord.count()};

            for(int i=0;i<fieldCount;++i){
                const QString fieldName {sqlRecord.fieldName(i)};
                const QVariant fieldValue {sqlRecord.value(i)};
                if(fieldValue.isNull()){
                    outUserObject.insert(fieldName,QJsonValue::Null);
                }
                else{
                    outUserObject.insert(fieldName,fieldValue.toString());
                }
            }
            return true;
        }
        else{
            lastError=sqlQuery.lastError().text();
            return false;
        }
    }
    return false;
}

bool postUserRolePerm(QSqlDatabase& dataBase,const QString& userId,QString& lastError)
{
    QString rolePermId {};
    {//get UAuthAdmin rollePermId
        const QString adminName {"UAuthAdmin"};
        const QString queryText {"SELECT id FROM roles_permissions WHERE name=:adminName"};
        QSqlQuery sqlQuery {dataBase};
        if(!sqlQuery.prepare(queryText)){
            lastError=sqlQuery.lastError().text();
            return false;
        }
        sqlQuery.bindValue(":adminName",adminName);

        if(!sqlQuery.exec()){
            lastError=sqlQuery.lastError().text();
            return false;
        }
        sqlQuery.next();
        rolePermId=sqlQuery.value("id").toString();
    }
    const QString createdAt {timeWithTimezone()};
    const QString queryText {"INSERT INTO users_roles_permissions (created_at,user_id,role_permission_id) VALUES(:createdAt,:userId,:rolePermId)"};
    QSqlQuery sqlQuery {dataBase};
    if(!sqlQuery.prepare(queryText)){
        lastError=sqlQuery.lastError().text();
        return false;
    }
    sqlQuery.bindValue(":createdAt",createdAt);
    sqlQuery.bindValue(":userId",userId);
    sqlQuery.bindValue(":rolePermId",rolePermId);

    if(!sqlQuery.exec()){
        lastError=sqlQuery.lastError().text();
        return false;
    }
    return true;
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    const QString appVersion {APP_VERSION};
    app.setApplicationVersion(appVersion);

    QCommandLineParser parser {};
    parser.addVersionOption();
    parser.addHelpOption();
    parser.addOptions({
        {"id","User id","string"},
        {"email","User email address","string"},
        {"location_id","User location id","string"},
        {"ou_id","User orgunit id","string"}
    });
    if(!parser.parse(app.arguments())){
        std::cerr<<parser.errorText().toStdString()<<std::endl;
        return 1;
    }
    parser.process(app);
    QJsonObject inUserObject {};
    const QStringList& optionNames {"id","email","location_id","ou_id",};

    for(const QString& optionName: optionNames){
        if(!parser.isSet(optionName)){
            const QString lastError {QStringLiteral("Param '%1' is not set!").arg(optionName)};
            std::cerr<<lastError.toStdString()<<std::endl;
            return 1;
        }
        if(parser.value(optionName).isEmpty()){
            const QString lastError {QStringLiteral("Param '%1' is not defined!").arg(optionName)};
            std::cerr<<lastError.toStdString()<<std::endl;
            return 1;
        }
        inUserObject.insert(optionName,parser.value(optionName));
    }

    QString lastError {};
    QJsonObject paramsObject {};
    if(!initParams(paramsObject,lastError)){
        std::cerr<<lastError.toStdString()<<std::endl;
        return 1;
    }

    const QString driverName {"QPSQL"};
    const QString connectionName {"POSTGRES"};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase,paramsObject)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        QJsonObject outUserObject {};
        if(!postUserObject(dataBase,inUserObject,outUserObject,lastError)){
            goto end;
        }
        const QString userId {outUserObject.value("id").toString()};
        if(!postUserRolePerm(dataBase,userId,lastError)){
            goto end;
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    if(!lastError.isNull()){
        std::cerr<<lastError.toStdString()<<std::endl;
        return 1;
    }
    std::cout<<"All operations completed success"<<std::endl;
    return 0;
}


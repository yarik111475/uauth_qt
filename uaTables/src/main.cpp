#include <QtCore>
#include <QString>
#include <QtGlobal>
#include <QHostInfo>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonObject>
#include <QSharedPointer>
#include <QCommandLineParser>
#include <iostream>
#include "libpq-fe.h"
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

QSharedPointer<PGconn> makeConn(const QJsonObject& paramsObject,QString& lastError)
{
    const QString UA_DB_NAME {paramsObject.value("UA_DB_NAME").toString()};
    const QString UA_DB_HOST {paramsObject.value("UA_DB_HOST").toString()};
    const QString UA_DB_PORT {paramsObject.value("UA_DB_PORT").toString()};
    const QString UA_DB_USER {paramsObject.value("UA_DB_USER").toString()};
    const QString UA_DB_PASS {paramsObject.value("UA_DB_PASS").toString()};

    const QString connInfo {QString("postgresql://%1:%2@%3:%4/%5?connect_timeout=10").
                            arg(UA_DB_USER).arg(UA_DB_PASS).arg(UA_DB_HOST).
                            arg(UA_DB_PORT).arg(UA_DB_NAME)};
    QSharedPointer<PGconn> connPtr {PQconnectdb(connInfo.toLatin1().data()),&PQfinish};
    if(PQstatus(connPtr.get())!=CONNECTION_OK){
        lastError=QString {PQerrorMessage(connPtr.get())};
        return nullptr;
    }
    return connPtr;
}

bool initDbParams(QJsonObject& paramsObject,QString& lastError)
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

bool initRolesPermissions(QSharedPointer<PGconn> connPtr,QString& lastError)
{
    const QJsonArray rolePermissionObjects {
        QJsonObject {
            {"id","699bf280-70eb-552d-aae6-01341e2b8f33"},//2
            {"name","authorization_manage:update"},
            {"type","permission"},
            {"description","Assign role or permission to user"}
        },
        QJsonObject {
            {"id","d3722305-0489-51c1-8036-357ed6099c30"},//3
            {"name","role_permission:read"},
            {"type","permission"},
            {"description","List of roles and permissions; Get permission or role; Get permission or role with users;"}
        },
        QJsonObject {
            {"id","12892e88-9fbf-5915-b9b1-410b2bb1b42c"},//4
            {"name","role_permission:create"},
            {"type","permission"},
            {"description","Create permission or role"}
        },
        QJsonObject {
            {"id","e477530a-768d-5e87-bd79-a6c138edfef9"},//5
            {"name","role_permission:update"},
            {"type","permission"},
            {"description","Update permission or role"}
        },
        QJsonObject {
            {"id","005ece55-2703-5e10-9c20-561b87313b08"},//6
            {"name","role_permission:delete"},
            {"type","permission"},
            {"description","Delete permission or role"}
        },
        QJsonObject {
            {"id","4cabf4b7-c371-524b-8f32-7b0ac43a18e1"},//7
            {"name","user:read"},
            {"type","permission"},
            {"description","List of users; Get user info; Get user with role and permissions;"}
        },
        QJsonObject {
            {"id","5780bd9d-f6d9-5d14-b3fa-ffebc618f856"},//8
            {"name","user:create"},
            {"type","permission"},
            {"description","Create user"}
        },
        QJsonObject {
            {"id","a131af2b-0b1c-5a77-9589-0a0118c6b03b"},//9
            {"name","user:update"},
            {"type","permission"},
            {"description","Update user"}
        },
        QJsonObject {
            {"id","072a6653-025f-52b0-8653-f9528b9f2fee"},//10
            {"name","user:delete"},
            {"type","permission"},
            {"description","Delete user"}
        },
        QJsonObject {
            {"id","deb145a5-044f-5aed-befd-fc1f0a297aa0"},//11
            {"name","agent_certificate:create"},
            {"type","permission"},
            {"description","Sign agent certificate"}
        },
        QJsonObject {
            {"id","0c9e9550-6131-5a7d-a4fa-1fab41987ea5"},//12
            {"name","user_certificate:create"},
            {"type","permission"},
            {"description","Create user certificate"}
        },
        QJsonObject {
            {"id","a52851ae-b6d6-5df5-8534-8fb10d7a4eaa"},//13
            {"name","UAuthAdmin"},
            {"type","role"},
            {"description","Default Super User"}
        }
    };

    QSharedPointer<PGresult> resPtr {nullptr};
    for(const QJsonValue& jsonValue: rolePermissionObjects){
        const QJsonObject jsonObject {jsonValue.toObject()};
        const std::string id {jsonObject.value("id").toString().toStdString()};
        const std::string name {jsonObject.value("name").toString().toStdString()};
        const std::string type {jsonObject.value("type").toString().toStdString()};
        const std::string description {jsonObject.value("description").toString().toStdString()};

        const char* paramValues[] {id.c_str(),name.c_str(),type.c_str(),description.c_str()};
        const QString query {"INSERT INTO roles_permissions (id,name,type,description) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING"};
        resPtr.reset(PQexecParams(connPtr.get(),query.toStdString().c_str(),4,NULL,paramValues,NULL,NULL,0),&PQclear);
        if(PQresultStatus(resPtr.get())!=PGRES_COMMAND_OK){
            lastError=QString {PQresultErrorMessage(resPtr.get())};
            return false;
        }
    }
    return true;
}

bool initTables(QSharedPointer<PGconn> connPtr,QString& lastError)
{
    QSharedPointer<PGresult> resPtr {nullptr};
    {//drop type if exists 'rolepermissiontype'
        const QString query {"DROP TYPE IF EXISTS rolepermissiontype"};
        resPtr.reset(PQexec(connPtr.get(),query.toStdString().c_str()),&PQclear);
        if(PQresultStatus(resPtr.get()) != PGRES_COMMAND_OK){
            lastError=QString {PQresultErrorMessage(resPtr.get())};
            //return false;
        }
    }
    {//create type 'rolepermissiontype'
        const QString query {"CREATE TYPE rolepermissiontype AS ENUM ('role','permission')"};
        resPtr.reset(PQexec(connPtr.get(),query.toStdString().c_str()),&PQclear);
        if(PQresultStatus(resPtr.get()) != PGRES_COMMAND_OK){
            lastError=QString {PQresultErrorMessage(resPtr.get())};
            //return false;
        }
    }
    {//drop type if exists 'gender'
        const QString query {"DROP TYPE IF EXISTS gender"};
        resPtr.reset(PQexec(connPtr.get(),query.toStdString().c_str()),&PQclear);
        if(PQresultStatus(resPtr.get()) != PGRES_COMMAND_OK){
            lastError=QString {PQresultErrorMessage(resPtr.get())};
            //return false;
        }
    }
    {//create type 'gender'
        const QString query {"CREATE TYPE gender AS ENUM ('male','female')"};
        resPtr.reset(PQexec(connPtr.get(),query.toStdString().c_str()),&PQclear);
        if(PQresultStatus(resPtr.get()) != PGRES_COMMAND_OK){
            lastError=QString {PQresultErrorMessage(resPtr.get())};
            //return false;
        }
    }
    {//create table 'users'
        const QString query {"CREATE TABLE IF NOT EXISTS users "
                             "(id uuid PRIMARY KEY NOT NULL, created_at timestamptz NOT NULL, "
                             "updated_at timestamptz NOT NULL, first_name varchar(20) NULL, "
                             "last_name varchar(20) NULL, email varchar(60) NULL UNIQUE, is_blocked boolean NOT NULL, "
                             "phone_number varchar NULL, position varchar NULL, "
                             "gender gender NULL, location_id uuid NOT NULL, "
                             "ou_id uuid NOT NULL)"};
        resPtr.reset(PQexec(connPtr.get(),query.toStdString().c_str()),&PQclear);
        if(PQresultStatus(resPtr.get()) != PGRES_COMMAND_OK){
            lastError=QString {PQresultErrorMessage(resPtr.get())};
            return false;
        }
    }
    {//create table 'roles_permissions'
        const QString query {"CREATE TABLE IF NOT EXISTS roles_permissions "
                             "(id uuid PRIMARY KEY NOT NULL, name varchar(50) UNIQUE NOT NULL, "
                             "description varchar NULL, type rolepermissiontype NULL)"};
        resPtr.reset(PQexec(connPtr.get(),query.toStdString().c_str()),&PQclear);
        if(PQresultStatus(resPtr.get()) != PGRES_COMMAND_OK){
            lastError=QString {PQresultErrorMessage(resPtr.get())};
            return false;
        }

    }
    {//init default rps
        const bool isDefaultRolePermsOk {initRolesPermissions(connPtr,lastError)};
        if(!isDefaultRolePermsOk){
            return false;
        }
    }
    {//create table 'users_roles_permissions'
        const QString query {"CREATE TABLE IF NOT EXISTS users_roles_permissions "
                             "(created_at timestamptz NOT NULL, "
                             "user_id uuid NOT NULL references users, "
                             "role_permission_id uuid NOT NULL references roles_permissions, "
                             "primary key (user_id, role_permission_id))"};
        resPtr.reset(PQexec(connPtr.get(),query.toStdString().c_str()),&PQclear);
        if(PQresultStatus(resPtr.get()) != PGRES_COMMAND_OK){
            lastError=QString {PQresultErrorMessage(resPtr.get())};
            return false;
        }
    }
    {//create table 'roles_permissions_relationship'
        const QString query {"CREATE TABLE IF NOT EXISTS roles_permissions_relationship "
                             "(created_at timestamptz NOT NULL, "
                             "parent_id uuid NOT NULL references public.roles_permissions, "
                             "child_id uuid NOT NULL references public.roles_permissions, "
                             "primary key (parent_id, child_id))"};
        resPtr.reset(PQexec(connPtr.get(),query.toStdString().c_str()),&PQclear);
        if(PQresultStatus(resPtr.get()) != PGRES_COMMAND_OK){
            lastError=QString {PQresultErrorMessage(resPtr.get())};
            return false;
        }
    }
    return true;
}

int main(int argc, char *argv[])
{
    QCoreApplication app {argc,argv};
    const QString appVersion {APP_VERSION};
    app.setApplicationVersion(appVersion);
    QCommandLineParser parser;
    parser.addVersionOption();
    parser.process(app);

    QString lastError {};
    QJsonObject paramsObject {};
    const bool isDbParamsOk {initDbParams(paramsObject,lastError)};
    if(!isDbParamsOk){
        std::cerr<<lastError.toStdString()<<std::endl;
        return 1;
    }
    QSharedPointer<PGconn> connPtr {makeConn(paramsObject,lastError)};
    if(!connPtr){
        std::cerr<<lastError.toStdString()<<std::endl;
        return 1;
    }
    const bool isInitTablesOk {initTables(connPtr,lastError)};
    if(!isInitTablesOk){
        std::cerr<<lastError.toStdString()<<std::endl;
        return 1;
    }
    std::cerr<<"All tables init ok"<<std::endl;
    return 0;
}


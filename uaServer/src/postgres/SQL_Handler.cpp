#include "SQL_Handler.h"

#include <QUuid>
#include <QDebug>
#include <QDateTime>
#include <QSqlQuery>
#include <QSqlError>
#include <QSettings>
#include <QSqlDriver>
#include <QSqlRecord>
#include <QSqlDatabase>
#include <QSqlTableModel>
#include <QRegularExpression>
#include <algorithm>

QString SQL_Handler::timeWithTimezone()
{
    QDateTime currentDateTime {QDateTime::currentDateTime()};
    QDateTime utcDateTime {currentDateTime.toUTC()};
    utcDateTime.setTimeSpec(Qt::LocalTime);
    const qint64& utcOffset {utcDateTime.secsTo(currentDateTime)};
    currentDateTime.setOffsetFromUtc(utcOffset);
    return currentDateTime.toString(Qt::ISODateWithMs);
}

bool SQL_Handler::initDatabase(QSqlDatabase &dataBase)
{
    dataBase.setPort(appSettingsPtr_->value("UA_DB_PORT").toInt());
    dataBase.setHostName(appSettingsPtr_->value("UA_DB_HOST").toString());
    dataBase.setDatabaseName(appSettingsPtr_->value("UA_DB_NAME").toString());
    const bool isDataBaseOk {dataBase.open(appSettingsPtr_->value("UA_DB_USER").toString(),
                                           appSettingsPtr_->value("UA_DB_PASS").toString())};
    return isDataBaseOk;
}

void SQL_Handler::getRolePermIdsRecursive(const QSqlDatabase &dataBase, QStringList &rolePermIds)
{
    QStringList rolePermList {rolePermIds};
    QString queryText {"WITH RECURSIVE rp_list AS ("
                       "SELECT child_id, parent_id "
                       "FROM roles_permissions_relationship "
                       "WHERE parent_id IN (%1) "
                       "UNION "
                       "SELECT rpr.child_id, rpr.parent_id "
                       "FROM roles_permissions_relationship rpr "
                       "JOIN rp_list on rp_list.child_id = rpr.parent_id"
                       ") SELECT DISTINCT child_id FROM rp_list"};

    std::transform(rolePermList.begin(),rolePermList.end(),rolePermList.begin(),[](const QString& rolePermId){
        return QString("'%1'").arg(rolePermId);
    });

    QSqlQuery sqlQuery {dataBase};
    if(!sqlQuery.prepare(queryText.arg(rolePermList.join(", ")))){
        return;
    }
    if(!sqlQuery.exec()){
        return;
    }
    while(sqlQuery.next()){
        const QString rolePermId {sqlQuery.value(0).toString()};
        rolePermIds.push_back(rolePermId);
    }
}

bool SQL_Handler::checkUserById(const QSqlDatabase &dataBase, const QString &userId)
{
    const QString queryText {"SELECT COUNT(*) FROM users WHERE id=:userId"};
    QSqlQuery sqlQuery {dataBase};
    if(!sqlQuery.prepare(queryText)){
        return false;
    }
    sqlQuery.bindValue(":userId",userId);

    if(sqlQuery.exec()){
        if(sqlQuery.next()){
            const int rowCount {sqlQuery.value(0).toInt()};
            return (rowCount > 0);
        }
    }
    return false;
}

bool SQL_Handler::checkRolePermById(const QSqlDatabase &dataBase, const QString &rolePermId)
{
    const QString queryText {"SELECT COUNT(*) FROM roles_permissions WHERE id=:rolePermId"};
    QSqlQuery sqlQuery {dataBase};
    if(!sqlQuery.prepare(queryText)){
        return false;
    }
    sqlQuery.bindValue(":rolePermId",rolePermId);

    if(sqlQuery.exec()){
        if(sqlQuery.next()){
            const int rowCount {sqlQuery.value(0).toInt()};
            return (rowCount > 0);
        }
    }
    return false;
}

SQL_Status SQL_Handler::checkIsAuthorized(const QSqlDatabase &dataBase, const QString &userId, const QString &rolePermIdent, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::Unauthorized};
    QStringList userIdRolePermIdList {};
    {//check if uauthadmin
        const QString queryText {"SELECT name FROM roles_permissions WHERE id IN (SELECT role_permission_id FROM users_roles_permissions WHERE user_id=:userId)"};
        QSqlQuery sqlQuery {dataBase};
        if(!sqlQuery.prepare(queryText)){
            lastError=sqlQuery.lastError().text();
            goto end;
        }
        sqlQuery.bindValue(":userId",userId);

        if(!sqlQuery.exec()){
            lastError=sqlQuery.lastError().text();
            goto end;
        }
        while(sqlQuery.next()){
            const QString uauthAdminName {"UAuthAdmin"};
            const QString nameText {sqlQuery.value("name").toString()};
            if(uauthAdminName==nameText){
                sqlStatus=SQL_Status::Success;
                goto end;
            }
        }
    }
    {//get tot-level 'id' from users_roles_permissions
        const QString queryText {"SELECT role_permission_id FROM users_roles_permissions WHERE user_id=:userId"};
        QSqlQuery sqlQuery {dataBase};
        if(!sqlQuery.prepare(queryText)){
            lastError=sqlQuery.lastError().text();
            goto end;
        }
        sqlQuery.bindValue(":userId",userId);

        if(!sqlQuery.exec()){
            lastError=sqlQuery.lastError().text();
            goto end;
        }
        while(sqlQuery.next()){
            const QString rolePermId {sqlQuery.value(0).toString()};
            userIdRolePermIdList.push_back(rolePermId);
        }
        if(userIdRolePermIdList.isEmpty()){
            sqlStatus=SQL_Status::Unauthorized;
            goto end;
        }
        getRolePermIdsRecursive(dataBase,userIdRolePermIdList);
    }
    {
        const QRegularExpression re {"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"};
        const QRegularExpressionMatch match {re.match(rolePermIdent)};
        if(match.hasMatch()){
            const bool isContains {userIdRolePermIdList.contains(rolePermIdent)};
            sqlStatus=isContains ? SQL_Status::Success : SQL_Status::Unauthorized;
            goto end;
        }
        else{
            QStringList rolePermNameList {rolePermIdent.split(" ")};
            std::transform(rolePermNameList.begin(),rolePermNameList.end(),rolePermNameList.begin(),[](const QString& rolePermName){
                return QStringLiteral("'%1'").arg(rolePermName);
            });
            QStringList rolePermIdList {};
            QString queryText {QStringLiteral("SELECT id FROM roles_permissions WHERE name IN (%1)").arg(rolePermNameList.join(","))};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            if(sqlQuery.exec()){
                while(sqlQuery.next()){
                    const QString rolePermId {sqlQuery.value(0).toString()};
                    rolePermIdList.push_back(rolePermId);
                }
            }
            if(rolePermIdList.isEmpty()){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
            const bool isContains {std::all_of(rolePermIdList.begin(),rolePermIdList.end(),[&](const QString& rolePermId){
                return userIdRolePermIdList.contains(rolePermId);
            })};
            sqlStatus=isContains ? SQL_Status::Success : SQL_Status::Unauthorized;
            goto end;
        }
    }
end:
    return sqlStatus;
}

int SQL_Handler::getTotalUserRolePermsByUserId(const QSqlDatabase &dataBase, const QString &userId, QString &lastError)
{
    const QString queryText {"SELECT COUNT(*) FROM users_roles_permissions WHERE user_id=:userId"};
    QSqlQuery sqlQuery {dataBase};
    if(!sqlQuery.prepare(queryText)){
        lastError=sqlQuery.lastError().text();
        return -1;
    }
    sqlQuery.bindValue(":userId",userId);

    if(!sqlQuery.exec()){
        lastError=sqlQuery.lastError().text();
        return -1;
    }
    if(sqlQuery.next()){
        const int totalUserRolePerms {sqlQuery.value(0).toInt()};
        return totalUserRolePerms;
    }
    return 0;
}

int SQL_Handler::getTotalUserRolePermsByRolePermId(const QSqlDatabase &dataBase, const QString &rolePermId, QString &lastError)
{
    const QString queryText {"SELECT COUNT(*) FROM users_roles_permissions WHERE role_permission_id=:rolePermId"};
    QSqlQuery sqlQuery {dataBase};
    if(!sqlQuery.prepare(queryText)){
        lastError=sqlQuery.lastError().text();
        return -1;
    }
    sqlQuery.bindValue(":rolePermId",rolePermId);

    if(!sqlQuery.exec()){
        lastError=sqlQuery.lastError().text();
        return -1;
    }
    if(sqlQuery.next()){
        const int totalUserRolePerms {sqlQuery.value(0).toInt()};
        return totalUserRolePerms;
    }
    return 0;
}

QStringList SQL_Handler::getRolePermChildIds(const QSqlDatabase &dataBase, const QString &rolePermId, QString &lastError)
{
    const QString queryText {"SELECT child_id FROM roles_permissions_relationship WHERE parent_id=:rolePermId"};
    QSqlQuery sqlQuery {dataBase};
    if(!sqlQuery.prepare(queryText)){
        lastError=sqlQuery.lastError().text();
        return QStringList {};
    }
    sqlQuery.bindValue(":rolePermId",rolePermId);

    if(!sqlQuery.exec()){
        lastError=sqlQuery.lastError().text();
        return QStringList {};
    }
    QStringList rolePermIds {};
    while(sqlQuery.next()){
        const QString rolePermId {sqlQuery.value(0).toString()};
        rolePermIds.push_back(rolePermId);
    }
    return rolePermIds;
}

QStringList SQL_Handler::getRolePermParentIds(const QSqlDatabase &dataBase, const QString &rolePermId,QString &lastError)
{
    const QString queryText {"SELECT parent_id FROM roles_permissions_relationship WHERE child_id=:rolePermId"};
    QSqlQuery sqlQuery {dataBase};
    if(!sqlQuery.prepare(queryText)){
        lastError=sqlQuery.lastError().text();
        return QStringList {};
    }
    sqlQuery.bindValue(":rolePermId",rolePermId);

    if(!sqlQuery.exec()){
        lastError=sqlQuery.lastError().text();
        return QStringList {};
    }
    QStringList rolePermIds {};
    while(sqlQuery.next()){
        const QString rolePermId {sqlQuery.value(0).toString()};
        rolePermIds.push_back(rolePermId);
    }
    return rolePermIds;
}

QJsonArray SQL_Handler::getRolePermChildren(const QSqlDatabase &dataBase, const QString &rolePermId, QString &lastError)
{
    const QString queryText {"SELECT child_id from roles_permissions_relationship WHERE parent_id=:rolePermId"};
    QSqlQuery sqlQuery {dataBase};
    if(!sqlQuery.prepare(queryText)){
        lastError=sqlQuery.lastError().text();
        return QJsonArray {};
    }
    sqlQuery.bindValue(":rolePermId",rolePermId);
    if(!sqlQuery.exec()){
        lastError=sqlQuery.lastError().text();
        return QJsonArray {};
    }
    QStringList childRolePermIds {};
    while(sqlQuery.next()){
        const QString childId {sqlQuery.value("child_id").toString()};
        childRolePermIds.push_back(childId);
    }
    if(childRolePermIds.isEmpty()){
        return QJsonArray {};
    }
    std::transform(childRolePermIds.begin(),childRolePermIds.end(),childRolePermIds.begin(),[](const QString rolePermId){
        return QStringLiteral("'%1'").arg(rolePermId);
    });

    {
        const QString queryText {QStringLiteral("SELECT * FROM roles_permissions WHERE id IN (%1)").arg(childRolePermIds.join(","))};
        QSqlQuery sqlQuery {dataBase};
        if(!sqlQuery.prepare(queryText)){
            lastError=sqlQuery.lastError().text();
            return QJsonArray {};
        }

        if(sqlQuery.exec()){
            QJsonArray rolePermObjects {};
            while(sqlQuery.next()){
                QSqlRecord sqlRecord {sqlQuery.record()};
                const int fieldCount {sqlRecord.count()};

                QJsonObject rolePermObject {};
                for(int i=0;i<fieldCount;++i){
                    const QString fieldName {sqlRecord.fieldName(i)};
                    const QVariant fieldValue {sqlRecord.value(i)};
                    if(fieldValue.isNull()){
                        rolePermObject.insert(fieldName,QJsonValue::Null);
                    }
                    else{
                        rolePermObject.insert(fieldName,fieldValue.toString());
                    }
                }
                rolePermObjects.push_back(rolePermObject);
            }
            return rolePermObjects;
        }
        else{
            lastError=sqlQuery.lastError().text();
            return QJsonArray {};
        }
    }
    lastError="Undefined";
    return QJsonArray {};
}

SQL_Handler::SQL_Handler(QSharedPointer<QSettings> appSettingsPtr)
    :appSettingsPtr_{appSettingsPtr}
{
}

//Get Users
SQL_Status SQL_Handler::getUsersObject(const QMap<QString, QString> &queryMap, const QString &requesterId, QJsonObject &outUsersObject, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"user:read"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//query
            int queryLimit {100};
            int queryOffset {0};
            const auto queryTotal {[&](){
                    const QString queryText {"SELECT COUNT(*) FROM users"};
                    QSqlQuery sqlQuery {queryText,dataBase};
                    if(sqlQuery.next()){
                        const int totalUsers {sqlQuery.value(0).toInt()};
                        return totalUsers;
                    }
                    return 0;
                }()
            };
            QString queryText {"SELECT * FROM users"};

            {//set limit/offset
                QStringList validKeys {"limit","offset","first_name","last_name","email","is_blocked","phone_number","position","gender"};
                QMap<QString,QString> localQueryMap {queryMap};
                auto it {localQueryMap.begin()};
                while(it!=localQueryMap.end()){
                    if(!validKeys.contains(it.key())){
                        it=localQueryMap.erase(it);
                        continue;
                    }
                    ++it;
                }

                auto limitIt {localQueryMap.find("limit")};
                if(limitIt!=localQueryMap.end()){
                    queryLimit=limitIt.value().toInt();
                    localQueryMap.erase(limitIt);
                }
                auto offsetIt {localQueryMap.find("offset")};
                if(offsetIt!=localQueryMap.end()){
                    queryOffset=offsetIt.value().toInt();
                    localQueryMap.erase(offsetIt);
                }
                {//set filter
                    if(!localQueryMap.empty()){
                        queryText+=" WHERE";
                        auto it {localQueryMap.begin()};
                        while(it!=localQueryMap.end()){
                            if(it.key()=="first_name"){
                                queryText+=" first_name ILIKE '%" + it.value() + "%'";
                            }
                            else if(it.key()=="last_name"){
                                queryText+=" last_name ILIKE '%" + it.value() + "%'";
                            }
                            else if(it.key()=="email"){
                                queryText+=" email = '" + it.value() + "'";
                            }
                            else if(it.key()=="is_blocked"){
                                queryText+=" is_blocked = '" + it.value() + "'";
                            }
                            else if(it.key()=="phone_number"){
                                queryText+=" phone_number ILIKE '%" + it.value() + "%'";
                            }
                            else if(it.key()=="position"){
                                queryText+=" position ILIKE '%" + it.value() + "%'";
                            }
                            else if(it.key()=="gender"){
                                queryText+=" gender = '" + it.value() + "'";
                            }
                            it=localQueryMap.erase(it);
                            if(!localQueryMap.empty()){
                                queryText+=" AND";
                            }
                        }
                    }
                }
                queryText += " LIMIT " + QString::number(queryLimit);
                queryText += " OFFSET " + QString::number(queryOffset);
            }

            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }

            if(sqlQuery.exec()){
                QJsonArray userObjects {};
                while(sqlQuery.next()){
                    QSqlRecord sqlRecord {sqlQuery.record()};
                    const int fieldCount {sqlRecord.count()};

                    QJsonObject userObject {};
                    for(int i=0;i<fieldCount;++i){
                        const QString fieldName {sqlRecord.fieldName(i)};
                        const QVariant fieldValue {sqlRecord.value(i)};
                        if(fieldValue.isNull()){
                            userObject.insert(fieldName,QJsonValue::Null);
                        }
                        else{
                            if(fieldName=="is_blocked"){
                                userObject.insert(fieldName,fieldValue.toBool());
                            }
                            else{
                                userObject.insert(fieldName,fieldValue.toString());
                            }
                        }
                    }
                    userObjects.push_back(userObject);
                }
                outUsersObject.insert("limit",queryLimit);
                outUsersObject.insert("offset",queryOffset);
                outUsersObject.insert("count",userObjects.size());
                outUsersObject.insert("total",queryTotal);
                outUsersObject.insert("items",userObjects);
                sqlStatus=SQL_Status::Success;
                goto end;
            }
            else{
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}
//Get User
SQL_Status SQL_Handler::getUserObject(const QString &userId, const QString &requesterId, QJsonObject &outUserObject, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//autorize
            const QString rolePermIdent {"user:read"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//query
            const QString queryText {"SELECT * FROM users WHERE id=:userId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":userId",userId);

            if(sqlQuery.exec()){
                if(!sqlQuery.next()){
                    sqlStatus=SQL_Status::NotFound;
                    goto end;
                }
                QSqlRecord sqlRecord {sqlQuery.record()};
                const int fieldCount {sqlRecord.count()};

                for(int i=0;i<fieldCount;++i){
                    const QString fieldName {sqlRecord.fieldName(i)};
                    const QVariant fieldValue {sqlRecord.value(i)};
                    if(fieldValue.isNull()){
                        outUserObject.insert(fieldName,QJsonValue::Null);
                    }
                    else{
                        if(fieldName=="is_blocked"){
                            outUserObject.insert(fieldName,fieldValue.toBool());
                        }
                        else{
                            outUserObject.insert(fieldName,fieldValue.toString());
                        }
                    }
                }
                sqlStatus=SQL_Status::Success;
                goto end;
            }
            else{
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}
//Update User
SQL_Status SQL_Handler::putUserObject(const QString &userId, const QString &requesterId, const QJsonObject &inUserObject, QJsonObject &outUserObject, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"user:update"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//check
            const QStringList neededKeys {"first_name","last_name","email","is_blocked","phone_number","position","gender","location_id","ou_id"};
            for(const QString& key: neededKeys){
                if(!inUserObject.contains(key)){
                    lastError=QString("Not valid user, key: '%1' not present!").arg(key);
                    goto end;
                }
            }
        }
        {//update
            const QString updatedAt {timeWithTimezone()};
            const QString queryText {"UPDATE users SET first_name=:first_name,last_name=:last_name,email=:email,is_blocked=:is_blocked,updated_at=:updated_at,"
                                     "phone_number=:phone_number,position=:position,gender=:gender,location_id=:location_id,ou_id=:ou_id WHERE id=:id"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":id",userId);
            sqlQuery.bindValue(":updated_at",updatedAt);

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
                goto end;
            }
        }
        {//get updated back
            const QString queryText {"SELECT * FROM users WHERE id=:userId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
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
                        if(fieldName=="is_blocked"){
                            outUserObject.insert(fieldName,fieldValue.toBool());
                        }
                        else{
                            outUserObject.insert(fieldName,fieldValue.toString());
                        }
                    }
                }
                sqlStatus=SQL_Status::Success;
                goto end;
            }
            else{
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}
//Create User
SQL_Status SQL_Handler::postUserObject(const QString &requesterId, const QJsonObject &inUserObject, QJsonObject &outUserObject, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"user:create"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//check
            const QStringList neededKeys {"id","first_name","last_name","email","phone_number","position","gender","location_id","ou_id"};
            for(const QString& key: neededKeys){
                if(!inUserObject.contains(key)){
                    lastError=QString("Not valid user, key: '%1' not present!").arg(key);
                    goto end;
                }
            }
        }
        {//create
            const QString createdAt {timeWithTimezone()};
            const QString updatedAt {timeWithTimezone()};
            const QString queryText {"INSERT INTO users (id,first_name,last_name,email,created_at,updated_at,is_blocked,phone_number,position,gender,location_id,ou_id)"
                                     " VALUES(:id,:first_name,:last_name,:email,:created_at,:updated_at,:is_blocked,:phone_number,:position,:gender,:location_id,:ou_id)"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":created_at",createdAt);
            sqlQuery.bindValue(":updated_at",updatedAt);

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
                goto end;
            }
        }
        {//get created back
            const QString userId {inUserObject.value("id").toString()};
            const QString queryText {"SELECT * FROM users WHERE id=:userId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
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
                        if(fieldName=="is_blocked"){
                            outUserObject.insert(fieldName,fieldValue.toBool());
                        }
                        else{
                            outUserObject.insert(fieldName,fieldValue.toString());
                        }
                    }
                }
                sqlStatus=SQL_Status::Success;
                goto end;
            }
            else{
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}
//Delete User
SQL_Status SQL_Handler::deleteUserObject(const QString &userId, const QString &requesterId, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"user:delete"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//check if exists
            const QString queryText {"SELECT COUNT(*) FROM users WHERE id=:userId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":userId",userId);

            if(!sqlQuery.exec()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.next();
            const int queryRows {sqlQuery.value(0).toInt()};
            if(!queryRows){
                lastError=QString("User with id: '%1' not found!").arg(userId);
                sqlStatus=SQL_Status::NotFound;
                goto end;
            }
        }
        {//delete
            const QString queryText {"DELETE FROM users WHERE id=:userId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":userId",userId);

            if(!sqlQuery.exec()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlStatus=SQL_Status::Success;
            goto end;
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}

//Get RolePermissions
SQL_Status SQL_Handler::getRolePermsObject(const QMap<QString, QString> &queryMap, const QString &requesterId, QJsonObject &outRolePermsObject, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"role_permission:read"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//query
            int queryLimit {100};
            int queryOffset {0};
            const auto queryTotal {[&](){
                    const QString queryText {"SELECT COUNT(*) FROM roles_permissions"};
                    QSqlQuery sqlQuery {queryText,dataBase};
                    if(sqlQuery.next()){
                        const int totalRolePerms {sqlQuery.value(0).toInt()};
                        return totalRolePerms;
                    }
                    return 0;
                }()
            };
            QString queryText {"SELECT * FROM roles_permissions"};

            {//set limit/offset
                QStringList validKeys {"limit","offset","type","name"};
                QMap<QString,QString> localQueryMap {queryMap};
                auto it {localQueryMap.begin()};
                while(it!=localQueryMap.end()){
                    if(!validKeys.contains(it.key())){
                        it=localQueryMap.erase(it);
                        continue;
                    }
                    ++it;
                }

                auto limitIt {localQueryMap.find("limit")};
                if(limitIt!=localQueryMap.end()){
                    queryLimit=limitIt.value().toInt();
                    localQueryMap.erase(limitIt);
                }
                auto offsetIt {localQueryMap.find("offset")};
                if(offsetIt!=localQueryMap.end()){
                    queryOffset=offsetIt.value().toInt();
                    localQueryMap.erase(offsetIt);
                }
                {//set filter
                    if(!localQueryMap.empty()){
                        queryText+=" WHERE";
                        auto it {localQueryMap.begin()};
                        while(it!=localQueryMap.end()){
                            if(it.key()=="name"){
                                queryText+=" name ILIKE '%" + it.value() + "%'";
                            }
                            else if(it.key()=="type"){
                                queryText+=" type = '" + it.value() + "'";
                            }
                            it=localQueryMap.erase(it);
                            if(!localQueryMap.empty()){
                                queryText+=" AND";
                            }
                        }
                    }
                }
                queryText += " LIMIT " + QString::number(queryLimit);
                queryText += " OFFSET " + QString::number(queryOffset);
            }

            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }

            if(sqlQuery.exec()){
                QJsonArray rolePermObjects {};
                while(sqlQuery.next()){
                    QSqlRecord sqlRecord {sqlQuery.record()};
                    const int fieldCount {sqlRecord.count()};

                    QJsonObject rolePermObject {};
                    for(int i=0;i<fieldCount;++i){
                        const QString fieldName {sqlRecord.fieldName(i)};
                        const QVariant fieldValue {sqlRecord.value(i)};
                        if(fieldValue.isNull()){
                            rolePermObject.insert(fieldName,QJsonValue::Null);
                        }
                        else{
                            rolePermObject.insert(fieldName,fieldValue.toString());
                        }
                    }
                    rolePermObjects.push_back(rolePermObject);
                }
                outRolePermsObject.insert("limit",queryLimit);
                outRolePermsObject.insert("offset",queryOffset);
                outRolePermsObject.insert("count",rolePermObjects.size());
                outRolePermsObject.insert("total",queryTotal);
                outRolePermsObject.insert("items",rolePermObjects);
                sqlStatus=SQL_Status::Success;
                goto end;
            }
            else{
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
    }
    end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}
//Get RolePermission
SQL_Status SQL_Handler::getRolePermObject(const QString &rolePermId, const QString &requesterId, QJsonObject &outRolePermObject, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"role_permission:read"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//query
            const QString queryText {"SELECT * FROM roles_permissions WHERE id=:rolePermId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":rolePermId",rolePermId);

            if(sqlQuery.exec()){
                if(!sqlQuery.next()){
                    sqlStatus=SQL_Status::NotFound;
                    goto end;
                }
                QSqlRecord sqlRecord {sqlQuery.record()};
                const int fieldCount {sqlRecord.count()};

                for(int i=0;i<fieldCount;++i){
                    const QString fieldName {sqlRecord.fieldName(i)};
                    const QVariant fieldValue {sqlRecord.value(i)};
                    if(fieldValue.isNull()){
                        outRolePermObject.insert(fieldName,QJsonValue::Null);
                    }
                    else{
                        outRolePermObject.insert(fieldName,fieldValue.toString());
                    }
                }
                sqlStatus=SQL_Status::Success;
                goto end;
            }
            else{
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}
//Update RolePermission
SQL_Status SQL_Handler::putRolePermObject(const QString &rolePermId, const QString &requesterId, const QJsonObject &inRolePermObject, QJsonObject &outRolePermObject, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"role_permission:update"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//check
            const QStringList neededKeys {"name","type","description"};
            for(const QString& key: neededKeys){
                if(!inRolePermObject.contains(key)){
                    lastError=QString("Not valid role_permission, key: '%1' not present!").arg(key);
                    goto end;
                }
            }
        }
        {//update
            const QString queryText {"UPDATE roles_permissions SET name=:name,type=:type,description=:description WHERE id=:rolePermId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":rolePermId",rolePermId);

            const QStringList& jsonKeys {inRolePermObject.keys()};
            std::for_each(jsonKeys.begin(),jsonKeys.end(),[&](const QString& key){
                sqlQuery.bindValue(QString(":%1").arg(key),inRolePermObject.value(key).toString());
            });

            if(!sqlQuery.exec()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
        {//get updated back
            const QString queryText {"SELECT * FROM roles_permissions WHERE id=:rolePermId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":rolePermId",rolePermId);

            if(sqlQuery.exec()){
                sqlQuery.next();
                QSqlRecord sqlRecord {sqlQuery.record()};
                const int fieldCount {sqlRecord.count()};

                for(int i=0;i<fieldCount;++i){
                    const QString fieldName {sqlRecord.fieldName(i)};
                    const QVariant fieldValue {sqlRecord.value(i)};
                    if(fieldValue.isNull()){
                        outRolePermObject.insert(fieldName,QJsonValue::Null);
                    }
                    else{
                        outRolePermObject.insert(fieldName,fieldValue.toString());
                    }
                }
                sqlStatus=SQL_Status::Success;
                goto end;
            }
            else{
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}
//Create RolePermission
SQL_Status SQL_Handler::postRolePermObject(const QString &requesterId, const QJsonObject &inRolePermObject, QJsonObject &outRolePermObject, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"role_permission:create"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }

        {//check
            const QStringList neededKeys {"name","type","description"};
            for(const QString& key: neededKeys){
                if(!inRolePermObject.contains(key)){
                    lastError=QString("Not valid role_permission, key: '%1' not present!").arg(key);
                    goto end;
                }
            }
        }
        {//check if name is duplicate
            const QString rolePermName {inRolePermObject.value("name").toString()};
            const QString queryText {"SELECT COUNT(*) FROM roles_permissions WHERE name=:rolePermName"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=dataBase.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":rolePermName",rolePermName);
            if(!sqlQuery.exec()){
                lastError=dataBase.lastError().text();
                goto end;
            }
            if(sqlQuery.next()){
                const int rowCount {sqlQuery.value(0).toInt()};
                if(rowCount){
                    sqlStatus=SQL_Status::Conflict;
                    lastError=QString("Role/Permission with name: '%1' already exists!").arg(rolePermName);
                    goto end;
                }
            }
        }
        const QString rolePermId {QUuid::createUuidV5(QUuid::createUuid(),usystemNamespace_).toString(QUuid::WithoutBraces)};

        {//create
            const QString queryText {"INSERT INTO roles_permissions (id,name,type,description) VALUES(:rolePermId,:name,:type,:description)"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":rolePermId",rolePermId);

            const QStringList& jsonKeys {inRolePermObject.keys()};
            std::for_each(jsonKeys.begin(),jsonKeys.end(),[&](const QString& key){
                sqlQuery.bindValue(QString(":%1").arg(key),inRolePermObject.value(key).toString());
            });

            if(!sqlQuery.exec()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
        {//get created back
            const QString queryText {"SELECT * FROM roles_permissions WHERE id=:rolePermId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":rolePermId",rolePermId);

            if(sqlQuery.exec()){
                sqlQuery.next();
                QSqlRecord sqlRecord {sqlQuery.record()};
                const int fieldCount {sqlRecord.count()};

                for(int i=0;i<fieldCount;++i){
                    const QString fieldName {sqlRecord.fieldName(i)};
                    const QVariant fieldValue {sqlRecord.value(i)};
                    if(fieldValue.isNull()){
                        outRolePermObject.insert(fieldName,QJsonValue::Null);
                    }
                    else{
                        outRolePermObject.insert(fieldName,fieldValue.toString());
                    }
                }
                sqlStatus=SQL_Status::Success;
                goto end;
            }
            else{
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}
//Delete RolePermission
SQL_Status SQL_Handler::deleteRolePermObject(const QString &rolePermId, const QString &requesterId, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"role_permission:delete"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//check if exists
            const QString queryText {"SELECT COUNT(*) FROM roles_permissions WHERE id=:rolePermId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":rolePermId",rolePermId);

            if(!sqlQuery.exec()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            if(!sqlQuery.next()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            const int queryRows {sqlQuery.value(0).toInt()};
            if(!queryRows){
                lastError=QString("Role/Permission with id: '%1' not found!").arg(rolePermId);
                sqlStatus=SQL_Status::NotFound;
                goto end;
            }
        }
        {//check role/permission/admin
            const QString queryText {"SELECT name,type FROM roles_permissions WHERE id=:rolePermId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":rolePermId",rolePermId);

            if(!sqlQuery.exec()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            if(!sqlQuery.next()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            const QString uauthAdminName {"UAuthAdmin"};
            const QString nameText {sqlQuery.value("name").toString()};
            const QString typeText {sqlQuery.value("type").toString()};
            if(uauthAdminName==nameText){
                lastError=QString("Delete a role/permission with name: '%1' is prohibited!").arg(uauthAdminName);
                goto end;
            }
            if("permission"==typeText){
                lastError="Delete a role/permission with type: 'permission' is prohibited!";
                goto end;
            }
        }
        {//check references
            const QStringList childRolePermIds {getRolePermChildIds(dataBase,rolePermId,lastError)};
            if(!lastError.isEmpty()){
                goto end;
            }
            const QStringList parentRolePermIds {getRolePermParentIds(dataBase,rolePermId,lastError)};
            if(!lastError.isEmpty()){
                goto end;
            }

            if(!childRolePermIds.empty() || !parentRolePermIds.empty()){
                lastError=QString("%1 is parent/child for: %2 %3").arg(rolePermId).
                        arg(parentRolePermIds.empty() ? "" : parentRolePermIds.join(", ")).
                        arg(childRolePermIds.empty() ? "" : childRolePermIds.join(", "));
                sqlStatus=SQL_Status::UnprocessableEntity;
                goto end;
            }
        }
        {//delete
            const QString queryText {"DELETE FROM roles_permissions WHERE id=:rolePermId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":rolePermId",rolePermId);

            if(!sqlQuery.exec()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlStatus=SQL_Status::Success;
            goto end;
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}

//Add Child to RolePermission
SQL_Status SQL_Handler::putRolePermChild(const QString &parentRolePermId, const QString &childRolePermId, const QString &requesterId, QJsonObject& outRolePermObject,QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"role_permission:update"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//check parent and child
            if(!checkRolePermById(dataBase,parentRolePermId) || !checkRolePermById(dataBase,childRolePermId)){
                lastError=QString("Role/Permission with id: '%1' or '%2' not found!").arg(parentRolePermId,childRolePermId);
                sqlStatus=SQL_Status::NotFound;
                goto end;
            }
        }
        {//create
            const QString createdAt {timeWithTimezone()};
            const QString queryText {"INSERT INTO roles_permissions_relationship (created_at,parent_id,child_id) VALUES(:createdAt,:parentRolePermId,:childRolePermId)"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":createdAt",createdAt);
            sqlQuery.bindValue(":parentRolePermId",parentRolePermId);
            sqlQuery.bindValue(":childRolePermId",childRolePermId);

            if(!sqlQuery.exec()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
        {//get created back
            const QString queryText {"SELECT * FROM roles_permissions WHERE id=:parentRolePermId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":parentRolePermId",parentRolePermId);

            if(sqlQuery.exec()){
                while(sqlQuery.next()){
                    QSqlRecord sqlRecord {sqlQuery.record()};
                    const int fieldCount {sqlRecord.count()};

                    for(int i=0;i<fieldCount;++i){
                        const QString fieldName {sqlRecord.fieldName(i)};
                        const QVariant fieldValue {sqlRecord.value(i)};
                        if(fieldValue.isNull()){
                            outRolePermObject.insert(fieldName,QJsonValue::Null);
                        }
                        else{
                            outRolePermObject.insert(fieldName,fieldValue.toString());
                        }
                    }
                    {//get chidren
                        const QJsonArray rolePermChidren {getRolePermChildren(dataBase,parentRolePermId,lastError)};
                        if(!lastError.isEmpty()){
                            goto end;
                        }
                        outRolePermObject.insert("children",rolePermChidren);
                    }
                    sqlStatus=SQL_Status::Success;
                    goto end;
                }
            }
            else{
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}
//Delete Child from RolePermission
SQL_Status SQL_Handler::deleteRolePermChild(const QString &parentRolePermId, const QString &childRolePermId, const QString &requesterId, QJsonObject& outRolePermObject,QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"role_permission:update"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//check parent and child
            if(!checkRolePermById(dataBase,parentRolePermId) || !checkRolePermById(dataBase,childRolePermId)){
                lastError=QString("Role/Permission with id: '%1' or '%2' not found!").arg(parentRolePermId,childRolePermId);
                sqlStatus=SQL_Status::NotFound;
                goto end;
            }
        }
        {//delete
            const QString createdAt {timeWithTimezone()};
            const QString queryText {"DELETE FROM roles_permissions_relationship WHERE parent_id=:parentRolePermId AND child_id=:childRolePermId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":parentRolePermId",parentRolePermId);
            sqlQuery.bindValue(":childRolePermId",childRolePermId);

            if(!sqlQuery.exec()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
        {//get updated back
            const QString queryText {"SELECT * FROM roles_permissions WHERE id=:parentRolePermId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":parentRolePermId",parentRolePermId);

            if(sqlQuery.exec()){
                while(sqlQuery.next()){
                    QSqlRecord sqlRecord {sqlQuery.record()};
                    const int fieldCount {sqlRecord.count()};

                    for(int i=0;i<fieldCount;++i){
                        const QString fieldName {sqlRecord.fieldName(i)};
                        const QVariant fieldValue {sqlRecord.value(i)};
                        if(fieldValue.isNull()){
                            outRolePermObject.insert(fieldName,QJsonValue::Null);
                        }
                        else{
                            outRolePermObject.insert(fieldName,fieldValue.toString());
                        }
                    }
                    {//get chidren
                        const QJsonArray rolePermChidren {getRolePermChildren(dataBase,parentRolePermId,lastError)};
                        if(!lastError.isEmpty()){
                            goto end;
                        }
                        outRolePermObject.insert("children",rolePermChidren);
                    }
                    sqlStatus=SQL_Status::Success;
                    goto end;
                }
            }
            else{
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}

//Get User's RolePermissions by UserId
SQL_Status SQL_Handler::getUserRolePermsObject(const QString &userId, const QMap<QString, QString> &queryMap, const QString &requesterId, QJsonObject &outRolePermsObject, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"role_permission:read"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//query
            int queryLimit {100};
            int queryOffset {0};
            const int queryTotal {getTotalUserRolePermsByUserId(dataBase,userId,lastError)};
            QString queryText {"SELECT * FROM roles_permissions WHERE id IN (SELECT role_permission_id FROM users_roles_permissions WHERE user_id=:userId)"};

            {//set limit/offset
                QStringList validKeys {"limit","offset"};
                QMap<QString,QString> localQueryMap {queryMap};
                auto it {localQueryMap.begin()};
                while(it!=localQueryMap.end()){
                    if(!validKeys.contains(it.key())){
                        localQueryMap.erase(it++);
                        continue;
                    }
                    ++it;
                }

                auto limitIt {localQueryMap.find("limit")};
                if(limitIt!=localQueryMap.end()){
                    queryLimit=limitIt.value().toInt();
                    localQueryMap.erase(limitIt);
                }
                auto offsetIt {localQueryMap.find("offset")};
                if(offsetIt!=localQueryMap.end()){
                    queryOffset=offsetIt.value().toInt();
                }

                queryText += " LIMIT " + QString::number(queryLimit);
                queryText += " OFFSET " + QString::number(queryOffset);
            }

            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":userId",userId);

            if(sqlQuery.exec()){
                QJsonArray rolePermObjects {};
                while(sqlQuery.next()){
                    QSqlRecord sqlRecord {sqlQuery.record()};
                    const int fieldCount {sqlRecord.count()};

                    QJsonObject rolePermObject {};
                    for(int i=0;i<fieldCount;++i){
                        const QString fieldName {sqlRecord.fieldName(i)};
                        const QVariant fieldValue {sqlRecord.value(i)};
                        if(fieldValue.isNull()){
                            rolePermObject.insert(fieldName,QJsonValue::Null);
                        }
                        else{
                            rolePermObject.insert(fieldName,fieldValue.toString());
                        }
                    }
                    rolePermObjects.push_back(rolePermObject);
                }
                outRolePermsObject.insert("limit",queryLimit);
                outRolePermsObject.insert("offset",queryOffset);
                outRolePermsObject.insert("count",rolePermObjects.size());
                outRolePermsObject.insert("total",queryTotal);
                outRolePermsObject.insert("items",rolePermObjects);
                sqlStatus=SQL_Status::Success;
                goto end;
            }
            else{
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}
//Get RolePermission's Users by RolePermissionId
SQL_Status SQL_Handler::getRolePermUsersObject(const QString &rolePermId, const QMap<QString, QString> &queryMap, const QString &requesterId, QJsonObject &outUsersObject, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"user:read"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//query
            int queryLimit {100};
            int queryOffset {0};
            const int queryTotal {getTotalUserRolePermsByRolePermId(dataBase,rolePermId,lastError)};
            QString queryText {"SELECT * FROM users WHERE id IN (SELECT user_id FROM users_roles_permissions WHERE role_permission_id=:rolePermId)"};

            {//set limit/offset
                QStringList validKeys {"limit","offset"};
                QMap<QString,QString> localQueryMap {queryMap};
                auto it {localQueryMap.begin()};
                while(it!=localQueryMap.end()){
                    if(!validKeys.contains(it.key())){
                        localQueryMap.erase(it++);
                        continue;
                    }
                    ++it;
                }

                auto limitIt {localQueryMap.find("limit")};
                if(limitIt!=localQueryMap.end()){
                    queryLimit=limitIt.value().toInt();
                    localQueryMap.erase(limitIt);
                }
                auto offsetIt {localQueryMap.find("offset")};
                if(offsetIt!=localQueryMap.end()){
                    queryOffset=offsetIt.value().toInt();
                }

                queryText += " LIMIT " + QString::number(queryLimit);
                queryText += " OFFSET " + QString::number(queryOffset);
            }

            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":rolePermId",rolePermId);

            if(sqlQuery.exec()){
                QJsonArray userObjects {};
                while(sqlQuery.next()){
                    QSqlRecord sqlRecord {sqlQuery.record()};
                    const int fieldCount {sqlRecord.count()};

                    QJsonObject userObject {};
                    for(int i=0;i<fieldCount;++i){
                        const QString fieldName {sqlRecord.fieldName(i)};
                        const QVariant fieldValue {sqlRecord.value(i)};
                        if(fieldValue.isNull()){
                            userObject.insert(fieldName,QJsonValue::Null);
                        }
                        else{
                            userObject.insert(fieldName,fieldValue.toString());
                        }
                    }
                    userObjects.push_back(userObject);
                }
                outUsersObject.insert("limit",queryLimit);
                outUsersObject.insert("offset",queryOffset);
                outUsersObject.insert("count",userObjects.size());
                outUsersObject.insert("total",queryTotal);
                outUsersObject.insert("items",userObjects);
                sqlStatus=SQL_Status::Success;
                goto end;
            }
            else{
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}
//Get RolePermission Details
SQL_Status SQL_Handler::getRolePermDetailObject(const QString &rolePermId, const QString &requesterId, QJsonObject &outRolePermObject, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"role_permission:read"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//query
            const QString queryText {"SELECT * FROM roles_permissions WHERE id=:rolePermId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":rolePermId",rolePermId);

            if(sqlQuery.exec()){
                while(sqlQuery.next()){
                    QSqlRecord sqlRecord {sqlQuery.record()};
                    const int fieldCount {sqlRecord.count()};

                    for(int i=0;i<fieldCount;++i){
                        const QString fieldName {sqlRecord.fieldName(i)};
                        const QVariant fieldValue {sqlRecord.value(i)};
                        if(fieldValue.isNull()){
                            outRolePermObject.insert(fieldName,QJsonValue::Null);
                        }
                        else{
                            outRolePermObject.insert(fieldName,fieldValue.toString());
                        }
                    }
                    const QJsonArray rolePermChildren {getRolePermChildren(dataBase,rolePermId,lastError)};
                    if(!lastError.isNull()){
                        goto end;
                    }
                    outRolePermObject.insert("children",rolePermChildren);
                    sqlStatus=SQL_Status::Success;
                    goto end;
                }
            }
            else{
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}

//Check That User Authorized variant_new
SQL_Status SQL_Handler::getAuthzCheck(const QMap<QString, QString> &queryMap, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//check
            if(!queryMap.contains("user_id") || (!queryMap.contains("rp_name") & !queryMap.contains("rp_id"))){
                lastError=QStringLiteral("Query does not contains '%1', '%2' or '%3' keys!").arg("user_id","rp_name","rp_id");
                goto end;
            }
        }
        const QString userId {queryMap.value("user_id")};
        {//check if uauthadmin
            const QString queryText {"SELECT name FROM roles_permissions WHERE id IN (SELECT role_permission_id FROM users_roles_permissions WHERE user_id=:userId)"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":userId",userId);

            if(!sqlQuery.exec()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            while(sqlQuery.next()){
                const QString uauthAdminName {"UAuthAdmin"};
                const QString nameText {sqlQuery.value("name").toString()};
                if(uauthAdminName==nameText){
                    sqlStatus=SQL_Status::Success;
                    goto end;
                }
            }
        }

        QStringList userIdRolePermIdList {};
        QStringList rolePermIdList {};

        {//get tot-level 'id' from users_roles_permissions
            const QString queryText {"SELECT role_permission_id FROM users_roles_permissions WHERE user_id=:userId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":userId",userId);

            if(!sqlQuery.exec()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            while(sqlQuery.next()){
                const QString rolePermId {sqlQuery.value(0).toString()};
                userIdRolePermIdList.push_back(rolePermId);
            }
            if(userIdRolePermIdList.isEmpty()){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
            getRolePermIdsRecursive(dataBase,userIdRolePermIdList);
        }
        {//get all 'rolePermId' and 'rolePermId' by 'rolePermName' (if presents)
            std::map<QString,QString> localQueryMap {queryMap.toStdMap()};
            QStringList rolePermNameList {};
            std::for_each(localQueryMap.begin(),localQueryMap.end(),[&](const std::pair<QString,QString>& pair){
                if(pair.first=="rp_id"){
                    rolePermIdList.push_back(pair.second);
                }
                else if(pair.first=="rp_name"){
                    rolePermNameList.push_back(QStringLiteral("'%1'").arg(pair.second));
                }
            });
            if(!rolePermNameList.isEmpty()){
                QString queryText {QStringLiteral("SELECT id from roles_permissions WHERE name IN (%1)").arg(rolePermNameList.join(","))};
                QSqlQuery sqlQuery {dataBase};
                if(!sqlQuery.prepare(queryText)){
                    lastError=sqlQuery.lastError().text();
                    goto end;
                }
                if(!sqlQuery.exec()){
                    lastError=sqlQuery.lastError().text();
                    goto end;
                }
                while(sqlQuery.next()){
                    const QString rolePermId {sqlQuery.value(0).toString()};
                    rolePermIdList.push_back(rolePermId);
                }
            }
            if(rolePermIdList.isEmpty()){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        const bool isContains {std::all_of(rolePermIdList.begin(),rolePermIdList.end(),[&](const QString& rolePermId){
                return userIdRolePermIdList.contains(rolePermId);
        })};
        sqlStatus=isContains ? SQL_Status::Success : SQL_Status::Unauthorized;
        goto end;
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}
//Check That User Authorized variant_old
SQL_Status SQL_Handler::getAuthzCheck(const QString &userId, const QString &rolePermIdent, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            sqlStatus=checkIsAuthorized(dataBase,userId,rolePermIdent,lastError);
            goto end;
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}

//Assign Role Or Permission To User
SQL_Status SQL_Handler::postAuthzManage(const QString &userId, const QString &rolePermId, const QString &requesterId, QJsonObject &outRolePermObject, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"authorization_manage:update"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//check
            const bool isUserExists {checkUserById(dataBase,userId)};
            if(!isUserExists){
                sqlStatus=SQL_Status::NotFound;
                goto end;
            }
        }
        {//assign
            const QString createdAt {timeWithTimezone()};
            const QString queryText {"INSERT INTO users_roles_permissions (created_at,user_id,role_permission_id) VALUES(:createdAt,:userId,:rolePermId)"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":createdAt",createdAt);
            sqlQuery.bindValue(":userId",userId);
            sqlQuery.bindValue(":rolePermId",rolePermId);

            if(!sqlQuery.exec()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
        {//get updated back
            const QString queryText {"SELECT * FROM roles_permissions WHERE id=:rolePermId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":rolePermId",rolePermId);

            if(!sqlQuery.exec()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            while(sqlQuery.next()){
                QSqlRecord sqlRecord {sqlQuery.record()};
                const int fieldCount {sqlRecord.count()};

                for(int i=0;i<fieldCount;++i){
                    const QString fieldName {sqlRecord.fieldName(i)};
                    const QVariant fieldValue {sqlRecord.value(i)};
                    if(fieldValue.isNull()){
                        outRolePermObject.insert(fieldName,QJsonValue::Null);
                    }
                    else{
                        outRolePermObject.insert(fieldName,fieldValue.toString());
                    }
                }
                sqlStatus=SQL_Status::Success;
                goto end;
            }
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}
//Delete Role Or Permission From User
SQL_Status SQL_Handler::deleteAuthzManage(const QString &userId, const QString &rolePermId, const QString &requesterId, QJsonObject &outRolePermObject, QString &lastError)
{
    SQL_Status sqlStatus {SQL_Status::BadRequest};
    const QString driverName {"QPSQL"};
    const QString connectionName {QUuid::createUuid().toString(QUuid::WithoutBraces)};
    {
        QSqlDatabase dataBase {QSqlDatabase::addDatabase(driverName,connectionName)};
        if(!initDatabase(dataBase)){
            lastError=dataBase.lastError().text();
            goto end;
        }
        {//authorize
            const QString rolePermIdent {"authorization_manage:update"};
            const SQL_Status authStatus {checkIsAuthorized(dataBase,requesterId,rolePermIdent,lastError)};
            if(authStatus!=SQL_Status::Success){
                sqlStatus=SQL_Status::Unauthorized;
                goto end;
            }
        }
        {//check
            const bool isUserExists {checkUserById(dataBase,userId)};
            if(!isUserExists){
                sqlStatus=SQL_Status::NotFound;
                goto end;
            }
        }
        {//delete
            const QString queryText {"DELETE FROM users_roles_permissions WHERE user_id=:userId AND role_permission_id=:rolePermId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":userId",userId);
            sqlQuery.bindValue(":rolePermId",rolePermId);

            if(!sqlQuery.exec()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
        }
        {//get updated back
            const QString queryText {"SELECT * FROM roles_permissions WHERE id=:rolePermId"};
            QSqlQuery sqlQuery {dataBase};
            if(!sqlQuery.prepare(queryText)){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            sqlQuery.bindValue(":rolePermId",rolePermId);

            if(!sqlQuery.exec()){
                lastError=sqlQuery.lastError().text();
                goto end;
            }
            while(sqlQuery.next()){
                QSqlRecord sqlRecord {sqlQuery.record()};
                const int fieldCount {sqlRecord.count()};

                for(int i=0;i<fieldCount;++i){
                    const QString fieldName {sqlRecord.fieldName(i)};
                    const QVariant fieldValue {sqlRecord.value(i)};
                    if(fieldValue.isNull()){
                        outRolePermObject.insert(fieldName,QJsonValue::Null);
                    }
                    else{
                        outRolePermObject.insert(fieldName,fieldValue.toString());
                    }
                }
                sqlStatus=SQL_Status::Success;
                goto end;
            }
        }
    }
end:
    QSqlDatabase::removeDatabase(connectionName);
    return sqlStatus;
}

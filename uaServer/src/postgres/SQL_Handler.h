#ifndef SQLHANDLER_H
#define SQLHANDLER_H

#include <QMap>
#include <QString>
#include <QJsonArray>
#include <QJsonObject>
#include <QStringList>
#include <QSqlDatabase>
#include <QSharedPointer>

enum class SQL_Status{
    Success,
    Conflict,
    NotFound,
    BadRequest,
    Unauthorized,
    UnprocessableEntity
};

class QSettings;

class SQL_Handler
{
private:
    const QString usystemNamespace_ {"6ba7b810-9dad-11d1-80b4-00c04fd430c8"};
    QJsonObject paramsObject_ {};
    QSharedPointer<QSettings> appSettingsPtr_  {nullptr};

    QString timeWithTimezone();
    bool initDatabase(QSqlDatabase& dataBase);
    void getRolePermIdsRecursive(const QSqlDatabase& dataBase,QStringList& rolePermIds);

    bool checkUserById(const QSqlDatabase& dataBase,const QString& userId);
    bool checkRolePermById(const QSqlDatabase& dataBase,const QString& rolePermId);
    SQL_Status checkIsAuthorized(const QSqlDatabase& dataBase,const QString& userId,const QString& rolePermIdent,QString& lastError);

    int getTotalUserRolePermsByUserId(const QSqlDatabase& dataBase,const QString& userId,QString& lastError);
    int getTotalUserRolePermsByRolePermId(const QSqlDatabase& dataBase,const QString& rolePermId,QString& lastError);

    QStringList getRolePermChildIds(const QSqlDatabase& dataBase, const QString& rolePermId, QString& lastError);
    QStringList getRolePermParentIds(const QSqlDatabase& dataBase, const QString& rolePermId, QString& lastError);
    QJsonArray getRolePermChildren(const QSqlDatabase& dataBase,const QString& rolePermId,QString& lastError);

public:
    explicit SQL_Handler(QSharedPointer<QSettings> appSettingsPtr);
    ~SQL_Handler()=default;

    //Get Users
    SQL_Status getUsersObject(const QMap<QString,QString>& queryMap,const QString& requesterId,QJsonObject& outUsersObject,QString& lastError);
    //Get User
    SQL_Status getUserObject(const QString& userId,const QString& requesterId,QJsonObject& outUserObject,QString& lastError);
    //Update User
    SQL_Status putUserObject(const QString& userId,const QString& requesterId,const QJsonObject& inUserObject,QJsonObject& outUserObject,QString& lastError);
    //Create User
    SQL_Status postUserObject(const QString& requesterId,const QJsonObject& inUserObject,QJsonObject& outUserObject,QString& lastError);
    //Delete User
    SQL_Status deleteUserObject(const QString& userId,const QString& requesterId,QString& lastError);

    //Get RolePermissions
    SQL_Status getRolePermsObject(const QMap<QString,QString>& queryMap,const QString& requesterId,QJsonObject& outRolePermsObject,QString& lastError);
    //Get RolePermission
    SQL_Status getRolePermObject(const QString& rolePermId,const QString& requesterId,QJsonObject& outRolePermObject,QString& lastError);
    //Update RolePermission
    SQL_Status putRolePermObject(const QString& rolePermId, const QString& requesterId, const QJsonObject& inRolePermObject, QJsonObject& outRolePermObject, QString& lastError);
    //Create RolePermission
    SQL_Status postRolePermObject(const QString& requesterId,const QJsonObject& inRolePermObject,QJsonObject& outRolePermObject,QString& lastError);
    //Delete RolePermission
    SQL_Status deleteRolePermObject(const QString& rolePermId,const QString& requesterId,QString& lastError);;

    //Add Child to RolePermission
    SQL_Status putRolePermChild(const QString& parentRolePermId,const QString& childRolePermId,const QString& requesterId,QJsonObject& outRolePermObject,QString& lastError);
    //Delete Child from RolePermission
    SQL_Status deleteRolePermChild(const QString& parentRolePermId,const QString& childRolePermId,const QString& requesterId,QJsonObject& outRolePermObject,QString& lastError);

    //Get User's RolePermissions by UserId
    SQL_Status getUserRolePermsObject(const QString& userId,const QMap<QString,QString>& queryMap,const QString& requesterId,QJsonObject& outRolePermsObject,QString& lastError);
    //Get RolePermission's Users by RolePermissionId
    SQL_Status getRolePermUsersObject(const QString& rolePermId, const QMap<QString,QString>& queryMap, const QString& requesterId, QJsonObject& outUsersObject, QString& lastError);
    //Get RolePermission Details
    SQL_Status getRolePermDetailObject(const QString& rolePermId,const QString& requesterId,QJsonObject& outRolePermObject,QString& lastError);

    //Check That User Authorized
    SQL_Status getAuthzCheck(const QMap<QString,QString>& queryMap,QString& lastError);
    SQL_Status getAuthzCheck(const QString& userId, const QString& rolePermIdent,QString& lastError);

    //Assign Role Or Permission To User
    SQL_Status postAuthzManage(const QString& userId,const QString& rolePermId,const QString& requesterId,QJsonObject& outRolePermObject,QString& lastError);
    //Delete Role Or Permission From User
    SQL_Status deleteAuthzManage(const QString& userId,const QString& rolePermId,const QString& requesterId,QJsonObject& outRolePermObject,QString& lastError);
};

#endif // SQLHANDLER_H

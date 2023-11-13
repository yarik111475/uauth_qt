#include "HttpClient.h"
#include "HttpLiterals_p.h"
#include "HttpRequest.h"
#include "HttpRequest_p.h"
#include "HttpResponse.h"
#include "HttpResponder.h"
#include "HttpRouterRule.h"
#include "../postgres/SQL_Handler.h"
#include "../crypto/CryptoGenerator.h"
#include "3rdparty/http-parser/http_parser.h"

#include <QDebug>
#include <QSettings>
#include <QUrlQuery>
#include <QTcpSocket>
#include <QByteArray>
#include <QJsonObject>
#include <QJsonDocument>

void HttpClient::addUserRules(const HttpRequest &request, QAbstractSocket *socket)
{
    {// '/api/v1/u-auth/users' rule for GET
        auto handler {[&](){}};
        using ViewHandler=decltype(handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/users",HttpRequest::Method::GET,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                HttpResponse response(HttpResponse::StatusCode::FailedDependency);
                    sendResponse(response,request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                const QMap<QString,QString> queryMap {getQueryMap(request)};
                {
                    QString lastError {};
                    QJsonObject outUsersObject {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->getUsersObject(queryMap,requesterId,outUsersObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QJsonDocument(outUsersObject).toJson(),HttpResponse::StatusCode::Ok);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
    {// '/api/v1/u-auth/users/<arg> rule for GET
        auto handler {[&](const QString& userId){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/users/<arg>",HttpRequest::Method::GET,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                const QString userId {match.captured(1)};
                {
                    QString lastError {};
                    QJsonObject outUserObject {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->getUserObject(userId,requesterId,outUserObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QJsonDocument(outUserObject).toJson(),HttpResponse::StatusCode::Ok);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
    {// '/api/v1/u-auth/users/<arg>' rule for PUT
        auto handler {[&](const QString& userId){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/users/<arg>",HttpRequest::Method::PUT,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                const QString userId {match.captured(1)};
                {
                    QString lastError {};
                    QJsonObject outUserObject {};
                    const QJsonObject inUserObject {QJsonDocument::fromJson(request.body()).object()};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->putUserObject(userId,requesterId,inUserObject,outUserObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QJsonDocument(outUserObject).toJson(),HttpResponse::StatusCode::Ok);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
    {// '/api/v1/u-auth/users' rule for POST
        auto handler {[&](){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/users",HttpRequest::Method::POST,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                {
                    QString lastError {};
                    QJsonObject outUserObject {};
                    const QJsonObject inUserObject {QJsonDocument::fromJson(request.body()).object()};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->postUserObject(requesterId,inUserObject,outUserObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QJsonDocument(outUserObject).toJson(),HttpResponse::StatusCode::Created);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Conflict);
                                sendResponse(response,request,socket);
                            }
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
    {// '/api/v1/u-auth/users/<arg>' rule for DELETE
        auto handler {[&](const QString& userId){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/users/<arg>",HttpRequest::Method::DELETE,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                const QString userId {match.captured(1)};
                {
                    QString lastError {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->deleteUserObject(userId,requesterId,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QByteArray{},HttpResponse::StatusCode::NoContent);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
}

void HttpClient::addRolePermRules(const HttpRequest &request, QAbstractSocket *socket)
{
    {// '/api/v1/u-auth/roles-permissions' rule for GET
        auto handler {[&](){}};
        using ViewHandler=decltype(handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/roles-permissions",HttpRequest::Method::GET,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                logRequest(request);
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                const QMap<QString,QString> queryMap {getQueryMap(request)};
                {
                    QString lastError {};
                    QJsonObject outRolePermsObject {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->getRolePermsObject(queryMap,requesterId,outRolePermsObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QJsonDocument(outRolePermsObject).toJson(),HttpResponse::StatusCode::Ok);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
    {// '/api/v1/u-auth/roles-permissions/<arg>/ rule for GET
        auto handler {[&](const QString& rolePermId){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/roles-permissions/<arg>",HttpRequest::Method::GET,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                logRequest(request);
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                const QString userId {match.captured(1)};
                {
                    QString lastError {};
                    QJsonObject outRolePermObject {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->getRolePermObject(userId,requesterId,outRolePermObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QJsonDocument(outRolePermObject).toJson(),HttpResponse::StatusCode::Ok);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
    {// '/api/v1/u-auth/roles-permissions/<arg>' rule for PUT
        auto handler {[&](const QString& rolePermId){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/roles-permissions/<arg>",HttpRequest::Method::PUT,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                logRequest(request);
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                const QString rolePermId {match.captured(1)};
                {
                    QString lastError {};
                    QJsonObject outRolePermObject {};
                    const QJsonObject inRolePermObject {QJsonDocument::fromJson(request.body()).object()};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->putRolePermObject(rolePermId,requesterId,inRolePermObject,outRolePermObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QJsonDocument(outRolePermObject).toJson(),HttpResponse::StatusCode::Ok);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
    {// '/api/v1/u-auth/roles-permissions' rule for POST
        auto handler {[&](){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/roles-permissions",HttpRequest::Method::POST,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                {
                    QString lastError {};
                    QJsonObject outRolePermObject {};
                    const QJsonObject inRolePermObject {QJsonDocument::fromJson(request.body()).object()};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->postRolePermObject(requesterId,inRolePermObject,outRolePermObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QJsonDocument(outRolePermObject).toJson(),HttpResponse::StatusCode::Created);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Conflict);
                                sendResponse(response,request,socket);
                            }
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
    {// '/api/v1/u-auth/roles-permissions/' rule for POST
        auto handler {[&](){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/roles-permissions/",HttpRequest::Method::POST,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                {
                    QString lastError {};
                    QJsonObject outRolePermObject {};
                    const QJsonObject inRolePermObject {QJsonDocument::fromJson(request.body()).object()};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->postRolePermObject(requesterId,inRolePermObject,outRolePermObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QJsonDocument(outRolePermObject).toJson(),HttpResponse::StatusCode::Created);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Conflict);
                                sendResponse(response,request,socket);
                            }
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
    {// '/api/v1/u-auth/roles-permissions/<arg>' rule for DELETE
        auto handler {[&](const QString& rolePermId){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/roles-permissions/<arg>",HttpRequest::Method::DELETE,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                const QString rolePermId {match.captured(1)};
                {
                    QString lastError {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->deleteRolePermObject(rolePermId,requesterId,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QByteArray{},HttpResponse::StatusCode::NoContent);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::UnprocessableEntity);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
}

void HttpClient::addParentChildRules(const HttpRequest &request, QAbstractSocket *socket)
{
    {// '/api/v1/u-auth/roles-permissions/<arg>/add-child/<arg>' rule for PUT
        auto handler {[&](const QString& parentRolePermId,const QString& childRolePermId){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/roles-permissions/<arg>/add-child/<arg>",HttpRequest::Method::PUT,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }
                const QString requesterId {getRequesterId(request)};
                const QString parentRolePermId {match.captured(1)};
                const QString childRolePermId {match.captured(2)};
                {
                    QString lastError {};
                    QJsonObject outRolePermObject {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->putRolePermChild(parentRolePermId,childRolePermId,requesterId,outRolePermObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QJsonDocument(outRolePermObject).toJson(),HttpResponse::StatusCode::Ok);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
    {// '/api/v1/u-auth/roles-permissions/<arg>/remove-child/<arg>' rule for DELETE
        auto handler {[&](const QString& parentRolePermId,const QString& childRolePermId){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/roles-permissions/<arg>/remove-child/<arg>",HttpRequest::Method::DELETE,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                const QString parentRolePermId {match.captured(1)};
                const QString childRolePermId {match.captured(2)};
                {
                    QString lastError {};
                    QJsonObject outRolePermObject {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->deleteRolePermChild(parentRolePermId,childRolePermId,requesterId,outRolePermObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NoContent);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
}

void HttpClient::addUserRolePermRules(const HttpRequest &request, QAbstractSocket *socket)
{
    {// '/api/v1/u-auth/users/<arg>/roles-permissions' rule for GET
        auto handler {[&](const QString& userId){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/users/<arg>/roles-permissions",HttpRequest::Method::GET,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                const QString userId {match.captured(1)};
                const QMap<QString,QString> queryMap {getQueryMap(request)};
                {
                    QString lastError {};
                    QJsonObject outRolePermsObject {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->getUserRolePermsObject(userId,queryMap,requesterId,outRolePermsObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QJsonDocument(outRolePermsObject).toJson(),HttpResponse::StatusCode::Ok);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
    {// '/api/v1/u-auth/roles-permissions/<arg>/associated-users' rule for GET
        auto handler {[&](const QString& rolePermId){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/roles-permissions/<arg>/associated-users",HttpRequest::Method::GET,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                const QString rolePermId {match.captured(1)};
                const QMap<QString,QString> queryMap {getQueryMap(request)};
                {
                    QString lastError {};
                    QJsonObject outUsersObject {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->getRolePermUsersObject(rolePermId,queryMap,requesterId,outUsersObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QJsonDocument(outUsersObject).toJson(),HttpResponse::StatusCode::Ok);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
    {// '/api/v1/u-auth/roles-permissions/<arg>/detail' rule for GET
        auto handler {[&](const QString& rolePermId){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/roles-permissions/<arg>/detail",HttpRequest::Method::GET,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                const QString rolePermId {match.captured(1)};
                {
                    QString lastError {};
                    QJsonObject outRolePermObject {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->getRolePermDetailObject(rolePermId,requesterId,outRolePermObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QJsonDocument(outRolePermObject).toJson(),HttpResponse::StatusCode::Ok);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
}

void HttpClient::addAuthzRules(const HttpRequest &request, QAbstractSocket *socket)
{
    {// '/api/v1/u-auth/authz/<arg>/authorized-to/<arg>' rule for GET
        auto handler {[&](const QString& userId,const QString& rolePermIdent){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/authz/<arg>/authorized-to/<arg>",HttpRequest::Method::GET,
                                     [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString userId {match.captured(1)};
                const QString rolePermIdent {match.captured(2)};
                {
                    QString lastError {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->getAuthzCheck(userId,rolePermIdent,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response {HttpLiterals::contentTypeJson(),"true",HttpResponse::StatusCode::Ok};
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response {HttpLiterals::contentTypeJson(),"false",HttpResponse::StatusCode::Ok};
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                 HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                 sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                        default:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
    {// '/api/v1/u-auth/authz' rule for GET
        auto handler {[&](){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/authz",HttpRequest::Method::GET,
                                     [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QMap<QString,QString> queryMap {getQueryMap(request)};
                {
                    QString lastError {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->getAuthzCheck(queryMap,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response {HttpLiterals::contentTypeJson(),"true",HttpResponse::StatusCode::Ok};
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response {HttpLiterals::contentTypeJson(),"false",HttpResponse::StatusCode::Ok};
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                 HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                 sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                        default:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
}

void HttpClient::addAuthzManageRules(const HttpRequest &request, QAbstractSocket *socket)
{
    {// '/api/v1/u-auth/authz/manage/<arg>/assign/<arg>' rule for POST
        auto handler {[&](const QString& userId,const QString& rolePermId){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/authz/manage/<arg>/assign/<arg>",HttpRequest::Method::POST,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                const QString userId {match.captured(1)};
                const QString rolePermId {match.captured(2)};
                {
                    QString lastError {};
                    QJsonObject outRolePermObject {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->postAuthzManage(userId,rolePermId,requesterId,outRolePermObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpLiterals::contentTypeJson(),QJsonDocument(outRolePermObject).toJson(),HttpResponse::StatusCode::Created);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
    {// '/api/v1/u-auth/authz/manage/<arg>/revoke/<arg>' rule for DELETE
        auto handler {[&](const QString& userId,const QString& rolePermId){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/authz/manage/<arg>/revoke/<arg>",HttpRequest::Method::DELETE,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {

                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }

                const QString requesterId {getRequesterId(request)};
                const QString userId {match.captured(1)};
                const QString rolePermId {match.captured(2)};
                {
                    QString lastError {};
                    QJsonObject outRolePermObject {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->deleteAuthzManage(userId,rolePermId,requesterId,outRolePermObject,lastError)};
                    switch(sqlStatus){
                        case SQL_Status::Success:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NoContent);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::BadRequest:
                            {
                                HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Unauthorized:
                            {
                                HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                                sendResponse(response,request,socket);
                            }
                            break;
                        case SQL_Status::Conflict:
                        case SQL_Status::NotFound:
                        case SQL_Status::UnprocessableEntity:
                            {
                                HttpResponse response(HttpResponse::StatusCode::NotFound);
                                sendResponse(response,request,socket);
                            }
                            break;
                    }
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
}

void HttpClient::addCertificateRules(const HttpRequest &request, QAbstractSocket *socket)
{
    {// '/api/v1/u-auth/certificates/user/<arg>' rule for POST
        auto handler {[&](const QString& userId){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/certificates/user/<arg>",HttpRequest::Method::POST,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }
                const QString requesterId {getRequesterId(request)};
                const QJsonObject inJsonObject {QJsonDocument::fromJson(request.body()).object()};
                if(!inJsonObject.contains("password")){
                    HttpResponse response(HttpLiterals::contentTypeText(),
                                          QByteArrayLiteral("Request body does not contains 'password' key!"),
                                          HttpResponse::StatusCode::BadRequest);
                    sendResponse(response,request,socket);
                    return true;
                }
                int validDays {0};
                if(inJsonObject.contains("valid_days")){
                    validDays=inJsonObject.value("valid_days").toInt();
                    if((validDays <= 0) || (validDays > 365 * 5)){
                        HttpResponse response(HttpLiterals::contentTypeText(),
                                              QStringLiteral("Parameter 'valid_days' incorrect value: %1").arg(validDays).toUtf8(),
                                              HttpResponse::StatusCode::BadRequest);
                        sendResponse(response,request,socket);
                        return true;
                    }
                }
                const QString userId {match.captured(1)};
                const QString userCertPass {inJsonObject.value("password").toString()};
                {//authorize
                    QString lastError{};
                    const QString rolePermIdent {"user_certificate:create"};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->getAuthzCheck(requesterId,rolePermIdent,lastError)};
                    if(sqlStatus!=SQL_Status::Success){
                        HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                        sendResponse(response,request,socket);
                        return true;
                    }
                }
                QString userEmail {};
                {//get userEmail
                    QString lastError {};
                    QJsonObject outUserObject {};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->getUserObject(userId,requesterId,outUserObject,lastError)};
                    if(sqlStatus!=SQL_Status::Success){
                        HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                        sendResponse(response,request,socket);
                        return true;
                    }
                    userEmail=outUserObject.value("email").toString();
                }
                {//create userCert response
                    QString lastError {};
                    QByteArray userCertData {};
                    const QString userCertName   {QString("%1.pfx").arg(userEmail)};
                    const QString caCertPath     {appSettingsPtr_->value("UA_CA_CRT_PATH").toString()};
                    const QString publicKeyPath  {appSettingsPtr_->value("UA_SIGNING_CA_CRT_PATH").toString()};
                    const QString privateKeyPath {appSettingsPtr_->value("UA_SIGNING_CA_KEY_PATH").toString()};
                    const QString privateKeyPass {appSettingsPtr_->value("UA_SIGNING_CA_KEY_PASS").toString()};
                    CryptoGenerator cryptoGenerator {};
                    const bool isUserCertOk {cryptoGenerator.createUserCert(userId,caCertPath,publicKeyPath,
                                                             privateKeyPath,privateKeyPass,
                                                             userCertPass,userCertName,userCertData,lastError,validDays)};
                    if(!isUserCertOk){
                        HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                        sendResponse(response,request,socket);
                        return true;
                    }
                    const QString contentDispositionHeader {QStringLiteral("attachment;filename=%1.pfx").arg(userEmail)};
                    HttpResponse response {HttpLiterals::contentTypePkcs(),userCertData,HttpResponse::StatusCode::Created};
                    response.setHeader("Content-Length",QByteArray::number(userCertData.size()));
                    response.setHeader("Content-Disposition",contentDispositionHeader.toUtf8());
                    sendResponse(response,request,socket);
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
    {// '/api/v1/u-auth/certificates/agent/sign-csr' rule for POST
        auto handler {[&](){}};
        using ViewHandler=decltype (handler);
        auto rule=new HttpRouterRule("/api/v1/u-auth/certificates/agent/sign-csr",HttpRequest::Method::POST,
                                               [&] (QRegularExpressionMatch &match,const HttpRequest &request,QAbstractSocket *socket) {
                if(!isIntegrityOk_){
                    sendResponse(HttpResponse(HttpResponse::StatusCode::FailedDependency),request,socket);
                    return true;
                }
                const QString requesterId {getRequesterId(request)};
                {//authorize
                    QString lastError{};
                    const QString rolePermIdent {"agent_certificate:create"};
                    const SQL_Status sqlStatus {sqlHandlerPtr_->getAuthzCheck(requesterId,rolePermIdent,lastError)};
                    if(sqlStatus!=SQL_Status::Success){
                        HttpResponse response(HttpResponse::StatusCode::Unauthorized);
                        sendResponse(response,request,socket);
                        return true;
                    }
                }
                {
                    QString lastError {};
                    QByteArray agentCertData {};
                    const QByteArray agentReqData {request.body()};
                    const QString publicKeyPath  {appSettingsPtr_->value("UA_SIGNING_CA_CRT_PATH").toString()};
                    const QString privateKeyPath {appSettingsPtr_->value("UA_SIGNING_CA_KEY_PATH").toString()};
                    const QString privateKeyPass {appSettingsPtr_->value("UA_SIGNING_CA_KEY_PASS").toString()};
                    CryptoGenerator cryptoGenerator {};
                    const bool isAgentCertOk {cryptoGenerator.createAgentCert(publicKeyPath,privateKeyPath,
                                                                              privateKeyPass,agentReqData,
                                                                              agentCertData,lastError)};
                    if(!isAgentCertOk){
                        HttpResponse response(HttpLiterals::contentTypeText(),lastError.toUtf8(),HttpResponse::StatusCode::BadRequest);
                        sendResponse(response,request,socket);
                        return true;
                    }
                    const QByteArray contentDispositionHeader {"attachment;filename=agent_certificate.pem"};
                    HttpResponse response {HttpLiterals::contentTypePem(),agentCertData,HttpResponse::StatusCode::Created};
                    response.setHeader("Content-Length",QByteArray::number(agentCertData.size()));
                    response.setHeader("Content-Disposition",contentDispositionHeader);
                    sendResponse(response,request,socket);
                }
                return true;
        });
        router_.addRule<ViewHandler>(rule);
    }
}

void HttpClient::logRequest(const HttpRequest &request)
{
    const QString logMsg {QStringLiteral("[REQUEST]; [URL]: %1; [METHOD]: %2; [BODY]: %3").
                arg(request.url().toString()).arg(methodToText(request.method())).arg(QString(request.body()))};
    qDebug(qPrintable(logMsg));
}

void HttpClient::logResponse(const HttpResponse &response)
{
    const QString logMsg {QStringLiteral("[RESPONSE]; [MIME_TYPE]: %1; [DATA]: %2").
                arg(QString(response.mimeType())).arg(QString(response.data()))};
    qDebug(qPrintable(logMsg));
}

QString HttpClient::methodToText(HttpRequest::Method method)
{
    switch(method){
    case HttpRequest::Method::GET:
        return "GET";
    case HttpRequest::Method::PUT:
        return "PUT";
    case HttpRequest::Method::DELETE:
        return "DELETE";
    case HttpRequest::Method::POST:
        return "POST";
    case HttpRequest::Method::HEAD:
        return "HEAD";
    case HttpRequest::Method::OPTIONS:
        return "OPTIONS";
    case HttpRequest::Method::PATCH:
        return "PATCH";
    case HttpRequest::Method::All:
        return "All";
    case HttpRequest::Method::Unknown:
        return "UNKNOWN";
    default:
        return "UNKNOWN";
    }
}

QString HttpClient::getRequesterId(const HttpRequest &request)
{
    const QVariantMap headersMap {request.headers()};
    const auto it {headersMap.find("X-Client-Cert-Dn")};
    if(it!=headersMap.end()){
        return it.value().toString();
    }
    return QString{};
}

QMap<QString, QString> HttpClient::getQueryMap(const HttpRequest &request)
{
    const QUrlQuery urlQuery {request.query()};
    auto queryItems {urlQuery.queryItems()};
    QMap<QString,QString> queryMap {};
    for(const auto& queryItem: queryItems){
        queryMap.insert(queryItem.first,queryItem.second);
    };
    return queryMap;
}

void HttpClient::run()
{
    sqlHandlerPtr_.reset(new SQL_Handler{appSettingsPtr_});
    auto socket {sslEnable_ ? new QSslSocket : new QTcpSocket};
    socket->setSocketDescriptor(socketDescriptor_);
    if(sslEnable_){
        auto sslSocket {qobject_cast<QSslSocket*>(socket)};
        sslSocket->setSslConfiguration(sslConfiguration_);
    }
    HttpRequest* request {new HttpRequest(socket->peerAddress())};
    http_parser_init(&request->d->httpParser,HTTP_REQUEST);

    QObject::connect(socket,&QTcpSocket::readyRead,
                     [this, request, socket](){
        handleReadyRead(socket,request);
    });
    QObject::connect(socket, &QTcpSocket::disconnected, [this,socket,request](){
        socket->deleteLater();
        delete request;
        QThread::quit();
    });
    QThread::exec();
}

HttpClient::HttpClient(qintptr socketDescriptor, bool isIntegrityOk, QSharedPointer<QSettings> appSettingsPtr, QObject *parent)
    :QThread{parent},socketDescriptor_{socketDescriptor},isIntegrityOk_{isIntegrityOk},appSettingsPtr_{appSettingsPtr}
{
}

HttpClient::~HttpClient()
{
    QThread::quit();
    QThread::wait();
}

void HttpClient::sslSetup(const QSslConfiguration &sslConfiguration)
{
    sslConfiguration_=sslConfiguration;
    sslEnable_=true;
}

void HttpClient::handleReadyRead(QAbstractSocket *socket, HttpRequest *request)
{
    Q_ASSERT(socket);
    Q_ASSERT(request);

    if(request->d->state==HttpRequestPrivate::State::OnMessageComplete){
        request->d->clear();
    }
    if(!request->d->parse(socket)){
        socket->disconnect();
        return;
    }
    if(!request->d->httpParser.upgrade && request->d->state != HttpRequestPrivate::State::OnMessageComplete){
        return; // Partial read
    }
    logRequest(*request);
    if(!handleRequest(*request,socket)){
        sendResponse(HttpResponse(HttpResponse::StatusCode::NotFound),*request,socket);
    }
    socket->disconnectFromHost();
}

bool HttpClient::handleRequest(const HttpRequest &request, QAbstractSocket *socket)
{
    addUserRules(request,socket);
    addRolePermRules(request,socket);
    addParentChildRules(request,socket);
    addParentChildRules(request,socket);
    addUserRolePermRules(request,socket);
    addAuthzRules(request,socket);
    addAuthzManageRules(request,socket);
    addCertificateRules(request,socket);
    return router_.handleRequest(request,socket); 
}

void HttpClient::sendResponse(const HttpResponse &response, const HttpRequest &request, QAbstractSocket *socket)
{
    logResponse(response);
    response.write(HttpResponder(request, socket));
}

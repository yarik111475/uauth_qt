/****************************************************************************
**
** Copyright (C) 2019 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtHttpServer module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:GPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 3 or (at your option) any later version
** approved by the KDE Free Qt Foundation. The licenses are as published by
** the Free Software Foundation and appearing in the file LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

#ifndef QABSTRACTHTTPSERVER_H
#define QABSTRACTHTTPSERVER_H

#include <QtCore/qobject.h>

#include "qthttpserverglobal.h"

#include <QtNetwork/qhostaddress.h>

#if defined(QT_WEBSOCKETS_LIB)
#include <QtWebSockets/qwebsocketserver.h>
#endif // defined(QT_WEBSOCKETS_LIB)

#if QT_CONFIG(ssl)
#include "sslserver/qsslserver.h"
#include <QSslCertificate>
#include <QSslKey>
#endif

QT_BEGIN_NAMESPACE

class QHttpServerRequest;
class QHttpServerResponder;
class QTcpServer;
class QTcpSocket;
class QWebSocket;

class Q_HTTPSERVER_EXPORT QAbstractHttpServer : public QObject
{
    Q_OBJECT

public:
    QAbstractHttpServer(QObject *parent = nullptr);

    int listen(const QHostAddress &address = QHostAddress::Any, quint16 port = 0);

    void bind(QTcpServer *server = nullptr);
    QVector<QTcpServer *> servers() const;

#if QT_CONFIG(ssl)
    void sslSetup(const QSslCertificate &certificate, const QSslKey &privateKey,
                  QSsl::SslProtocol protocol = QSsl::SecureProtocols);
    void sslSetup(const QSslConfiguration &sslConfiguration);
#endif

Q_SIGNALS:
    void missingHandler(const QHttpServerRequest &request, QTcpSocket *socket);

#if defined(QT_WEBSOCKETS_LIB)
    void newWebSocketConnection();

public:
    bool hasPendingWebSocketConnections() const;
    QWebSocket *nextPendingWebSocketConnection();
#endif // defined(QT_WEBSOCKETS_LIB)

protected:
    virtual bool handleRequest(const QHttpServerRequest &request, QTcpSocket *socket) = 0;
    static QHttpServerResponder makeResponder(const QHttpServerRequest &request,
                                              QTcpSocket *socket);

private:
#if defined(QT_WEBSOCKETS_LIB)
    QWebSocketServer websocketServer_ {
        QLatin1String("QtHttpServer"),
        QWebSocketServer::NonSecureMode
    };
#endif // defined(QT_WEBSOCKETS_LIB)

    void handleNewConnections();
    void handleReadyRead(QTcpSocket *socket,
                         QHttpServerRequest *request);

#if QT_CONFIG(ssl)
    QSslConfiguration sslConfiguration_;
    bool sslEnabled_ = false;
#endif
};

QT_END_NAMESPACE

#endif // QABSTRACTHTTPSERVER_H

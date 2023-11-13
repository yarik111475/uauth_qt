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

#ifndef QHTTPSERVERREQUEST_H
#define QHTTPSERVERREQUEST_H

#include <QtCore/qdebug.h>
#include <QtCore/qglobal.h>
#include <QtCore/qurl.h>
#include <QtCore/qurlquery.h>
#include <QtNetwork/qhostaddress.h>


class QRegularExpression;
class QString;
class QTcpSocket;

class HttpRequestPrivate;
class HttpRequest
{
    friend class HttpClient;
    friend class HttpResponse;

    Q_GADGET

public:
    virtual ~HttpRequest();

    enum class Method
    {
        Unknown = 0x0000,
        Get     = 0x0001,
        Put     = 0x0002,
        Delete  = 0x0004,
        Post    = 0x0008,
        Head    = 0x0010,
        Options = 0x0020,
        Patch   = 0x0040,

        All = Get | Put | Delete | Post | Head | Options | Patch,

        // Include upper-case aliases for the sake of parsing from strings:
        GET     = Get,
        PUT     = Put,
        DELETE  = Delete,
        POST    = Post,
        HEAD    = Head,
        OPTIONS = Options,
        PATCH   = Patch
    };
    Q_ENUM(Method)
    Q_DECLARE_FLAGS(Methods, Method)
    Q_FLAG(Methods)

    QByteArray value(const QByteArray &key) const;
    QUrl url() const;
    QUrlQuery query() const;
    Method method() const;
    QVariantMap headers() const;
    QByteArray body() const;
    QHostAddress remoteAddress() const;

protected:
    HttpRequest(const HttpRequest &other);

private:
    friend QDebug operator<<(QDebug debug, const HttpRequest &request);
    explicit HttpRequest(const QHostAddress &remoteAddress);

    QSharedPointer<HttpRequestPrivate> d;
};

#endif // QHTTPSERVERREQUEST_H

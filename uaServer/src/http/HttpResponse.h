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

#ifndef QHTTPSERVERRESPONSE_H
#define QHTTPSERVERRESPONSE_H

#include "HttpResponder.h"

#include <QtCore/qscopedpointer.h>

class QJsonObject;

class HttpResponsePrivate;
class HttpResponse
{
    Q_DECLARE_PRIVATE(HttpResponse)

public:
    using StatusCode = HttpResponder::StatusCode;

    HttpResponse() = delete;
    HttpResponse(const HttpResponse &other) = delete;
    HttpResponse& operator=(const HttpResponse &other) = delete;

    HttpResponse(HttpResponse &&other);
    HttpResponse& operator=(HttpResponse &&other) = delete;

    HttpResponse(const StatusCode statusCode);

    HttpResponse(const char *data);

    HttpResponse(const QString &data);

    explicit HttpResponse(const QByteArray &data);
    explicit HttpResponse(QByteArray &&data);

    HttpResponse(const QJsonObject &data);
    HttpResponse(const QJsonArray &data);

    HttpResponse(const QByteArray &mimeType,
                        const QByteArray &data,
                        const StatusCode status = StatusCode::Ok);
    HttpResponse(QByteArray &&mimeType,
                        const QByteArray &data,
                        const StatusCode status = StatusCode::Ok);
    HttpResponse(const QByteArray &mimeType,
                        QByteArray &&data,
                        const StatusCode status = StatusCode::Ok);
    HttpResponse(QByteArray &&mimeType,
                        QByteArray &&data,
                        const StatusCode status = StatusCode::Ok);

    virtual ~HttpResponse();
    static HttpResponse fromFile(const QString &fileName);

    QByteArray data() const;

    QByteArray mimeType() const;

    StatusCode statusCode() const;

    void addHeader(QByteArray &&name, QByteArray &&value);
    void addHeader(QByteArray &&name, const QByteArray &value);
    void addHeader(const QByteArray &name, QByteArray &&value);
    void addHeader(const QByteArray &name, const QByteArray &value);

    void addHeaders(HttpResponder::HeaderList headers);

    template<typename Container>
    void addHeaders(const Container &headers)
    {
        for (const auto &header : headers)
            addHeader(header.first, header.second);
    }

    void clearHeader(const QByteArray &name);
    void clearHeaders();

    void setHeader(QByteArray &&name, QByteArray &&value);
    void setHeader(QByteArray &&name, const QByteArray &value);
    void setHeader(const QByteArray &name, QByteArray &&value);
    void setHeader(const QByteArray &name, const QByteArray &value);

    void setHeaders(HttpResponder::HeaderList headers);

    bool hasHeader(const QByteArray &name) const;
    bool hasHeader(const QByteArray &name, const QByteArray &value) const;

    QVector<QByteArray> headers(const QByteArray &name) const;

    virtual void write(HttpResponder &&responder) const;

private:
    HttpResponse(const QByteArray &mimeType,
                        HttpResponsePrivate *d);

    HttpResponse(QByteArray &&mimeType,
                        HttpResponsePrivate *d);

    QScopedPointer<HttpResponsePrivate> d_ptr;
};

#endif   // QHTTPSERVERRESPONSE_H

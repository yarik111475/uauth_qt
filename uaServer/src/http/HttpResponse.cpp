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

#include "HttpResponse.h"
#include "HttpLiterals_p.h"
#include "HttpResponse_p.h"
#include "HttpResponder_p.h"

#include <QtCore/qfile.h>
#include <QtCore/qjsondocument.h>
#include <QtCore/qjsonobject.h>
#include <QtCore/qmimedatabase.h>

HttpResponse::HttpResponse(HttpResponse &&other)
    : d_ptr(other.d_ptr.take())
{
}

HttpResponse::HttpResponse(
        const HttpResponse::StatusCode statusCode)
    : HttpResponse(HttpLiterals::contentTypeXEmpty(),
                          QByteArray(),
                          statusCode)
{
}

HttpResponse::HttpResponse(const char *data)
    : HttpResponse(QByteArray::fromRawData(data, qstrlen(data)))
{
}

HttpResponse::HttpResponse(const QString &data)
    : HttpResponse(data.toUtf8())
{
}

HttpResponse::HttpResponse(const QByteArray &data)
    : HttpResponse(QMimeDatabase().mimeTypeForData(data).name().toLocal8Bit(), data)
{
}

HttpResponse::HttpResponse(QByteArray &&data)
    : HttpResponse(
            QMimeDatabase().mimeTypeForData(data).name().toLocal8Bit(),
            std::move(data))
{
}

HttpResponse::HttpResponse(const QJsonObject &data)
    : HttpResponse(HttpLiterals::contentTypeJson(),
                          QJsonDocument(data).toJson(QJsonDocument::Compact))
{
}

HttpResponse::HttpResponse(const QJsonArray &data)
    : HttpResponse(HttpLiterals::contentTypeJson(),
                          QJsonDocument(data).toJson(QJsonDocument::Compact))
{
}

HttpResponse::HttpResponse(const QByteArray &mimeType,
                                         const QByteArray &data,
                                         const StatusCode status)
    : HttpResponse(mimeType,
                          new HttpResponsePrivate{data, status, {}})
{
}

HttpResponse::HttpResponse(QByteArray &&mimeType,
                                         const QByteArray &data,
                                         const StatusCode status)
    : HttpResponse(std::move(mimeType),
                          new HttpResponsePrivate{data, status, {}})
{
}

HttpResponse::HttpResponse(const QByteArray &mimeType,
                                         QByteArray &&data,
                                         const StatusCode status)
    : HttpResponse(
            mimeType,
            new HttpResponsePrivate{std::move(data), status, {}})
{
}

HttpResponse::HttpResponse(QByteArray &&mimeType,
                                         QByteArray &&data,
                                         const StatusCode status)
    : HttpResponse(
            std::move(mimeType),
            new HttpResponsePrivate{std::move(data), status, {}})
{
}

HttpResponse::~HttpResponse()
{
}

HttpResponse HttpResponse::fromFile(const QString &fileName)
{
    QFile file(fileName);
    if (!file.open(QFile::ReadOnly))
        return HttpResponse(StatusCode::NotFound);
    const QByteArray data = file.readAll();
    file.close();
    const QByteArray mimeType = QMimeDatabase().mimeTypeForFileNameAndData(fileName, data).name().toLocal8Bit();
    return HttpResponse(mimeType, data);
}

HttpResponse::HttpResponse(const QByteArray &mimeType,
                                         HttpResponsePrivate *d)
    : d_ptr(d)
{
    setHeader(HttpLiterals::contentTypeHeader(), mimeType);
}

HttpResponse::HttpResponse(QByteArray &&mimeType,
                                         HttpResponsePrivate *d)
    : d_ptr(d)
{
    setHeader(HttpLiterals::contentTypeHeader(),
              std::move(mimeType));
}

/*!
    Returns response body.
*/
QByteArray HttpResponse::data() const
{
    Q_D(const HttpResponse);
    return d->data;
}

HttpResponse::StatusCode HttpResponse::statusCode() const
{
    Q_D(const HttpResponse);
    return d->statusCode;
}

/*!
    Returns HTTP "Content-Type" header.

    \note Default value is "text/html"
*/
QByteArray HttpResponse::mimeType() const
{
    Q_D(const HttpResponse);
    const auto res = d->headers.find(
            HttpLiterals::contentTypeHeader());
    if (res == d->headers.end())
        return HttpLiterals::contentTypeTextHtml();

    return res->second;
}

/*!
    Adds the HTTP header with name \a name and value \a value,
    does not override any previously set headers.
*/
void HttpResponse::addHeader(QByteArray &&name, QByteArray &&value)
{
    Q_D(HttpResponse);
    d->headers.emplace(std::move(name), std::move(value));
}

/*!
    Adds the HTTP header with name \a name and value \a value,
    does not override any previously set headers.
*/
void HttpResponse::addHeader(QByteArray &&name, const QByteArray &value)
{
    Q_D(HttpResponse);
    d->headers.emplace(std::move(name), value);
}

/*!
    Adds the HTTP header with name \a name and value \a value,
    does not override any previously set headers.
*/
void HttpResponse::addHeader(const QByteArray &name, QByteArray &&value)
{
    Q_D(HttpResponse);
    d->headers.emplace(name, std::move(value));
}

/*!
    Adds the HTTP header with name \a name and value \a value,
    does not override any previously set headers.
*/
void HttpResponse::addHeader(const QByteArray &name, const QByteArray &value)
{
    Q_D(HttpResponse);
    d->headers.emplace(name, value);
}

void HttpResponse::addHeaders(HttpResponder::HeaderList headers)
{
    for (auto &&header : headers)
        addHeader(header.first, header.second);
}

/*!
    Removes the HTTP header with name \a name.
*/
void HttpResponse::clearHeader(const QByteArray &name)
{
    Q_D(HttpResponse);
    d->headers.erase(name);
}

/*!
    Removes all HTTP headers.
*/
void HttpResponse::clearHeaders()
{
    Q_D(HttpResponse);
    d->headers.clear();
}

/*!
    Sets the HTTP header with name \a name and value \a value,
    overriding any previously set headers.
*/
void HttpResponse::setHeader(QByteArray &&name, QByteArray &&value)
{
    Q_D(HttpResponse);
    clearHeader(name);
    addHeader(std::move(name), std::move(value));
}

/*!
    Sets the HTTP header with name \a name and value \a value,
    overriding any previously set headers.
*/
void HttpResponse::setHeader(QByteArray &&name, const QByteArray &value)
{
    Q_D(HttpResponse);
    clearHeader(name);
    addHeader(std::move(name), value);
}

/*!
    Sets the HTTP header with name \a name and value \a value,
    overriding any previously set headers.
*/
void HttpResponse::setHeader(const QByteArray &name, QByteArray &&value)
{
    Q_D(HttpResponse);
    clearHeader(name);
    addHeader(name, std::move(value));
}

/*!
    Sets the HTTP header with name \a name and value \a value,
    overriding any previously set headers.
*/
void HttpResponse::setHeader(const QByteArray &name, const QByteArray &value)
{
    Q_D(HttpResponse);
    clearHeader(name);
    addHeader(name, value);
}

/*!
    Sets the headers \a headers, overriding any previously set headers.
*/
void HttpResponse::setHeaders(HttpResponder::HeaderList headers)
{
    for (auto &&header : headers)
        setHeader(header.first, header.second);
}

/*!
    Returns true if the response contains an HTTP header with name \a name,
    otherwise returns false.
*/
bool HttpResponse::hasHeader(const QByteArray &header) const
{
    Q_D(const HttpResponse);
    return d->headers.find(header) != d->headers.end();
}

/*!
    Returns true if the response contains an HTTP header with name \a name and
    with value \a value, otherwise returns false.
*/
bool HttpResponse::hasHeader(const QByteArray &name,
                                    const QByteArray &value) const
{
    Q_D(const HttpResponse);
    auto range = d->headers.equal_range(name);

    auto condition = [&value] (const std::pair<QByteArray, QByteArray> &pair) {
        return pair.second == value;
    };

    return std::find_if(range.first, range.second, condition) != range.second;
}

/*!
    Returns values of the HTTP header with name \a name
*/
QVector<QByteArray> HttpResponse::headers(const QByteArray &name) const
{
    Q_D(const HttpResponse);

    QVector<QByteArray> results;
    auto range = d->headers.equal_range(name);

    for (auto it = range.first; it != range.second; ++it)
        results.append(it->second);

    return results;
}

/*!
    Writes HTTP response into HttpResponder \a responder.
*/
void HttpResponse::write(HttpResponder &&responder) const
{
    Q_D(const HttpResponse);
    responder.writeStatusLine(d->statusCode);

    for (auto &&header : d->headers)
        responder.writeHeader(header.first, header.second);

    responder.writeHeader(HttpLiterals::contentLengthHeader(),
                          QByteArray::number(d->data.size()));

    responder.writeBody(d->data);
}


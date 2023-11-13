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

#include "HttpRequest.h"
#include "HttpRequest_p.h"

#include <QtCore/qdebug.h>
#include <QtCore/qloggingcategory.h>
#include <QtNetwork/qtcpsocket.h>
#if QT_CONFIG(ssl)
#include <QtNetwork/qsslsocket.h>
#endif

QDebug operator<<(QDebug debug, const HttpRequest &request)
{
    const auto oldSetting = debug.autoInsertSpaces();
    debug.nospace() << "HttpRequest(";
    debug << "(Url: " << request.url() << ")";
    debug << "(Headers: " << request.headers() << ")";
    debug << ')';
    debug.setAutoInsertSpaces(oldSetting);
    return debug.maybeSpace();
}

QDebug operator<<(QDebug debug, const http_parser *const httpParser)
{
    const auto oldSetting = debug.autoInsertSpaces();
    debug.nospace() << "http_parser(" << static_cast<const void *>(httpParser) << ": ";
    debug << "HTTP " << httpParser->http_major << "." << httpParser->http_minor << " "
          << http_method_str(http_method(httpParser->method)) << ')';
    debug.setAutoInsertSpaces(oldSetting);
    return debug.maybeSpace();
}

http_parser_settings HttpRequestPrivate::httpParserSettings {
    &HttpRequestPrivate::onMessageBegin,
    &HttpRequestPrivate::onUrl,
    &HttpRequestPrivate::onStatus,
    &HttpRequestPrivate::onHeaderField,
    &HttpRequestPrivate::onHeaderValue,
    &HttpRequestPrivate::onHeadersComplete,
    &HttpRequestPrivate::onBody,
    &HttpRequestPrivate::onMessageComplete,
    &HttpRequestPrivate::onChunkHeader,
    &HttpRequestPrivate::onChunkComplete
};

HttpRequestPrivate::HttpRequestPrivate(const QHostAddress &remoteAddress)
    : remoteAddress(remoteAddress)
{
    httpParser.data = this;
}

QByteArray HttpRequestPrivate::header(const QByteArray &key) const
{
    return headers.value(headerHash(key)).second;
}

bool HttpRequestPrivate::parse(QIODevice *socket)
{
    const auto fragment = socket->readAll();
    if (fragment.size()) {
#if QT_CONFIG(ssl)
        auto sslSocket = qobject_cast<QSslSocket *>(socket);
        url.setScheme(sslSocket && sslSocket->isEncrypted() ? QStringLiteral("https")
                                                            : QStringLiteral("http"));
#else
        url.setScheme(QStringLiteral("http"));
#endif
        const auto parsed = http_parser_execute(&httpParser,
                                                &httpParserSettings,
                                                fragment.constData(),
                                                size_t(fragment.size()));
        if (int(parsed) < fragment.size()) {
            qWarning("Parse error: %d", httpParser.http_errno);
            return false;
        }
    }
    return true;
}

uint HttpRequestPrivate::headerHash(const QByteArray &key) const
{
    return qHash(key.toLower(), headersSeed);
}

void HttpRequestPrivate::clear()
{
    url.clear();
    lastHeader.clear();
    headers.clear();
    body.clear();
}

bool HttpRequestPrivate::parseUrl(const char *at, size_t length, bool connect, QUrl *url)
{
    static const std::map<std::size_t, std::function<void(const QString &, QUrl *)>> functions {
        { UF_SCHEMA,    [](const QString &string, QUrl *url) { url->setScheme(string); } },
        { UF_HOST,      [](const QString &string, QUrl *url) { url->setHost(string); } },
        { UF_PORT,      [](const QString &string, QUrl *url) { url->setPort(string.toInt()); } },
        { UF_PATH,
          [](const QString &string, QUrl *url) { url->setPath(string, QUrl::TolerantMode); } },
        { UF_QUERY,     [](const QString &string, QUrl *url) { url->setQuery(string); } },
        { UF_FRAGMENT,  [](const QString &string, QUrl *url) { url->setFragment(string); } },
        { UF_USERINFO,  [](const QString &string, QUrl *url) { url->setUserInfo(string); } },
    };
    struct http_parser_url u;
    if (http_parser_parse_url(at, length, connect ? 1 : 0, &u) == 0) {
        for (auto i = 0u; i < UF_MAX; i++) {
            if (u.field_set & (1 << i)) {
                functions.find(i)->second(QString::fromUtf8(at + u.field_data[i].off,
                                                            u.field_data[i].len),
                                          url);
            }
        }
        return true;
    }
    return false;
}

HttpRequestPrivate *HttpRequestPrivate::instance(http_parser *httpParser)
{
    return static_cast<HttpRequestPrivate *>(httpParser->data);
}

int HttpRequestPrivate::onMessageBegin(http_parser *httpParser)
{
    //qDebug() << static_cast<void *>(httpParser);
    instance(httpParser)->state = State::OnMessageBegin;
    return 0;
}

int HttpRequestPrivate::onUrl(http_parser *httpParser, const char *at, size_t length)
{
    //qDebug() << httpParser << QString::fromUtf8(at, int(length));
    auto instance = static_cast<HttpRequestPrivate *>(httpParser->data);
    instance->state = State::OnUrl;
    parseUrl(at, length, false, &instance->url);
    return 0;
}

int HttpRequestPrivate::onStatus(http_parser *httpParser, const char *at, size_t length)
{
    //qDebug() << httpParser << QString::fromUtf8(at, int(length));
    instance(httpParser)->state = State::OnStatus;
    return 0;
}

int HttpRequestPrivate::onHeaderField(http_parser *httpParser, const char *at, size_t length)
{
    //qDebug() << httpParser << QString::fromUtf8(at, int(length));
    auto i = instance(httpParser);
    i->state = State::OnHeaders;
    const auto key = QByteArray(at, int(length));
    i->headers.insert(i->headerHash(key), qMakePair(key, QByteArray()));
    i->lastHeader = key;
    return 0;
}

int HttpRequestPrivate::onHeaderValue(http_parser *httpParser, const char *at, size_t length)
{
    //qDebug() << httpParser << QString::fromUtf8(at, int(length));
    auto i = instance(httpParser);
    i->state = State::OnHeaders;
    Q_ASSERT(!i->lastHeader.isEmpty());
    const auto value = QByteArray(at, int(length));
    i->headers[i->headerHash(i->lastHeader)] = qMakePair(i->lastHeader, value);
    if (i->lastHeader.compare(QByteArrayLiteral("host"), Qt::CaseInsensitive) == 0)
        parseUrl(at, length, true, &i->url);
#if defined(QT_DEBUG)
    i->lastHeader.clear();
#endif
    return 0;
}

int HttpRequestPrivate::onHeadersComplete(http_parser *httpParser)
{
    //qDebug() << httpParser;
    instance(httpParser)->state = State::OnHeadersComplete;
    return 0;
}

int HttpRequestPrivate::onBody(http_parser *httpParser, const char *at, size_t length)
{
    //qDebug() << httpParser << QString::fromUtf8(at, int(length));
    auto i = instance(httpParser);
    i->state = State::OnBody;
    if (i->body.isEmpty()) {
        i->body.reserve(
                static_cast<int>(httpParser->content_length) +
                static_cast<int>(length));
    }

    i->body.append(at, int(length));
    return 0;
}

int HttpRequestPrivate::onMessageComplete(http_parser *httpParser)
{
    //qDebug() << httpParser;
    instance(httpParser)->state = State::OnMessageComplete;
    return 0;
}

int HttpRequestPrivate::onChunkHeader(http_parser *httpParser)
{
    //qDebug() << httpParser;
    instance(httpParser)->state = State::OnChunkHeader;
    return 0;
}

int HttpRequestPrivate::onChunkComplete(http_parser *httpParser)
{
    //qDebug() << httpParser;
    instance(httpParser)->state = State::OnChunkComplete;
    return 0;
}

HttpRequest::HttpRequest(const QHostAddress &remoteAddress) :
    d(new HttpRequestPrivate(remoteAddress))
{}

HttpRequest::HttpRequest(const HttpRequest &other) :
    d(other.d)
{}

HttpRequest::~HttpRequest()
{}

QByteArray HttpRequest::value(const QByteArray &key) const
{
    return d->headers.value(d->headerHash(key)).second;
}

QUrl HttpRequest::url() const
{
    return d->url;
}

QUrlQuery HttpRequest::query() const
{
    return QUrlQuery(d->url.query());
}

HttpRequest::Method HttpRequest::method() const
{
    switch (d->httpParser.method) {
    case HTTP_GET:
        return HttpRequest::Method::Get;
    case HTTP_PUT:
        return HttpRequest::Method::Put;
    case HTTP_DELETE:
        return HttpRequest::Method::Delete;
    case HTTP_POST:
        return HttpRequest::Method::Post;
    case HTTP_HEAD:
        return HttpRequest::Method::Head;
    case HTTP_OPTIONS:
        return HttpRequest::Method::Options;
    case HTTP_PATCH:
        return HttpRequest::Method::Patch;
    default:
        return HttpRequest::Method::Unknown;
    }
}

QVariantMap HttpRequest::headers() const
{
    QVariantMap ret;
    for (auto it = d->headers.cbegin(), end = d->headers.cend(); it != end; ++it)
        ret.insert(it.value().first, it.value().second);
    return ret;
}

QByteArray HttpRequest::body() const
{
    return d->body;
}

QHostAddress HttpRequest::remoteAddress() const
{
    return d->remoteAddress;
}

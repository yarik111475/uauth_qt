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

#ifndef QHTTPSERVERROUTERRULE_H
#define QHTTPSERVERROUTERRULE_H

#include "HttpRequest.h"

#include <QMap>
#include <initializer_list>

QT_BEGIN_NAMESPACE

class QString;
class HttpRequest;
class QAbstractSocket;
class QRegularExpressionMatch;
class HttpRouter;
class HttpRouterRulePrivate;

class HttpRouterRule
{
    Q_DECLARE_PRIVATE(HttpRouterRule)

public:
    using RouterHandler = std::function<void(QRegularExpressionMatch &,
                                             const HttpRequest &,
                                             QAbstractSocket *)>;

    explicit HttpRouterRule(const QString &pathPattern,
                            RouterHandler &&routerHandler);
    explicit HttpRouterRule(const QString &pathPattern,
                            const HttpRequest::Methods methods,
                            RouterHandler &&routerHandler);
    explicit HttpRouterRule(const QString &pathPattern,
                            const char * methods,
                            RouterHandler &&routerHandler);

    HttpRouterRule(HttpRouterRule &&other) = delete;
    HttpRouterRule &operator=(HttpRouterRule &&other) = delete;

    virtual ~HttpRouterRule();

protected:
    bool exec(const HttpRequest &request, QAbstractSocket *socket) const;

    bool hasValidMethods() const;

    bool createPathRegexp(const std::initializer_list<int> &metaTypes,
                          const QMap<int, QLatin1String> &converters);

    virtual bool matches(const HttpRequest &request,
                         QRegularExpressionMatch *match) const;

    HttpRouterRule(HttpRouterRulePrivate *d);

private:
    Q_DISABLE_COPY(HttpRouterRule)
    QScopedPointer<HttpRouterRulePrivate> d_ptr;

    friend class HttpRouter;
};

#endif // QHTTPSERVERROUTERRULE_H

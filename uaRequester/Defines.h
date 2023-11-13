#ifndef DEFINES_H
#define DEFINES_H

#include <QMap>
#include <QString>

enum class HttpVerb
{
    GET,
    PUT,
    POST,
    DELETE,
    NONE
};

inline HttpVerb qstringToVerb(const QString& key){
    const QMap<QString,HttpVerb> methodsMap {
        {"GET",HttpVerb::GET},
        {"PUT",HttpVerb::PUT},
        {"POST",HttpVerb::POST},
        {"DELETE",HttpVerb::DELETE}
    };
    auto it {methodsMap.find(key)};
    if(it!=methodsMap.end()){
        return it.value();
    }
    return HttpVerb::NONE;
}
#endif // DEFINES_H

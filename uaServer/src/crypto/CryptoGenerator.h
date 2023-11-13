#ifndef X509GENERATOR_H
#define X509GENERATOR_H

#include <QString>
#include <QByteArray>

class CryptoGenerator
{
public:
    static bool createAgentCert(const QString& publicKeyPath,const QString privateKeyPath,
                           const QString& privateKeyPass,const QByteArray& agentReqData,
                           QByteArray& agentCertData,QString& lastError);

    static bool createUserCert(const QString& userId,const QString& caCertPath,
                             const QString& publicKeyPath,const QString& privateKeyPath,
                             const QString& privateKeyPass,const QString& userCertPass,
                             const QString& userCertName,QByteArray& userCertData,QString& lastError,long validDays);
};

#endif // X509GENERATOR_H

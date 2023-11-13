#include "CryptoGenerator.h"

#include <QSharedPointer>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/objects.h>
#include <openssl/x509_vfy.h>

bool CryptoGenerator::createAgentCert(const QString &publicKeyPath, const QString privateKeyPath,
                               const QString &privateKeyPass, const QByteArray &agentReqData,
                               QByteArray &agentCertData, QString &lastError)
{
    const QString bugError {"error:00000000:lib(0):func(0):reason(0)"};
    const auto makeError{[](){
            const unsigned long& errCode {ERR_get_error()};
            const QString errText {ERR_error_string(errCode,NULL)};
            return errText;
        }
    };
    int ret {1};
    QSharedPointer<BIO> reqBioPtr {BIO_new(BIO_s_mem()),&BIO_free};
    ret&=BIO_write(reqBioPtr.get(),agentReqData.data(),(int)agentReqData.size());
    if(ret <=0 ){
        lastError=makeError();
        //return false;
    }
    QSharedPointer<X509_REQ> reqPtr {PEM_read_bio_X509_REQ(reqBioPtr.get(),NULL,NULL,NULL),&X509_REQ_free};
    EVP_PKEY* reqKeyPtr {X509_REQ_get0_pubkey(reqPtr.get())};
    X509_NAME* reqNamePtr {X509_REQ_get_subject_name(reqPtr.get())};

    QSharedPointer<BIO> pubKeyBioPtr {BIO_new_file(publicKeyPath.toStdString().c_str(),"r+"),&BIO_free};
    QSharedPointer<X509> pubX509Ptr {PEM_read_bio_X509(pubKeyBioPtr.get(),NULL,NULL,NULL),&X509_free};
    QSharedPointer<EVP_PKEY> pubKeyPtr {X509_get_pubkey(pubX509Ptr.get()),&EVP_PKEY_free};
    X509_NAME* pubNamePtr {X509_get_subject_name(pubX509Ptr.get())};

    QSharedPointer<BIO> prvKeyBioPtr {BIO_new_file(privateKeyPath.toStdString().c_str(),"r+"),&BIO_free};
    QSharedPointer<EVP_PKEY> prvKeyPtr {PEM_read_bio_PrivateKey(prvKeyBioPtr.get(),NULL,NULL,(unsigned char*)privateKeyPass.toStdString().c_str()),&EVP_PKEY_free};

    QSharedPointer<X509> x509Ptr {X509_new(),&X509_free};
    ret&=X509_set_version(x509Ptr.get(),2L);
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }
    X509_gmtime_adj(X509_get_notBefore(x509Ptr.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x509Ptr.get()), 31536000L * 3);
    ret&=X509_set_subject_name(x509Ptr.get(),reqNamePtr);
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }
    ret&=X509_set_issuer_name(x509Ptr.get(),pubNamePtr);
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }
    ret&=X509_set_pubkey(x509Ptr.get(),reqKeyPtr);
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }
    ret&=X509_sign(x509Ptr.get(),prvKeyPtr.get(),EVP_sha256());
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }

    QSharedPointer<BIO> x509BioPtr {BIO_new(BIO_s_mem()),&BIO_free};
    ret&=PEM_write_bio_X509(x509BioPtr.get(),x509Ptr.get());
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }
    const int& x509Length {BIO_pending(x509BioPtr.get())};
    agentCertData.resize(x509Length);
    ret&=BIO_read(x509BioPtr.get(),agentCertData.data(),(int)agentCertData.size());
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }
    return true;
}

bool CryptoGenerator::createUserCert(const QString &userId, const QString &caCertPath,
                                 const QString &publicKeyPath, const QString &privateKeyPath,
                                 const QString &privateKeyPass, const QString &userCertPass,
                                 const QString &userCertName, QByteArray &userCertData, QString &lastError, long validDays)
{
    const QString bugError {"error:00000000:lib(0):func(0):reason(0)"};
    const auto makeError{[](){
            const unsigned long& errCode {ERR_get_error()};
            const QString errText {ERR_error_string(errCode,NULL)};
            return errText;
        }
    };
    int ret {1};
    QSharedPointer<BIO> rootBioPtr {BIO_new_file(caCertPath.toStdString().c_str(),"r+"),&BIO_free};
    QSharedPointer<X509> rootX509Ptr {PEM_read_bio_X509(rootBioPtr.get(),NULL,NULL,NULL),&X509_free};

    QSharedPointer<BIO> pubBioPtr {BIO_new_file(publicKeyPath.toStdString().c_str(),"r+"),&BIO_free};
    QSharedPointer<X509> pubX509Ptr {PEM_read_bio_X509(pubBioPtr.get(),NULL,NULL,NULL),&X509_free};
    QSharedPointer<EVP_PKEY> pubKeyPtr {X509_get_pubkey(pubX509Ptr.get()),&EVP_PKEY_free};
    X509_NAME* pubNamePtr {X509_get_subject_name(pubX509Ptr.get())};

    QSharedPointer<BIO> prvBioPtr {BIO_new_file(privateKeyPath.toStdString().c_str(),"r+"),&BIO_free};
    QSharedPointer<EVP_PKEY> prvKeyPtr {PEM_read_bio_PrivateKey(prvBioPtr.get(),NULL,NULL,(unsigned char*)privateKeyPass.toStdString().c_str()),&EVP_PKEY_free};

    QSharedPointer<X509> x509Ptr {X509_new(),&X509_free};
    ret&=X509_set_version(x509Ptr.get(),2L);
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }
    const long validSeconds {
        validDays==0 ? 31536000L * 3 : validDays * 86400
    };
    X509_gmtime_adj(X509_get_notBefore(x509Ptr.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x509Ptr.get()), validSeconds);
    ret&=X509_set_pubkey(x509Ptr.get(),pubKeyPtr.get());
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }
    ret&=X509_set_issuer_name(x509Ptr.get(),pubNamePtr);
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }

    int lastPos {-1};
    lastPos=X509_NAME_get_index_by_NID(pubNamePtr,NID_commonName,-1);
    if(lastPos!=-1){
        auto ptr {X509_NAME_delete_entry(pubNamePtr,lastPos)};
        if(!ptr){
            lastError="COMMON_NAME entry not found!";
            return false;
        }
        X509_NAME_ENTRY_free(ptr);
    }

    ret&=X509_NAME_add_entry_by_txt(pubNamePtr,"OU",MBSTRING_ASC,(const unsigned char*)"User",-1,-1,0);
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }
    ret&=X509_NAME_add_entry_by_txt(pubNamePtr,"CN",MBSTRING_ASC,(const unsigned char*)userId.toStdString().c_str(),-1,-1,0);
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }
    ret&=X509_set_subject_name(x509Ptr.get(),pubNamePtr);
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }

    ret&=X509_sign(x509Ptr.get(),prvKeyPtr.get(),EVP_sha256());
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }

    QSharedPointer<STACK_OF(X509)> x509StackPtr {sk_X509_new_null(),&sk_X509_free};
    ret&=sk_X509_push(x509StackPtr.get(),pubX509Ptr.get());
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }
    ret&=sk_X509_push(x509StackPtr.get(),rootX509Ptr.get());
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }

    QSharedPointer<PKCS12> pkcsPtr {PKCS12_create(userCertPass.toStdString().c_str(),userCertName.toStdString().c_str(),prvKeyPtr.get(),x509Ptr.get(),x509StackPtr.get(),
                                 NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                 NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                 20000,
                                 1,
                                 0),&PKCS12_free};
    QSharedPointer<BIO> pkcsBioPtr {BIO_new(BIO_s_mem()),&BIO_free};
    ret&=i2d_PKCS12_bio(pkcsBioPtr.get(),pkcsPtr.get());
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }

    const int& pkcsLength {BIO_pending(pkcsBioPtr.get())};
    userCertData.resize(pkcsLength);
    ret&=BIO_read(pkcsBioPtr.get(),userCertData.data(),(int)userCertData.size());
    if(ret <=0 ){
        lastError=makeError();
        if(lastError!=bugError){
            return false;
        }
    }
    return true;
}

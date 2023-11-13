#include "MainWindow.h"
#include "Defines.h"
#include "network/HttpClient.h"

#include <QUrl>
#include <QUrlQuery>
#include <QLabel>
#include <QRegExp>
#include <QWidget>
#include <QGroupBox>
#include <QTextEdit>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QGridLayout>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QIntValidator>
#include <QRegExpValidator>

void MainWindow::sendReqSlot()
{
    if(ipAddressLineEditPtr_->text().isEmpty()){
        QMessageBox::warning(this,"Warning","IP address is empty!");
        return;
    }
    if(routeLineEditPtr_->text().isEmpty()){
        QMessageBox::warning(this,"Warning","Route is empty!");
        return;
    }

    QUrl reqUrl {};
    reqUrl.setScheme(schemeComboBoxPtr_->currentText());
    reqUrl.setHost(ipAddressLineEditPtr_->text());
    reqUrl.setPort(portLineEditPtr_->text().toInt());

    const QString queryPath  {routeLineEditPtr_->text().section('?',0,0)};
    reqUrl.setPath(queryPath);
    const QString queryString {routeLineEditPtr_->text().section('?',1,1)};
    if(!queryString.isEmpty()){
        QUrlQuery reqQuery {queryString};
        reqUrl.setQuery(reqQuery);
    }
    if(!reqUrl.isValid()){
        QMessageBox::warning(this,"Warning",reqUrl.errorString());
        return;
    }

    HttpVerb reqVerb {qstringToVerb(verbComboBoxPtr_->currentText())};
    const QByteArray reqBody {reqBodyTextEditPtr_->toPlainText().toUtf8()};
    const QString reqHeader {headerLaneEditPtr_->text()};
    btnsGroupBoxPtr_->setEnabled(false);
    Q_EMIT httpClientPtr_->sendReqSignal(reqUrl,reqVerb,reqBody,reqHeader);

}

void MainWindow::clearReqBodySlot()
{
    reqBodyTextEditPtr_->clear();
}

void MainWindow::clearRespBodySlot()
{
    respBodyTextEditPtr_->clear();
}

void MainWindow::finishedSlot(bool isSuccess, const QByteArray &respBody)
{
    btnsGroupBoxPtr_->setEnabled(true);
    respBodyTextEditPtr_->append(respBody);
}

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{
    schemeComboBoxPtr_=new QComboBox;
    schemeComboBoxPtr_->addItems({"http","https"});
    schemeComboBoxPtr_->setCurrentIndex(0);

    ipAddressLineEditPtr_=new QLineEdit;
    QRegExp re {"^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\\.(?!$)|$)){4}$"};
    QRegExpValidator* ipValidator {new QRegExpValidator(re,ipAddressLineEditPtr_)};
    ipAddressLineEditPtr_->setValidator(ipValidator);
    ipAddressLineEditPtr_->setPlaceholderText("Enter valid IP address");
    ipAddressLineEditPtr_->setText("127.0.0.1");

    portLineEditPtr_=new QLineEdit;
    portLineEditPtr_->setFixedWidth(50);
    portLineEditPtr_->setText(QString::number(8030));
    portLineEditPtr_->setValidator(new QIntValidator(0,USHRT_MAX));

    verbComboBoxPtr_=new QComboBox;
    verbComboBoxPtr_->addItems({"GET","PUT","POST","DELETE"});
    verbComboBoxPtr_->setCurrentIndex(0);

    headerLaneEditPtr_=new QLineEdit;
    headerLaneEditPtr_->setPlaceholderText("Enter ID for header");
    headerLaneEditPtr_->setText("dc77b7f3-71d9-4ce9-95a2-100b88d0306c");

    routeLineEditPtr_=new QLineEdit;
    routeLineEditPtr_->setPlaceholderText("Enter valid route");
    routeLineEditPtr_->setText("/api/v1/u-auth/users");

    sendReqBtnPtr_=new QPushButton{"Send request"};
    QObject::connect(sendReqBtnPtr_,&QPushButton::clicked,this,&MainWindow::sendReqSlot);
    clearReqBtnPtr_=new QPushButton{"Clear request"};
    QObject::connect(clearReqBtnPtr_,&QPushButton::clicked,this,&MainWindow::clearReqBodySlot);
    clearRespBtnPtr_=new QPushButton{"Clear response"};
    QObject::connect(clearRespBtnPtr_,&QPushButton::clicked,this,&MainWindow::clearRespBodySlot);

    QVBoxLayout* btnsVBoxLayoutPtr {new QVBoxLayout};
    btnsVBoxLayoutPtr->addWidget(sendReqBtnPtr_);
    btnsVBoxLayoutPtr->addWidget(clearReqBtnPtr_);
    btnsVBoxLayoutPtr->addWidget(clearRespBtnPtr_);

    btnsGroupBoxPtr_=new QGroupBox("Operations");
    btnsGroupBoxPtr_->setLayout(btnsVBoxLayoutPtr);

    QGridLayout* gridLayoutPtr {new QGridLayout};
    gridLayoutPtr->setSpacing(10);
    gridLayoutPtr->addWidget(new QLabel("Scheme:"),0,0,1,1,Qt::AlignLeft|Qt::AlignBottom);
    gridLayoutPtr->addWidget(schemeComboBoxPtr_,1,0,1,1);

    gridLayoutPtr->addWidget(new QLabel("IP Address:"),0,1,Qt::AlignLeft|Qt::AlignBottom);
    gridLayoutPtr->addWidget(ipAddressLineEditPtr_,1,1,1,6);

    gridLayoutPtr->addWidget(new QLabel("Port:"),0,7,1,1,Qt::AlignLeft|Qt::AlignBottom);
    gridLayoutPtr->addWidget(portLineEditPtr_,1,7,1,1);

    gridLayoutPtr->addWidget(new QLabel("Verb:"),0,8,1,1,Qt::AlignLeft|Qt::AlignBottom);
    gridLayoutPtr->addWidget(verbComboBoxPtr_,1,8,1,1);

    gridLayoutPtr->addWidget(new QLabel("X-Client-Cert-Dn:"),2,0,1,1);
    gridLayoutPtr->addWidget(headerLaneEditPtr_,2,1,1,8);

    gridLayoutPtr->addWidget(new QLabel("Route:"),3,0,1,1);
    gridLayoutPtr->addWidget(routeLineEditPtr_,3,1,1,8);

    gridLayoutPtr->addWidget(btnsGroupBoxPtr_,0,9,4,1);

    reqBodyTextEditPtr_=new QTextEdit;
    QGroupBox* reqGroupBoxPtr {new QGroupBox("Request body")};
    QVBoxLayout* reqVBoxLayOutrPtr {new QVBoxLayout};
    reqVBoxLayOutrPtr->addWidget(reqBodyTextEditPtr_);
    reqGroupBoxPtr->setLayout(reqVBoxLayOutrPtr);


    respBodyTextEditPtr_=new QTextEdit;
    QGroupBox* respGroupBoxPtr {new QGroupBox("Reponse body")};
    QVBoxLayout* respVBoxLayOutrPtr {new QVBoxLayout};
    respVBoxLayOutrPtr->addWidget(respBodyTextEditPtr_);
    respGroupBoxPtr->setLayout(respVBoxLayOutrPtr);

    QVBoxLayout* bodiesVBoxLayoutPtr {new QVBoxLayout};
    bodiesVBoxLayoutPtr->addWidget(reqGroupBoxPtr);
    bodiesVBoxLayoutPtr->addWidget(respGroupBoxPtr);

    QVBoxLayout* mainVBoxLayoutPtr {new QVBoxLayout};
    mainVBoxLayoutPtr->addLayout(gridLayoutPtr,0);
    mainVBoxLayoutPtr->addLayout(bodiesVBoxLayoutPtr,5);

    QWidget* centralWidgetPtr {new QWidget};
    centralWidgetPtr->setLayout(mainVBoxLayoutPtr);
    setCentralWidget(centralWidgetPtr);
    resize(800,600);

    httpClientPtr_=new HttpClient;
    QObject::connect(httpClientPtr_,&HttpClient::finishedSignal,this,&MainWindow::finishedSlot);
    httpClientPtr_->start();
}

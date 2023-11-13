#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <limits>

class QComboBox;
class QLineEdit;
class QTextEdit;
class QGroupBox;
class QPushButton;
class HttpClient;
class MainWindow : public QMainWindow
{
    Q_OBJECT
private:
    QComboBox* schemeComboBoxPtr_    {nullptr};
    QLineEdit* ipAddressLineEditPtr_ {nullptr};
    QLineEdit* portLineEditPtr_      {nullptr};
    QComboBox* verbComboBoxPtr_      {nullptr};
    QLineEdit* headerLaneEditPtr_    {nullptr};
    QLineEdit* routeLineEditPtr_     {nullptr};

    QPushButton* sendReqBtnPtr_      {nullptr};
    QPushButton* clearReqBtnPtr_     {nullptr};
    QPushButton* clearRespBtnPtr_    {nullptr};
    QGroupBox* btnsGroupBoxPtr_      {nullptr};

    QTextEdit* reqBodyTextEditPtr_   {nullptr};
    QTextEdit* respBodyTextEditPtr_  {nullptr};

    HttpClient* httpClientPtr_       {nullptr};
private Q_SLOTS:
    void sendReqSlot();
    void clearReqBodySlot();
    void clearRespBodySlot();
    void finishedSlot(bool isSuccess,const QByteArray& respBody);
public:
    explicit MainWindow(QWidget *parent = nullptr);
    virtual ~MainWindow()=default;
signals:

};

#endif // MAINWINDOW_H

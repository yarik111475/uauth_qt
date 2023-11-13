#include <QApplication>
#include <QCommandLineParser>
#include "gui/MainWindow.h"
#include "../Version.h"

int main(int argc, char *argv[])
{
    QApplication app {argc,argv};
    const QString appVersion {APP_VERSION};
    app.setApplicationVersion(appVersion);
    QCommandLineParser parser;
    parser.addVersionOption();
    parser.process(app);

    MainWindow mainWindow {};
    mainWindow.show();
    return app.exec();
}


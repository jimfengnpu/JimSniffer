#include <QApplication>
#include "sniffer_window.h"


int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    JmSniffer mainWindow(nullptr);
    return QApplication::exec();
}

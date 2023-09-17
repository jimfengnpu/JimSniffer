#include <QApplication>
#include <QPushButton>
#include "sniffer.h"

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    Sniffer sniffer;
    QPushButton button("Hello world!", nullptr);
    button.resize(200, 100);
    button.show();
    return QApplication::exec();
}

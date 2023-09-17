#include <QApplication>
#include <QPushButton>
#include <QBoxLayout>
#include <QComboBox>
#include "sniffer.h"

class JmSniffer:QWidget {
public:
    QComboBox devSelector;
    Sniffer sniffer;
    explicit JmSniffer(QWidget *parent);

};

JmSniffer::JmSniffer(QWidget *parent) : QWidget(parent), devSelector(this){
    vector<string> infos;
    setGeometry(300, 300, 1000, 600);
    auto *vLayout = new QVBoxLayout(this);
    auto *headerLayout = new QHBoxLayout(this);
    vLayout->addLayout(headerLayout);
    headerLayout->addWidget(&devSelector);
    headerLayout->addStretch(1);
    devSelector.resize(200, 40);
    sniffer.getDevicesInfo(infos);
    for(const auto& info: infos){
        devSelector.addItem(QString::asprintf("%s", info.c_str()));
        cout << info << endl;
    }
    this->show();
}

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    JmSniffer sniffer(nullptr);
//    QPushButton button("Hello world!", nullptr);
//    button.resize(200, 100);
//    button.show();
    return QApplication::exec();
}

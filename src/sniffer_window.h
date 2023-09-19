//
// Created by jimfeng on 23-9-17.
//

#ifndef JIM_SNIFFER_UI_SNIFFER_WIDGET_H
#define JIM_SNIFFER_UI_SNIFFER_WIDGET_H
#include <QDebug>
#include <QMainWindow>
#include <QMenuBar>
#include <QToolBar>
#include <QBoxLayout>
#include <QPushButton>
#include <QComboBox>
#include <QTableWidget>
#include <QTreeWidget>
#include <QTextEdit>
#include <QHeaderView>
#include <iomanip>
#include "sniffer.h"

#define NO_COLUMN 0
#define SRC_COLUMN 1
#define DST_COLUMN 2
#define PROTO_COLUMN 3
#define LEN_COLUMN 4
#define INFO_COLUMN 5
#define TABLE_CELL_DATA(str) (new QTableWidgetItem(QString::fromStdString(str)))

class JmSniffer: QMainWindow {
public:
    QMenuBar *menuBar;
    QToolBar *toolBar;
    QComboBox *devSelector;
    QTableWidget *packetList;
    QTreeWidget *protocolWindow;
    QTextEdit *hexDataWindow;
    QPushButton *startListenBtn;
    QPushButton *endListenBtn;
    Sniffer *sniffer;
    explicit JmSniffer(QWidget *parent);
    void setMenu();
    void setController();
    void updateDevices() const;
    void updateWidgetState() const;
    void onPacketReceive(Packet* packet) const;
    void onPacketSelected(int row) const;
};


#endif //JIM_SNIFFER_UI_SNIFFER_WIDGET_H

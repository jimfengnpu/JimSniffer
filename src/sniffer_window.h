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
#include <QHeaderView>
#include "sniffer.h"

class JmSniffer: QMainWindow {
public:
    QMenuBar *menuBar;
    QToolBar *toolBar;
    QComboBox *devSelector;
    QTableWidget *packetList;
    QPushButton *startListenBtn;
    QPushButton *endListenBtn;
    Sniffer *sniffer;
    explicit JmSniffer(QWidget *parent);
    void setMenu();
    void setController();
    void updateDevices() const;
    void updateWidgetState() const;
};


#endif //JIM_SNIFFER_UI_SNIFFER_WIDGET_H

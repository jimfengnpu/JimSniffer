//
// Created by jimfeng on 23-9-17.
//

#include "sniffer_window.h"

JmSniffer::JmSniffer(QWidget *parent) : QMainWindow(parent){
    // UI/View
    // Window Init
    setGeometry(300, 300, 1000, 600);
    auto *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    auto *vLayout = new QVBoxLayout(centralWidget);
    menuBar = new QMenuBar(this);
    setMenuBar(menuBar);
    toolBar = new QToolBar(this);
    addToolBar(toolBar);
    devSelector = new QComboBox(this);
    startListenBtn = new QPushButton("开始", this);
    endListenBtn = new QPushButton("结束", this);
    packetList = new QTableWidget(this);
    // Layout
    auto *dockLayout = new QHBoxLayout(nullptr);
    vLayout->addWidget(packetList);
    vLayout->addLayout(dockLayout);
    toolBar->addWidget(devSelector);
    toolBar->addWidget(startListenBtn);
    toolBar->addWidget(endListenBtn);
    devSelector->resize(200, 40);
    packetList->resize(1000, 500);
    // Model
    sniffer = new Sniffer();
    packetList->setEditTriggers(QAbstractItemView::NoEditTriggers);
    packetList->setSelectionMode(QAbstractItemView::SingleSelection);
    packetList->setShowGrid(false);
    packetList->setColumnCount(6);
    packetList->setHorizontalHeaderLabels(QStringList({
        "No.", "Src", "Dst", "Protocol", "Length", "Info"
    }));
    packetList->horizontalHeader()->setDefaultSectionSize(80);
    packetList->setColumnWidth(1, 160);
    packetList->setColumnWidth(2, 160);
    packetList->horizontalHeader()->setStretchLastSection(true);
    // Controller
    setMenu();
    setController();
    updateDevices();
    updateWidgetState();
    this->show();
}

void JmSniffer::updateDevices() const {
    vector<string> infos;
    devSelector->clear();
    sniffer->loadDevices();
    sniffer->setDevice(0);
    sniffer->getDevicesInfo(infos);
    for(const auto& info: infos){
        devSelector->addItem(QString::fromStdString(info));
    }
}

void JmSniffer::setController() {
    connect(devSelector, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
            this, [=](int i){ sniffer->setDevice(i);}
            );
    connect(startListenBtn, &QPushButton::clicked, this,
            [=]{sniffer->startListening(); updateWidgetState();});
    connect(endListenBtn, &QPushButton::clicked, this,
            [=]{sniffer->stopListening(); updateWidgetState();});
}

void JmSniffer::setMenu() {

}

void JmSniffer::updateWidgetState() const {
    bool listening = sniffer->isListening;
    startListenBtn->setDisabled(listening);
    endListenBtn->setEnabled(listening);
}

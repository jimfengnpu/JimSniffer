//
// Created by jimfeng on 23-9-17.
//

#include "sniffer_window.h"

JmSniffer::JmSniffer(QWidget *parent) : QMainWindow(parent){
    // UI/View
    // Window Init
    setGeometry(300, 300, 1000, 700);
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
    protocolWindow = new QTreeWidget(this);
    hexDataWindow = new QTextEdit(this);
    // Layout
    auto *dockLayout = new QHBoxLayout(nullptr);
    vLayout->addWidget(packetList);
    vLayout->addLayout(dockLayout);
    toolBar->addWidget(devSelector);
    toolBar->addWidget(startListenBtn);
    toolBar->addWidget(endListenBtn);
    devSelector->resize(200, 40);
    packetList->resize(1000, 300);
    dockLayout->addWidget(protocolWindow);
    dockLayout->addWidget(hexDataWindow);
    protocolWindow->resize(500, 300);
    hexDataWindow->resize(500, 300);
    hexDataWindow->setReadOnly(true);
    hexDataWindow->setFont(QFont("Noto Mono", 12));
    // Model
    sniffer = new Sniffer();
    packetList->setEditTriggers(QAbstractItemView::NoEditTriggers);
    packetList->setSelectionMode(QAbstractItemView::ContiguousSelection);
    packetList->setShowGrid(false);
    packetList->setColumnCount(6);
    packetList->setHorizontalHeaderLabels(QStringList({
        "No.", "Src", "Dst", "Protocol", "Length", "Info"
    }));
    packetList->horizontalHeader()->setDefaultSectionSize(80);
    packetList->verticalHeader()->setVisible(false);
    packetList->setColumnWidth(SRC_COLUMN, 160);
    packetList->setColumnWidth(DST_COLUMN, 160);
    packetList->horizontalHeader()->setStretchLastSection(true);
    protocolWindow->header()->setVisible(false);
    protocolWindow->setSelectionMode(QAbstractItemView::SingleSelection);
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
    connect(sniffer, &Sniffer::onPacketReceive, this,
            [=](Packet* packet){ onPacketReceive(packet); });
    connect(packetList, &QTableWidget::cellClicked, this,
            [=](int row, int col){ onPacketSelected(row);});
    connect(protocolWindow, &QTreeWidget::itemSelectionChanged, this,
            [=]{
                auto list = protocolWindow->selectedItems();
                if(list.length() < 1){
                    return;
                }
                auto info = (PacketInfo* )list[0];
                auto cursor = hexDataWindow->textCursor();
                cursor.clearSelection();
                cursor.setPosition(info->start*3);
                cursor.setPosition(info->end*3-1, QTextCursor::KeepAnchor);
                hexDataWindow->setTextCursor(cursor);
            });
}

void JmSniffer::setMenu() {

}

void JmSniffer::updateWidgetState() const {
    bool listening = sniffer->isListening;
    startListenBtn->setDisabled(listening);
    devSelector->setDisabled(listening);
    endListenBtn->setEnabled(listening);
}

void JmSniffer::onPacketReceive(Packet *packet) const {
    int row = packetList->rowCount();
    packetList->insertRow(row);
    // fill Data
    packetList->setItem(row, NO_COLUMN, TABLE_CELL_DATA(to_string(packet->frameId)));
    packetList->setItem(row, SRC_COLUMN, TABLE_CELL_DATA(packet->src));
    packetList->setItem(row, DST_COLUMN, TABLE_CELL_DATA(packet->dst));
    packetList->setItem(row, PROTO_COLUMN, TABLE_CELL_DATA(packet->proto));
    packetList->setItem(row, LEN_COLUMN, TABLE_CELL_DATA(to_string(packet->length)));
    packetList->setItem(row, INFO_COLUMN, TABLE_CELL_DATA(packet->info));
}

void JmSniffer::onPacketSelected(int row) const {
    assert(row < sniffer->packetList.size());
    packetList->setRangeSelected(
            QTableWidgetSelectionRange(0, 0, packetList->rowCount(), 5), false);
    packetList->setRangeSelected(
            QTableWidgetSelectionRange(row, 0, row, 5), true);
    Packet *packet = sniffer->packetList[row];
    while(protocolWindow->topLevelItemCount()){
        protocolWindow->takeTopLevelItem(0);
    }
    for(auto item: packet->protocolInfo){
        protocolWindow->addTopLevelItem(item);
    }
    protocolWindow->expandAll();
    stringstream ss;
    auto it = packet->data.begin();
    uint cnt = 0;
    for(int i = 0; i < packet->length && it != packet->data.end();) {
        ss << std::setfill('0') << std::setw(2) << std::hex << (int) it->start[cnt];
        if((++i)%16 == 0) {
            ss << endl;
        }else {
            ss << " ";
        }
        if(it->len == cnt) {
            it++;
            cnt = 0;
        }else {
            cnt ++;
        }
    }
    hexDataWindow->setText(QString::fromStdString(ss.str()));
}

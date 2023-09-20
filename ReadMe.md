# JimSniffer
基于Qt5和libpcap实现的抓包工具，wireshark的简化版本
最终预计功能：
抓取以太网数据帧
网卡选择
数据包内容与协议栈内容对应展示
pcap格式文件的保存和载入
解析IPv4,TCP,UDP,ICMP,HTTP,ARP数据段内容
IP分片重组
TCP分段重组
## 项目状态
开发中
## 进度
+ 主体页面...ok
+ libpcap各项接口...ok
  + 抓取数据包...ok
  + 文件载入与保存...ok
+ 数据解析....developing
  + MAC解析...ok
  + IP层解析...ok
  + TCP报头解析...todo
  + UDP报头解析...todo
  + ICMP报文解析...todo
  + ARP报文解析...todo
  + HTTP报文解析...todo
+ IP分片重组.....todo
+ TCP分段重组.....todo
+ 数据查看及筛选.....todo



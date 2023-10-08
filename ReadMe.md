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
+ 数据解析....ok
  + MAC解析...ok
  + IP层解析...ok
  + TCP报头解析...ok
  + UDP报头解析...ok
  + ICMP报文解析...ok
  + ARP报文解析...ok
  + HTTP报文解析...ok
+ IP分片重组.....ok
+ TCP分段重组.....ok
+ 数据查看及筛选.....todo



#include<iostream>
#include<pcap.h>
#include<cstring>
#include<winsock2.h>
#include <ws2tcpip.h>


using namespace std;


#pragma pack(1)		//进入字节对齐方式

//定义帧首部
typedef struct FrameHeader_t {
	BYTE DesMAC[6];		//目的地址
	BYTE SrcMAC[6];		//源地址
	WORD FrameType;		//帧类型
}FrameHeader_t;

//定义IP首部
typedef struct IPHeader_t {
	BYTE Ver_HLen;		//IP版本和头部长度
	BYTE TOS;			//服务类型
	WORD TotalLen;		//总长度
	WORD ID;			//标识
	WORD Flag_Segment;	//片偏移
	BYTE TTL;			//生存时间
	BYTE Protocol;		//协议
	WORD Checksum;		//首部校验和
	ULONG SrcIP;		//源IP
	ULONG DstIP;		//目的IP
}IPHeader_t;

//定义包含帧首部和IP首部的数据包
typedef struct Data_t {
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}Data_t;

#pragma pack()		//恢复缺省对齐方式

void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
	Data_t* data = (Data_t*)packet;

	// 打印目的 MAC 地址
	cout << "目的 MAC: ";
	for (int i = 0; i < 6; i++) {
		cout << hex << (int)data->FrameHeader.DesMAC[i];
		if (i < 5) cout << ":";
	}
	cout << endl;

	// 打印源 MAC 地址
	cout << "源 MAC: ";
	for (int i = 0; i < 6; i++) {
		cout << hex << (int)data->FrameHeader.SrcMAC[i];
		if (i < 5) cout << ":";
	}
	cout << endl;

	// 打印帧类型
	cout << "帧类型: " << ntohs(data->FrameHeader.FrameType) << endl;

	//打印IP首部信息
	cout << "IP首部信息：" << endl;
	cout << "版本: IPv " << hex << (data->IPHeader.Ver_HLen & 0xF0) / 16 << endl;
	cout << "头部长度: " << (data->IPHeader.Ver_HLen & 0x0F) << endl;
	cout << "服务类型: " << hex << static_cast<int>(data->IPHeader.TOS) << endl;
	cout << "总长度: " << hex << ntohs(data->IPHeader.TotalLen) << endl;
	cout << "标识: " << hex << ntohs(data->IPHeader.ID) << endl;
	cout << "标志/片段偏移: " << hex << ntohs(data->IPHeader.Flag_Segment) << endl;
	cout << "TTL: " << dec << static_cast<int>(data->IPHeader.TTL) << endl;
	cout << "协议: " << hex << static_cast<int>(data->IPHeader.Protocol) << endl;
	cout << "校验和: " << hex << ntohs(data->IPHeader.Checksum) << endl;

	//打印源IP地址、目的IP地址
	ULONG SourceIP, DestinationIP;
	SourceIP = ntohl(data->IPHeader.SrcIP);
	DestinationIP = ntohl(data->IPHeader.DstIP);
	//讲ULONG转换为点分十进制格式
	struct in_addr src_addr, dst_addr;
	src_addr.s_addr = SourceIP;
	dst_addr.s_addr = DestinationIP;
	char src_ip_str[INET_ADDRSTRLEN]; // 存放源 IP 字符串
	char dst_ip_str[INET_ADDRSTRLEN]; // 存放目的 IP 字符串

	// 使用inet_ntop转换IP地址
	inet_ntop(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &dst_addr, dst_ip_str, INET_ADDRSTRLEN);

	cout << "源IP地址为：" << src_ip_str << endl;
	cout << "目的IP地址为：" << dst_ip_str << endl;

	cout << endl;

}


int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_addr_t* a;
	int devs_count = 0;

	char errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区

	//获取本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,	//获取本机的接口设备
		NULL,				//无需认证
		&alldevs,			//指向设备列表首部
		errbuf				//出错信息保存缓冲区
	) == -1)
	{
		cout << "获取本机设备列表时出错:" << errbuf << endl;
		return 1;
	}

	//显示接口列表
	for (d = alldevs; d != NULL; d = d->next)
	{
		devs_count++;
		//打印网络接口设备的名字和描述信息
		cout << devs_count << ". " << d->name << "->" << d->description << ";" << endl;
		////获取网络接口设备的IP地址信息
		//for (a = d->addresses; a != NULL; a = a->next)
		//{
		//	if (a->addr->sa_family == AF_INET)
		//	{
		//		cout << "IP地址：" << a->addr << endl;
		//		cout << "网络掩码：" << a->netmask << endl;
		//		cout << "广播地址：" << a->broadaddr << endl;
		//		cout << "目的地址：" << a->dstaddr << endl;
		//	}
		//}
	}
	cout << "请选择设备（1-" << devs_count << "):" << endl;
	int dev_select_num = 0;
	cin >> dev_select_num;
	pcap_if_t* dev_select = alldevs;

	for (int i = 0; i < dev_select_num - 1; i++)
	{
		dev_select = dev_select->next;
	}
	a = dev_select->addresses;
	cout << "您选择的设备信息为：" << dev_select->name << ";" << endl;

	//打印网络接口设备的IP地址信息
	if (a->addr->sa_family == AF_INET)
	{
		cout << "IP地址：" << a->addr << endl;
		cout << "网络掩码：" << a->netmask << endl;
		cout << "广播地址：" << a->broadaddr << endl;
		cout << "目的地址：" << a->dstaddr << endl;
	};
	cout << endl;

	
	//打开网络接口
	pcap_t* handle = pcap_open_live(dev_select->name, BUFSIZ, 1, 1000, errbuf);
	/*if (pcap_open == NULL)
	{
		cout << "打开设备" << dev_select_num << "的网络接口失败：" << errbuf << endl;
		return 1;
	}*/

	//捕获网络数据包
	pcap_loop(handle, 5, packet_handler, NULL);

	

	pcap_freealldevs(alldevs);
	pcap_close(handle);


	return 0;
}
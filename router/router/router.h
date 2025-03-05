#include<iostream>
#include<winsock2.h>
#include<pcap.h>
#include <algorithm>
#include <iphlpapi.h>
#include <iomanip>
#include <cstdlib>

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma warning(disable:4996)

using namespace std;

#define ROUTER_TABLE_SIZE 128

#pragma pack(1)//进入字节对齐方式

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

//定义ARP帧
typedef struct ARPFrame_t {
    FrameHeader_t FrameHeader;
    WORD HardwareType;	//硬件类型
    WORD ProtocolType;	//协议类型
    BYTE HLen;			//硬件地址长度
    BYTE PLen;			//协议地址长度
    WORD Operation;		//操作
    BYTE SendHa[6];		//源MAC地址
    DWORD SendIP;		//源IP地址
    BYTE RecvHa[6];		//目的MAC地址
    DWORD RecvIP;		//目的IP地址
}ARPFrame_t;

//定义路由表
typedef struct router_table {
    ULONG netmask;         //网络掩码
    ULONG desnet;          //目的网络
    ULONG nexthop;         //下一站路由
}router_table;

#pragma pack()    //恢复缺省对齐方式

// 网卡初始化
int in_dev(pcap_if_t*& alldevs, pcap_if_t*& d, pcap_addr_t*& a);


// 计算子网掩码的前缀长度
int get_pre_length(int netmask);

// 向路由表中添加项（插入时按前缀长度排序）
bool additem(router_table* t, int& tLength, router_table item);

//从路由表中删除项
bool deleteitem(router_table* t, int& tLength, int index);

// 打印路由表
void print_rt(router_table* t, int& tLength);

void addRoute(const string& desnet, const string& netmask, const string& nexthop);

// 对路由表内容进行操作
int router_op(router_table* rt, int& rt_length);

// 设置过滤器
int set_filter(pcap_t* p, pcap_if_t* d);

// 路由选择函数，最长匹配，返回值为下一跳的IP地址
ULONG search(router_table* t, int tLength, ULONG DesIP);

// 发送ARP请求
int send_arp_req(pcap_t* handle, BYTE* srcMAC, ULONG scrIP, ULONG targetIP);

// 从ARP包中解析MAC地址
int get_mac(pcap_t* p, ULONG targetIP, ULONG scrIP, BYTE* mac);

// 打印IP数据包
void print_ip_packet(Data_t* IPPacket);

// 设置校验和
void setchecksum(Data_t* temp);


void printIP(ULONG IP)
{
    BYTE* p = (BYTE*)&IP;
    for (int i = 0; i < 3; i++)
    {
        cout << dec << (int)*p << ".";
        p++;
    }
    cout << dec << (int)*p << " ";
}

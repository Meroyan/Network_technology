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

#pragma pack(1)//�����ֽڶ��뷽ʽ

//����֡�ײ�
typedef struct FrameHeader_t {
    BYTE DesMAC[6];		//Ŀ�ĵ�ַ
    BYTE SrcMAC[6];		//Դ��ַ
    WORD FrameType;		//֡����
}FrameHeader_t;

//����IP�ײ�
typedef struct IPHeader_t {
    BYTE Ver_HLen;		//IP�汾��ͷ������
    BYTE TOS;			//��������
    WORD TotalLen;		//�ܳ���
    WORD ID;			//��ʶ
    WORD Flag_Segment;	//Ƭƫ��
    BYTE TTL;			//����ʱ��
    BYTE Protocol;		//Э��
    WORD Checksum;		//�ײ�У���
    ULONG SrcIP;		//ԴIP
    ULONG DstIP;		//Ŀ��IP
}IPHeader_t;

//�������֡�ײ���IP�ײ������ݰ�
typedef struct Data_t {
    FrameHeader_t FrameHeader;
    IPHeader_t IPHeader;
}Data_t;

//����ARP֡
typedef struct ARPFrame_t {
    FrameHeader_t FrameHeader;
    WORD HardwareType;	//Ӳ������
    WORD ProtocolType;	//Э������
    BYTE HLen;			//Ӳ����ַ����
    BYTE PLen;			//Э���ַ����
    WORD Operation;		//����
    BYTE SendHa[6];		//ԴMAC��ַ
    DWORD SendIP;		//ԴIP��ַ
    BYTE RecvHa[6];		//Ŀ��MAC��ַ
    DWORD RecvIP;		//Ŀ��IP��ַ
}ARPFrame_t;

//����·�ɱ�
typedef struct router_table {
    ULONG netmask;         //��������
    ULONG desnet;          //Ŀ������
    ULONG nexthop;         //��һվ·��
}router_table;

#pragma pack()    //�ָ�ȱʡ���뷽ʽ

// ������ʼ��
int in_dev(pcap_if_t*& alldevs, pcap_if_t*& d, pcap_addr_t*& a);


// �������������ǰ׺����
int get_pre_length(int netmask);

// ��·�ɱ�����������ʱ��ǰ׺��������
bool additem(router_table* t, int& tLength, router_table item);

//��·�ɱ���ɾ����
bool deleteitem(router_table* t, int& tLength, int index);

// ��ӡ·�ɱ�
void print_rt(router_table* t, int& tLength);

void addRoute(const string& desnet, const string& netmask, const string& nexthop);

// ��·�ɱ����ݽ��в���
int router_op(router_table* rt, int& rt_length);

// ���ù�����
int set_filter(pcap_t* p, pcap_if_t* d);

// ·��ѡ�������ƥ�䣬����ֵΪ��һ����IP��ַ
ULONG search(router_table* t, int tLength, ULONG DesIP);

// ����ARP����
int send_arp_req(pcap_t* handle, BYTE* srcMAC, ULONG scrIP, ULONG targetIP);

// ��ARP���н���MAC��ַ
int get_mac(pcap_t* p, ULONG targetIP, ULONG scrIP, BYTE* mac);

// ��ӡIP���ݰ�
void print_ip_packet(Data_t* IPPacket);

// ����У���
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

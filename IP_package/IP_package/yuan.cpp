#include<iostream>
#include<pcap.h>
#include<cstring>
#include<winsock2.h>
#include <ws2tcpip.h>


using namespace std;


#pragma pack(1)		//�����ֽڶ��뷽ʽ

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

#pragma pack()		//�ָ�ȱʡ���뷽ʽ

void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
	Data_t* data = (Data_t*)packet;

	// ��ӡĿ�� MAC ��ַ
	cout << "Ŀ�� MAC: ";
	for (int i = 0; i < 6; i++) {
		cout << hex << (int)data->FrameHeader.DesMAC[i];
		if (i < 5) cout << ":";
	}
	cout << endl;

	// ��ӡԴ MAC ��ַ
	cout << "Դ MAC: ";
	for (int i = 0; i < 6; i++) {
		cout << hex << (int)data->FrameHeader.SrcMAC[i];
		if (i < 5) cout << ":";
	}
	cout << endl;

	// ��ӡ֡����
	cout << "֡����: " << ntohs(data->FrameHeader.FrameType) << endl;

	//��ӡIP�ײ���Ϣ
	cout << "IP�ײ���Ϣ��" << endl;
	cout << "�汾: IPv " << hex << (data->IPHeader.Ver_HLen & 0xF0) / 16 << endl;
	cout << "ͷ������: " << (data->IPHeader.Ver_HLen & 0x0F) << endl;
	cout << "��������: " << hex << static_cast<int>(data->IPHeader.TOS) << endl;
	cout << "�ܳ���: " << hex << ntohs(data->IPHeader.TotalLen) << endl;
	cout << "��ʶ: " << hex << ntohs(data->IPHeader.ID) << endl;
	cout << "��־/Ƭ��ƫ��: " << hex << ntohs(data->IPHeader.Flag_Segment) << endl;
	cout << "TTL: " << dec << static_cast<int>(data->IPHeader.TTL) << endl;
	cout << "Э��: " << hex << static_cast<int>(data->IPHeader.Protocol) << endl;
	cout << "У���: " << hex << ntohs(data->IPHeader.Checksum) << endl;

	//��ӡԴIP��ַ��Ŀ��IP��ַ
	ULONG SourceIP, DestinationIP;
	SourceIP = ntohl(data->IPHeader.SrcIP);
	DestinationIP = ntohl(data->IPHeader.DstIP);
	//��ULONGת��Ϊ���ʮ���Ƹ�ʽ
	struct in_addr src_addr, dst_addr;
	src_addr.s_addr = SourceIP;
	dst_addr.s_addr = DestinationIP;
	char src_ip_str[INET_ADDRSTRLEN]; // ���Դ IP �ַ���
	char dst_ip_str[INET_ADDRSTRLEN]; // ���Ŀ�� IP �ַ���

	// ʹ��inet_ntopת��IP��ַ
	inet_ntop(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &dst_addr, dst_ip_str, INET_ADDRSTRLEN);

	cout << "ԴIP��ַΪ��" << src_ip_str << endl;
	cout << "Ŀ��IP��ַΪ��" << dst_ip_str << endl;

	cout << endl;

}


int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_addr_t* a;
	int devs_count = 0;

	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������

	//��ȡ�������豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,	//��ȡ�����Ľӿ��豸
		NULL,				//������֤
		&alldevs,			//ָ���豸�б��ײ�
		errbuf				//������Ϣ���滺����
	) == -1)
	{
		cout << "��ȡ�����豸�б�ʱ����:" << errbuf << endl;
		return 1;
	}

	//��ʾ�ӿ��б�
	for (d = alldevs; d != NULL; d = d->next)
	{
		devs_count++;
		//��ӡ����ӿ��豸�����ֺ�������Ϣ
		cout << devs_count << ". " << d->name << "->" << d->description << ";" << endl;
		////��ȡ����ӿ��豸��IP��ַ��Ϣ
		//for (a = d->addresses; a != NULL; a = a->next)
		//{
		//	if (a->addr->sa_family == AF_INET)
		//	{
		//		cout << "IP��ַ��" << a->addr << endl;
		//		cout << "�������룺" << a->netmask << endl;
		//		cout << "�㲥��ַ��" << a->broadaddr << endl;
		//		cout << "Ŀ�ĵ�ַ��" << a->dstaddr << endl;
		//	}
		//}
	}
	cout << "��ѡ���豸��1-" << devs_count << "):" << endl;
	int dev_select_num = 0;
	cin >> dev_select_num;
	pcap_if_t* dev_select = alldevs;

	for (int i = 0; i < dev_select_num - 1; i++)
	{
		dev_select = dev_select->next;
	}
	a = dev_select->addresses;
	cout << "��ѡ����豸��ϢΪ��" << dev_select->name << ";" << endl;

	//��ӡ����ӿ��豸��IP��ַ��Ϣ
	if (a->addr->sa_family == AF_INET)
	{
		cout << "IP��ַ��" << a->addr << endl;
		cout << "�������룺" << a->netmask << endl;
		cout << "�㲥��ַ��" << a->broadaddr << endl;
		cout << "Ŀ�ĵ�ַ��" << a->dstaddr << endl;
	};
	cout << endl;

	
	//������ӿ�
	pcap_t* handle = pcap_open_live(dev_select->name, BUFSIZ, 1, 1000, errbuf);
	/*if (pcap_open == NULL)
	{
		cout << "���豸" << dev_select_num << "������ӿ�ʧ�ܣ�" << errbuf << endl;
		return 1;
	}*/

	//�����������ݰ�
	pcap_loop(handle, 5, packet_handler, NULL);

	

	pcap_freealldevs(alldevs);
	pcap_close(handle);


	return 0;
}
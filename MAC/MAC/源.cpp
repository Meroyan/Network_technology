//#include<iostream>
//#include<winsock2.h>
//#include<pcap.h>
//#pragma comment(lib,"wpcap.lib")
//#pragma comment(lib,"packet.lib")
//#pragma comment(lib,"ws2_32.lib")
//#pragma warning(disable:4996)
//using namespace std;
//
//#define IPTOSBUFFERS 12
//string HostIP;
//string HostBroadaddr;
//BYTE HostMAC[6];
//int flag = 0;
//
//#pragma pack(1)//�����ֽڶ��뷽ʽ
//
////����֡�ײ�
//typedef struct FrameHeader_t {
//	BYTE DesMAC[6];		//Ŀ�ĵ�ַ
//	BYTE SrcMAC[6];		//Դ��ַ
//	WORD FrameType;		//֡����
//}FrameHeader_t;
//
////����IP�ײ�
//typedef struct IPHeader_t {
//	BYTE Ver_HLen;		//IP�汾��ͷ������
//	BYTE TOS;			//��������
//	WORD TotalLen;		//�ܳ���
//	WORD ID;			//��ʶ
//	WORD Flag_Segment;	//Ƭƫ��
//	BYTE TTL;			//����ʱ��
//	BYTE Protocol;		//Э��
//	WORD Checksum;		//�ײ�У���
//	ULONG SrcIP;		//ԴIP
//	ULONG DstIP;		//Ŀ��IP
//}IPHeader_t;
//
////�������֡�ײ���IP�ײ������ݰ�
//typedef struct Data_t {
//	FrameHeader_t FrameHeader;
//	IPHeader_t IPHeader;
//}Data_t;
//
////����ARP֡
//typedef struct ARPFrame_t {
//	FrameHeader_t FrameHeader;
//	WORD HardwareType;	//Ӳ������
//	WORD ProtocolType;	//Э������
//	BYTE HLen;			//Ӳ����ַ����
//	BYTE PLen;			//Э���ַ����
//	WORD Operation;		//����
//	BYTE SendHa[6];		//ԴMAC��ַ
//	DWORD SendIP;		//ԴIP��ַ
//	BYTE RecvHa[6];		//Ŀ��MAC��ַ
//	DWORD RecvIP;		//Ŀ��IP��ַ
//}ARPFrame_t;
//
//#pragma pack()    //�ָ�ȱʡ���뷽ʽ
//
//
//void get_host_mac(pcap_t* handle, ARPFrame_t ARPFrame)
//{
//    struct pcap_pkthdr* packet_header;
//    const u_char* packet_data;
//    Data_t* packet;
//
//    for (int i = 0; i < 6; i++)
//    {
//        ARPFrame.FrameHeader.DesMAC[i] = 0xff; //Ŀ��Mac��ַ����Ϊ�㲥��ַ
//        ARPFrame.FrameHeader.SrcMAC[i] = HostMAC[i]; //ԴMAC��ַ����Ϊ��������MAC��
//        ARPFrame.SendHa[i] = i;
//        ARPFrame.RecvHa[i] = 0x00; //Ŀ��MAC��ַ����Ϊ0
//    }
//    ARPFrame.SendIP = inet_addr("110.110.110.110"); //ԴIP��ַ�������һ��
//    ARPFrame.RecvIP = inet_addr(HostIP.c_str()); //Ŀ��IP��ַΪ������ַ
//
//    //�������ݰ�
//    if (pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0);
//
//    //ץȡ�Լ������İ����Ӷ�����Լ���MAC��ַ
//    int res = 0;
//    while ((res = pcap_next_ex(handle, &packet_header, &packet_data)) >= 0)
//    {
//        if (res == 0) continue; //�������ݰ���ʱ
//
//        packet = (Data_t*)packet_data;
//        if (inet_ntoa(*(in_addr*)&packet->IPHeader.SrcIP) == HostIP) 
//        {
//            for (int i = 0; i < 6; i++)
//            {
//                HostMAC[i] = packet->FrameHeader.SrcMAC[i];
//            }
//            cout << "�����ӿ�IP��ַ��Ӧ��MAC��ַ��\n" << HostIP;
//            printf(" --> %02X-%02X-%02X-%02X-%02X-%02X\n\n",
//                (unsigned int)HostMAC[0],
//                (unsigned int)HostMAC[1],
//                (unsigned int)HostMAC[2],
//                (unsigned int)HostMAC[3],
//                (unsigned int)HostMAC[4],
//                (unsigned int)HostMAC[5]);
//            break;
//        }
//    }
//
//}
//
//void GetMAC(pcap_t* adhandle, ARPFrame_t ARPFrame)
//{
//    struct pcap_pkthdr* packet_header;
//    const u_char* packet_data;
//    Data_t* packet;
//
//    cout << "������IP��ַ��";
//    string IP;
//    cin >> IP;
//
//    //ARP���ݰ�
//    for (int i = 0; i < 6; i++)
//    {
//        ARPFrame.FrameHeader.DesMAC[i] = 0xff; //Ŀ��Mac��ַ����Ϊ�㲥��ַ
//        ARPFrame.FrameHeader.SrcMAC[i] = HostMAC[i]; //ԴMAC��ַ����Ϊ��������MAC��
//        ARPFrame.SendHa[i] = HostMAC[i]; //ԴMAC��ַ����Ϊ��������MAC��ַ
//        ARPFrame.RecvHa[i] = 0x00; //Ŀ��MAC��ַ����Ϊ0
//    }
//    ARPFrame.SendIP = inet_addr(HostIP.c_str()); //��������IP��ַ
//    ARPFrame.RecvIP = inet_addr(IP.c_str()); //Ŀ��IP��ַ
//
//    //�������ݰ�
//    pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
//
//    //����Ŀ��IPΪ����IP��ԭʼIPΪ����IP�����ݰ�
//    int res = 0;
//    while ((res = pcap_next_ex(adhandle, &packet_header, &packet_data)) >= 0)
//    {
//        if (res == 0) continue; //�������ݰ���ʱ
//
//        ARPFrame_t* ARP_Packet = (ARPFrame_t*)packet_data;
//        string desIP = inet_ntoa(*(in_addr*)&ARP_Packet->RecvIP);
//        string srcIP = inet_ntoa(*(in_addr*)&ARP_Packet->SendIP);
//        if ((desIP == HostIP) && (srcIP == IP))
//        {
//            BYTE MACs[6];
//            for (int i = 0; i < 6; i++)
//            {
//                MACs[i] = ARP_Packet->FrameHeader.SrcMAC[i];
//            }
//
//            cout << IP;
//            printf(" --> %02X-%02X-%02X-%02X-%02X-%02X\n\n",
//                (unsigned int)MACs[0],
//                (unsigned int)MACs[1],
//                (unsigned int)MACs[2],
//                (unsigned int)MACs[3],
//                (unsigned int)MACs[4],
//                (unsigned int)MACs[5]);
//
//            break;
//        }
//    }
//}
//
//int main()
//{
//    int i = 0;
//    int num = 0; //�ӿ����
//    pcap_if_t* alldevs; //ָ���豸�����ײ���ָ��
//    pcap_if_t* d;
//    pcap_addr_t* a; //��ʾ�ӿڵ�ַָ��
//    char errbuf[PCAP_ERRBUF_SIZE]; //������Ϣ������
//
//    //��ȡ��ǰ�����б�
//    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, //��ȡ�����Ľӿ��豸
//        NULL, //������֤
//        &alldevs, //ָ���豸�б��ײ�
//        errbuf //������Ϣ���滺����
//    ) == -1)
//    {
//        cout << "��ȡ���������б�ʱ����:" << errbuf << endl;
//        return 1;
//    }
//
//    //��ӡ�������б�
//    for (d = alldevs; d != NULL; d = d->next)
//    {
//        num++;
//        //��ӡ����ӿ��豸�����ֺ�������Ϣ
//        cout << num << ". " << d->name << "->" << d->description << ";" << endl;
//    }
//
//    //ѡ������
//    cout << "��ѡ���豸��1-" << num << "):" << endl;
//    int dev_select_num = 0;
//    cin >> dev_select_num;
//
//    while (dev_select_num < 1 || dev_select_num > num)
//    {
//        cout << "�ַ��Ƿ������������루1-" << num << "):" << endl;
//        cin >> dev_select_num;
//        if (dev_select_num >= 1 && dev_select_num <= num)
//        {
//            break;
//        }
//    }
//
//    //ת��ѡ����豸
//    for (d = alldevs, i = 0; i < dev_select_num - 1; i++)
//    {
//        d = d->next;
//    }
//
//    //��ӡѡ����豸����ϸ��Ϣ
//    cout << "��ѡ����豸��ϢΪ��" << d->name << ";" << endl;
//    cout << "������Ϣ��" << d->description << endl;
//
//    for (a = d->addresses; a != NULL; a = a->next)
//    {
//        if (a->addr->sa_family == AF_INET)
//        {
//            cout << "IP��ַ��" << inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr) << endl;
//            HostIP = inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);
//
//            cout << "�������룺" << inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr) << endl;
//            cout << "�㲥��ַ��" << inet_ntoa(((struct sockaddr_in*)a->broadaddr)->sin_addr) << endl;
//            HostBroadaddr = inet_ntoa(((struct sockaddr_in*)a->broadaddr)->sin_addr);
//            cout << endl;
//            break;
//        }
//    }
//
//    //������ӿ�
//    pcap_t* handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
//    if (pcap_open == NULL)
//    {
//        cout << "���豸" << dev_select_num << "������ӿ�ʧ�ܣ�" << errbuf << endl;
//        return 1;
//    }
//
//    //���巢�͵�ARP������ʼ��
//    ARPFrame_t ARPFrame;
//    
//    ARPFrame.FrameHeader.FrameType = htons(0x8086); //֡����ΪARP
//    ARPFrame.HardwareType = htons(0x0001); //Ӳ������Ϊ��̫��
//    ARPFrame.ProtocolType = htons(0x0800); //Э������ΪIP
//    ARPFrame.HLen = 6; //Ӳ����ַ����Ϊ6
//    ARPFrame.PLen = 4; //Э���ַ����Ϊ4
//    ARPFrame.Operation = htons(0x0001); //����ΪARP����
//
//
//    get_host_mac(handle, ARPFrame);
//
//    //��ô˾�����������һ��IP��ַ��Ӧ��MAC��ַ
//    while (1)
//    {
//        //GetMAC(handle, ARPFrame);
//    }
//
//
//    //�ͷ��б�
//    pcap_freealldevs(alldevs);
//
//
//    return 0;
//}

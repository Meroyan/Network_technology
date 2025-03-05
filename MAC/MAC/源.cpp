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
//#pragma pack(1)//进入字节对齐方式
//
////定义帧首部
//typedef struct FrameHeader_t {
//	BYTE DesMAC[6];		//目的地址
//	BYTE SrcMAC[6];		//源地址
//	WORD FrameType;		//帧类型
//}FrameHeader_t;
//
////定义IP首部
//typedef struct IPHeader_t {
//	BYTE Ver_HLen;		//IP版本和头部长度
//	BYTE TOS;			//服务类型
//	WORD TotalLen;		//总长度
//	WORD ID;			//标识
//	WORD Flag_Segment;	//片偏移
//	BYTE TTL;			//生存时间
//	BYTE Protocol;		//协议
//	WORD Checksum;		//首部校验和
//	ULONG SrcIP;		//源IP
//	ULONG DstIP;		//目的IP
//}IPHeader_t;
//
////定义包含帧首部和IP首部的数据包
//typedef struct Data_t {
//	FrameHeader_t FrameHeader;
//	IPHeader_t IPHeader;
//}Data_t;
//
////定义ARP帧
//typedef struct ARPFrame_t {
//	FrameHeader_t FrameHeader;
//	WORD HardwareType;	//硬件类型
//	WORD ProtocolType;	//协议类型
//	BYTE HLen;			//硬件地址长度
//	BYTE PLen;			//协议地址长度
//	WORD Operation;		//操作
//	BYTE SendHa[6];		//源MAC地址
//	DWORD SendIP;		//源IP地址
//	BYTE RecvHa[6];		//目的MAC地址
//	DWORD RecvIP;		//目的IP地址
//}ARPFrame_t;
//
//#pragma pack()    //恢复缺省对齐方式
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
//        ARPFrame.FrameHeader.DesMAC[i] = 0xff; //目的Mac地址设置为广播地址
//        ARPFrame.FrameHeader.SrcMAC[i] = HostMAC[i]; //源MAC地址设置为本机网卡MAC地
//        ARPFrame.SendHa[i] = i;
//        ARPFrame.RecvHa[i] = 0x00; //目的MAC地址设置为0
//    }
//    ARPFrame.SendIP = inet_addr("110.110.110.110"); //源IP地址随便设置一个
//    ARPFrame.RecvIP = inet_addr(HostIP.c_str()); //目的IP地址为本机地址
//
//    //发送数据包
//    if (pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0);
//
//    //抓取自己发出的包，从而获得自己的MAC地址
//    int res = 0;
//    while ((res = pcap_next_ex(handle, &packet_header, &packet_data)) >= 0)
//    {
//        if (res == 0) continue; //接收数据包超时
//
//        packet = (Data_t*)packet_data;
//        if (inet_ntoa(*(in_addr*)&packet->IPHeader.SrcIP) == HostIP) 
//        {
//            for (int i = 0; i < 6; i++)
//            {
//                HostMAC[i] = packet->FrameHeader.SrcMAC[i];
//            }
//            cout << "本机接口IP地址对应的MAC地址：\n" << HostIP;
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
//    cout << "请输入IP地址：";
//    string IP;
//    cin >> IP;
//
//    //ARP数据包
//    for (int i = 0; i < 6; i++)
//    {
//        ARPFrame.FrameHeader.DesMAC[i] = 0xff; //目的Mac地址设置为广播地址
//        ARPFrame.FrameHeader.SrcMAC[i] = HostMAC[i]; //源MAC地址设置为本机网卡MAC地
//        ARPFrame.SendHa[i] = HostMAC[i]; //源MAC地址设置为本机网卡MAC地址
//        ARPFrame.RecvHa[i] = 0x00; //目的MAC地址设置为0
//    }
//    ARPFrame.SendIP = inet_addr(HostIP.c_str()); //本机网卡IP地址
//    ARPFrame.RecvIP = inet_addr(IP.c_str()); //目的IP地址
//
//    //发送数据包
//    pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
//
//    //监听目的IP为本机IP，原始IP为输入IP的数据包
//    int res = 0;
//    while ((res = pcap_next_ex(adhandle, &packet_header, &packet_data)) >= 0)
//    {
//        if (res == 0) continue; //接收数据包超时
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
//    int num = 0; //接口序号
//    pcap_if_t* alldevs; //指向设备链表首部的指针
//    pcap_if_t* d;
//    pcap_addr_t* a; //表示接口地址指针
//    char errbuf[PCAP_ERRBUF_SIZE]; //错误信息缓冲区
//
//    //获取当前网卡列表
//    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, //获取本机的接口设备
//        NULL, //无需认证
//        &alldevs, //指向设备列表首部
//        errbuf //出错信息保存缓冲区
//    ) == -1)
//    {
//        cout << "获取本机网卡列表时出错:" << errbuf << endl;
//        return 1;
//    }
//
//    //打印网卡的列表
//    for (d = alldevs; d != NULL; d = d->next)
//    {
//        num++;
//        //打印网络接口设备的名字和描述信息
//        cout << num << ". " << d->name << "->" << d->description << ";" << endl;
//    }
//
//    //选择网卡
//    cout << "请选择设备（1-" << num << "):" << endl;
//    int dev_select_num = 0;
//    cin >> dev_select_num;
//
//    while (dev_select_num < 1 || dev_select_num > num)
//    {
//        cout << "字符非法，请重新输入（1-" << num << "):" << endl;
//        cin >> dev_select_num;
//        if (dev_select_num >= 1 && dev_select_num <= num)
//        {
//            break;
//        }
//    }
//
//    //转到选择的设备
//    for (d = alldevs, i = 0; i < dev_select_num - 1; i++)
//    {
//        d = d->next;
//    }
//
//    //打印选择的设备的详细信息
//    cout << "您选择的设备信息为：" << d->name << ";" << endl;
//    cout << "描述信息：" << d->description << endl;
//
//    for (a = d->addresses; a != NULL; a = a->next)
//    {
//        if (a->addr->sa_family == AF_INET)
//        {
//            cout << "IP地址：" << inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr) << endl;
//            HostIP = inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);
//
//            cout << "子网掩码：" << inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr) << endl;
//            cout << "广播地址：" << inet_ntoa(((struct sockaddr_in*)a->broadaddr)->sin_addr) << endl;
//            HostBroadaddr = inet_ntoa(((struct sockaddr_in*)a->broadaddr)->sin_addr);
//            cout << endl;
//            break;
//        }
//    }
//
//    //打开网络接口
//    pcap_t* handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
//    if (pcap_open == NULL)
//    {
//        cout << "打开设备" << dev_select_num << "的网络接口失败：" << errbuf << endl;
//        return 1;
//    }
//
//    //定义发送的ARP包并初始化
//    ARPFrame_t ARPFrame;
//    
//    ARPFrame.FrameHeader.FrameType = htons(0x8086); //帧类型为ARP
//    ARPFrame.HardwareType = htons(0x0001); //硬件类型为以太网
//    ARPFrame.ProtocolType = htons(0x0800); //协议类型为IP
//    ARPFrame.HLen = 6; //硬件地址长度为6
//    ARPFrame.PLen = 4; //协议地址长度为4
//    ARPFrame.Operation = htons(0x0001); //操作为ARP请求
//
//
//    get_host_mac(handle, ARPFrame);
//
//    //获得此局域网内任意一个IP地址对应的MAC地址
//    while (1)
//    {
//        //GetMAC(handle, ARPFrame);
//    }
//
//
//    //释放列表
//    pcap_freealldevs(alldevs);
//
//
//    return 0;
//}

#include "router.h"

int main()
{
	pcap_if_t* alldevs = nullptr;	//ָ���豸�����ײ���ָ��
	pcap_if_t* d = nullptr;
	pcap_addr_t* a = nullptr;		//��ʾ�ӿڵ�ַָ��

	router_table* rt = new router_table[ROUTER_TABLE_SIZE];
	int rt_length = 0;//·�ɱ�ĳ�ʼ����

	ULONG local_ip;
	BYTE local_mac[6];

	int num = 0;

	// ��ʼ��
	num = in_dev(alldevs, d, a);

	//ѡ������
	cout << "��ѡ���豸��1-" << num << "):" << endl;
	int dev_select_num = 0;
	cin >> dev_select_num;

	while (dev_select_num < 1 || dev_select_num > num)
	{
		cout << "�ַ��Ƿ������������루1-" << num << "):" << endl;
		cin >> dev_select_num;
		if (dev_select_num >= 1 && dev_select_num <= num)
		{
			break;
		}
	}

	//ת��ѡ����豸
	d = alldevs;
	for (int i = 0; i < dev_select_num - 1; i++)
	{
		d = d->next;
	}

	//��ӡѡ����豸����ϸ��Ϣ
	cout << "��ѡ����豸��ϢΪ��" << d->name << ";" << endl;
	cout << "������Ϣ��" << d->description << endl;

	//��ӡѡ��������IP���������롢�㲥��ַ
	for (a = d->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			cout << "IP��ַ��";
			printIP((((sockaddr_in*)a->addr)->sin_addr).s_addr);
			local_ip = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));

			cout << "   ";
			cout << "�������룺";
			printIP((((sockaddr_in*)a->netmask)->sin_addr).s_addr);
			cout << "   ";
			cout << "�㲥��ַ��";
			printIP((((sockaddr_in*)a->broadaddr)->sin_addr).s_addr);
			cout << endl;

			ULONG NetMask, DesNet, NextHop;
			DesNet = (((sockaddr_in*)a->addr)->sin_addr).s_addr;
			NetMask = (((sockaddr_in*)a->netmask)->sin_addr).s_addr;
			DesNet = DesNet & NetMask;
			NextHop = 0;
			router_table temp;
			temp.netmask = NetMask;
			temp.desnet = DesNet;
			temp.nexthop = NextHop;
			
			// ������Ϣ��ΪĬ��·��
			additem(rt, rt_length, temp);
		}
	}

	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������

	//������ӿ�
	pcap_t* handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
	if (pcap_open == NULL)
	{
		cout << "���豸" << dev_select_num << "������ӿ�ʧ�ܣ�" << errbuf << endl;
		return 1;
	}

	// ���ù�����
	set_filter(handle, d);

	// ����ARP�����ȡ����MAC��ַ
	BYTE scrMAC[6] = { 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 };
	ULONG virIP = inet_addr("112.112.112.112");
	send_arp_req(handle, scrMAC, virIP, local_ip);
	get_mac(handle, local_ip, virIP, local_mac);

	cout << " ����IP��";
	printIP(local_ip);
	cout << "    ����MAC��";
	for (int i = 0; i < 6; i++)
	{
		cout << hex << (int)local_mac[i];
		if (i != 5)cout << "-";
		else cout << endl;
	}


LOOP:

	ULONG DesNet, NetMask, NextHop;
	char* desnet = new char[20];
	char* netmask = new char[20];
	char* nexthop = new char[20];

	int op1, fin = 1;
	cout << "�Ƿ�Ҫ�޸�·�ɱ�:" << endl;
	cout << "  1.��\n  2.��" << endl;
	cin >> op1;

	if (op1 == 2)
	{
		fin = 0;
		cout << "��ǰ·�ɱ�Ϊ��" << endl;
		print_rt(rt, rt_length);
	}

	while (fin)
	{
		int op2 = 0;
		cout << "��ѡ����Ҫ���еĲ���:" << endl;
		cout << "  1.����·�ɱ���\n  2.ɾ��·�ɱ���\n  3.��ӡ��ǰ·�ɱ�" << endl;

		cin >> op2;

		if (op2 == 1)
		{
			cout << " [����] ������Ŀ�������:";
			cin >> desnet;
			cout << " [����] ��������������:";
			cin >> netmask;
			cout << " [����] ��������һ����:";
			cin >> nexthop;

			DesNet = inet_addr(desnet);
			NetMask = inet_addr(netmask);
			NextHop = inet_addr(nexthop);

			router_table addRoute;
			addRoute.desnet = DesNet;
			addRoute.netmask = NetMask;
			addRoute.nexthop = NextHop;

			//addRoute(desnet, netmask, nexthop);
			additem(rt, rt_length, addRoute);

		}

		if (op2 == 2)
		{
			int num = 0;
			cout << " [ɾ��] ������Ҫɾ����·����������";
			cin >> num;

			if (num == 0 || num == 1)
			{
				cout << " [����] ����ɾ��Ĭ��·�ɣ�" << endl;
			}
			else
				deleteitem(rt, rt_length, num);

		}

		if (op2 == 3)
		{
			print_rt(rt, rt_length);
		}

		else if (op2 < 0 || op2 > 4)
		{
			cout << " [����] ����Ƿ�������������" << endl;
		}

		int op3;
		cout << "�Ƿ�Ҫ�޸�·�ɱ�:" << endl;
		cout << "  1.��\n  2.��" << endl;
		cin >> op3;

		if (op3 == 2)
		{
			fin = 0;
			cout << "��ǰ·�ɱ�Ϊ��" << endl;
			print_rt(rt, rt_length);
			break;
		}

	}


	ULONG nextIP;  // ·�ɵ���һվ
	BYTE nextMac[6];
	int Count = 0;  // ���ʹ���
	Data_t* IPPacket;
	pcap_pkthdr* pkt_header = new pcap_pkthdr[1500];
	const u_char* pkt_data;

	while (1)
	{
		int ret = pcap_next_ex(handle, &pkt_header, &pkt_data);  // ��ȡ���ݰ�

		if (ret) 
		{
			IPPacket = (Data_t*)pkt_data;

			// �洢
			ULONG Len = pkt_header->len + sizeof(FrameHeader_t);
			u_char* send_packet = new u_char[Len];
			//memcpy(send_packet, pkt_data, Len);
			for (int i = 0; i < Len; i++)
			{
				send_packet[i] = pkt_data[i];
			}

			WORD FrameType = IPPacket->FrameHeader.FrameType;
			WORD RecvChecksum = IPPacket->IPHeader.Checksum;
			IPPacket->IPHeader.Checksum = 0;

			// ������ݰ���Ŀ��IP�뱾��IP�Ƿ�һ�£�һ��1����һ��0
			bool ip_compare = 1;
			for (int i = 0; i < 6; i++)
			{
				if (local_ip != IPPacket->IPHeader.DstIP)
				{
					ip_compare = 0;
				}
			}

			// ������ݰ���Ŀ��MAC�뱾��MAC�Ƿ�һ�£�һ��1����һ��0
			bool mac_compare = 1;
			for (int i = 0; i < 6; i++)
			{
				if (local_mac[i] != IPPacket->FrameHeader.DesMAC[i])
				{
					mac_compare = 0;
				}
			}

			// ����Ƿ���IPV4����1������0
			bool is_ipv4 = (FrameType == 0x0800);

			// ���Ŀ��IP���Ǳ���IP��Ŀ��MAC��ַ�Ǳ���MAC--ת��
			if (is_ipv4 && !ip_compare && mac_compare)
			{
				print_ip_packet(IPPacket);

				// ѡ·
				nextIP = search(rt, rt_length, IPPacket->IPHeader.DstIP);

				if (nextIP == 0)
				{
					nextIP = IPPacket->IPHeader.DstIP;
				}
				else if (nextIP == 0xffffffff)
				{
					cout << " [����] ���ɴ�޷�ת�����ݰ��������ԣ�" << endl;
					Count = 8;
				}

				// ����ARP���󣬻�ȡ��һ��MAC
				send_arp_req(handle, local_mac, local_ip, nextIP);
				get_mac(handle, nextIP, local_ip, nextMac);

				cout << " ��һ��IP��";
				printIP(nextIP);
				cout << "    ��һ��MAC��";
				for (int i = 0; i < 6; i++)
				{
					cout << hex << (int)nextMac[i];
					if (i != 5)cout << "-";
					else cout << endl;
				}

				// ����IP���ݰ���Ŀ��MAC��ַ
				Data_t* temp_packet;
				temp_packet = (Data_t*)send_packet;
				for (int i = 0; i < 6; i++)
				{
					temp_packet->FrameHeader.DesMAC[i] = nextMac[i];
				}

				// TTL��1
				temp_packet->IPHeader.TTL -= 1;

				temp_packet->IPHeader.Checksum = 0;  // ����У���
				setchecksum(temp_packet);

				// ���޸ĺ��TTLͬ��
				memcpy(temp_packet + sizeof(FrameHeader_t) + offsetof(IPHeader_t, TTL), &temp_packet->IPHeader.TTL, sizeof(temp_packet->IPHeader.TTL));

				// ͬ��У���
				memcpy(temp_packet + sizeof(FrameHeader_t) + offsetof(IPHeader_t, Checksum), &temp_packet->IPHeader.Checksum, sizeof(temp_packet->IPHeader.Checksum));

				// ����
				if (!pcap_sendpacket(handle, send_packet, Len))
				{
					Data_t* t;
					t = (Data_t*)send_packet;
					cout << " [ת��] ";
					print_ip_packet(t);

					Count++;

					cout << endl;
				}

				if (Count == 8)
					break;

			}

		}

		if (Count == 8)
			goto LOOP;

	}

	return 0;
}


// ��
int in_dev(pcap_if_t*& alldevs, pcap_if_t*& d, pcap_addr_t*& a)
{
	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������

	//��ȡ��ǰ�����б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, //��ȡ�����Ľӿ��豸
		NULL, //������֤
		&alldevs, //ָ���豸�б��ײ�
		errbuf //������Ϣ���滺����
	) == -1)
	{
		cout << "��ȡ���������б�ʱ����:" << errbuf << endl;
		return 0;
	}

	int num = 0;

	// ��ӡ�������б�
	for (d = alldevs; d != NULL; d = d->next)
	{
		num++;
		cout << num << ". " << d->name << "->" << d->description << ";" << endl;

		for (a = d->addresses; a != NULL; a = a->next)
		{
			if (a->addr->sa_family == AF_INET)
			{
				cout << "IP��ַ��";
				printIP((((sockaddr_in*)a->addr)->sin_addr).s_addr);
				cout << "   ";
				cout << "�������룺";
				printIP((((sockaddr_in*)a->netmask)->sin_addr).s_addr);
				cout << "   ";
				cout << "�㲥��ַ��";
				printIP((((sockaddr_in*)a->broadaddr)->sin_addr).s_addr);
				cout << endl << endl;
			}
		}
	}

	return num;
}

// ��·��ѡ�������ƥ�䣬����ֵΪ��һ����IP��ַ
ULONG search(router_table* t, int tLength, ULONG DesIP)
{
	ULONG best_desnet = 0;  //����ƥ���Ŀ������
	int best = -1;
	for (int i = 0; i < tLength; i++)
	{
		if ((t[i].netmask & DesIP) == t[i].desnet)
		{
			if (t[i].desnet >= best_desnet)//�ƥ��
			{
				best_desnet = t[i].desnet;
				best = i;
			}
		}
	}

	if (best == -1)
		return 0xffffffff;
	else
		return t[best].nexthop;
}

// �̼������������ǰ׺����
int get_pre_length(int netmask) 
{
	int length = 0;
	while (netmask) 
	{
		netmask &= (netmask - 1);
		length++;
	}
	return length;
}

// ����·�ɱ�����������ʱ��ǰ׺��������
bool additem(router_table* t, int& tLength, router_table item) 
{
	if (tLength == ROUTER_TABLE_SIZE)  // ·�ɱ������������
	{
		cout << " [����] ���ʧ�ܣ�·�ɱ�������������ɾ�������õı��" << endl;
		return false;
	}

	// ���·�ɱ����Ƿ��Ѵ�����ͬ��·����
	for (int i = 0; i < tLength; i++) {
		if (t[i].desnet == item.desnet && t[i].netmask == item.netmask && t[i].nexthop == item.nexthop) 
		{
			cout << " [����] ���ʧ�ܣ��Ѵ�����ͬ·�ɱ��" << endl;
			return false;  // ����Ѵ�����ȫ��ͬ��·�������false
		}
	}

	// ��ȡ��·�����ǰ׺����
	int itemPrefixLength = get_pre_length(item.netmask);

	// ��������뵽·�ɱ��У�������·�ɱ�ǰ׺��������
	int insertIndex = tLength;
	for (int i = 0; i < tLength; i++) {
		// ͨ���Ƚ�ǰ׺��������������λ�ã�ǰ׺���ȳ�������ǰ��
		int existingPrefixLength = get_pre_length(t[i].netmask);
		if (existingPrefixLength < itemPrefixLength) {
			insertIndex = i;
			break;
		}
	}

	// ��Ԫ�ز��뵽�ҵ��ĺ���λ��
	for (int i = tLength; i > insertIndex; i--) {
		t[i] = t[i - 1];  // ����ƶ�Ԫ�أ�Ϊ�����ڳ��ռ�
	}

	t[insertIndex] = item;  // ������ŵ���ȷ��λ��
	tLength++;  // ����·�ɱ�ĳ���
	cout << " [����] ��ӳɹ�����ǰ·�ɱ�Ϊ��" << endl;
	print_rt(t, tLength);

	return true;
}

// �̴�·�ɱ���ɾ����
bool deleteitem(router_table* t, int& tLength, int index)
{
	if (tLength == 0)   //·�ɱ�գ�����ɾ��
	{
		cout << " [����] ɾ��ʧ�ܣ���ǰ·�ɱ�Ϊ�ձ�" << endl;
		return false;

	}

	if (index == 0 || index == 1)
	{
		cout << " [����] ɾ��ʧ�ܣ�����ɾ��Ĭ��·��" << endl;
		return false;
	}

	for (int i = 0; i < tLength; i++)
	{
		if (i == index)   //ɾ����index�����ı���
		{
			for (; i < tLength - 1; i++)
				t[i] = t[i + 1];
			tLength = tLength - 1;
			cout << " [ɾ��] ɾ���ɹ�����ǰ·�ɱ�Ϊ��" << endl;
			print_rt(t, tLength);
			
			return true;
		}
	}

	cout << " [����] ɾ��ʧ�ܣ���ǰ·�ɱ��в����ڸ��" << endl;
	return false;   //·�ɱ��в����ڸ�������ɾ��
}

// ��ӡ·�ɱ�
void print_rt(router_table* t, int& tLength)
{
	cout << setfill('-') << setw(10) << ""
		<< setw(25) << ""
		<< setw(25) << ""
		<< setw(25) << ""
		<< setfill(' ') << endl;

	cout << left << setw(10) << "����"
		<< setw(25) << "Ŀ������"
		<< setw(25) << "��������"
		<< setw(25) << "��һվ·��"
		<< endl;

	cout << setfill('-') << setw(10) << ""
		<< setw(25) << ""
		<< setw(25) << ""
		<< setw(25) << ""
		<< setfill(' ') << endl;

	for (int i = 0; i < tLength; i++) {
		cout << i;
		cout << setw(7) << "";
		printIP(t[i].desnet);
		cout << setw(12) << "";
		printIP(t[i].netmask);
		cout << setw(15) << "";
		printIP(t[i].nexthop);
		cout << setw(10) << "";
		cout << endl;
	}

	cout << setfill('-') << setw(10) << ""
		<< setw(25) << ""
		<< setw(25) << ""
		<< setw(25) << ""
		<< setfill(' ') << endl;

	cout << endl;
}

//
void addRoute(const string& desnet, const string& netmask, const string& nexthop) {
	// ƴ�������ַ���
	string cmd = "route add " + desnet + " mask " + netmask + " " + nexthop;

	// ����ϵͳ����
	int result = system(cmd.c_str());

	if (result == 0) {
		cout << "[���] ·�ɳɹ�!" << endl;
	}
	else {
		cout << "[����] ���·��ʧ��!" << endl;
	}
}

// ��·�ɱ����ݽ��в���
int router_op(router_table* rt, int& rt_length)
{
	ULONG DesNet, NetMask, NextHop;
	char* desnet = new char[20];
	char* netmask = new char[20];
	char* nexthop = new char[20];

	while (1)
	{
		int op = 0;
		cout << "��ѡ����Ҫ���еĲ���:" << endl;
		cout << "  1.����·�ɱ���\n  2.ɾ��·�ɱ���\n  3.��ӡ��ǰ·�ɱ�" << endl;
		cout << "  4.�˳��޸�" << endl;

		cin >> op;

		if (op == 1)
		{
			cout << " [����] ������Ŀ�������:";
			cin >> desnet;
			cout << " [����] ��������������:";
			cin >> netmask;
			cout << " [����] ��������һ����:";
			cin >> nexthop;

			DesNet = inet_addr(desnet);
			NetMask = inet_addr(netmask);
			NextHop = inet_addr(nexthop);

			router_table addRoute;
			addRoute.desnet = DesNet;
			addRoute.netmask = NetMask;
			addRoute.nexthop = NextHop;

			//addRoute(desnet, netmask, nexthop);
			additem(rt, rt_length, addRoute);
	
		}

		if (op == 2)
		{
			int num = 0;
			cout << " [ɾ��] ������Ҫɾ����·����������";
			cin >> num;

			deleteitem(rt, rt_length, num);

		}

		if (op == 3)
		{
			print_rt(rt, rt_length);
		}

		if (op == 4)
		{
			return 0;
		}

		else if (op < 0 || op>4)
		{
			cout << " [����] ����Ƿ�������������" << endl;
		}

	}

}

// �����ù�����
int set_filter(pcap_t* handle, pcap_if_t* d)
{
	u_int net_mask;
	char packet_filter[] = "ip or arp";
	struct bpf_program fcode;

	net_mask = ((sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;

	if (pcap_compile(handle, &fcode, packet_filter, 1, net_mask) < 0)
	{
		cout << " [����] ���������ʧ�ܣ�" << endl;
		return 0;
	}

	if (pcap_setfilter(handle, &fcode) < 0) 
	{
		cout << " [����] ���ù�����ʱ����" << endl;
		return 0;
	}

	return 1;
}

// �̷���ARP����
int send_arp_req(pcap_t* handle, BYTE* srcMAC, ULONG scrIP, ULONG targetIP)
{
	ARPFrame_t ARPFrame;

	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff; //Ŀ��Mac��ַ����Ϊ�㲥��ַ
		ARPFrame.FrameHeader.SrcMAC[i] = srcMAC[i]; //ԴMAC��ַ
		ARPFrame.SendHa[i] = srcMAC[i];
		ARPFrame.RecvHa[i] = 0x00; //Ŀ��MAC��ַ����Ϊ0
	}

	ARPFrame.FrameHeader.FrameType = htons(0x0806);	// ֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);			// Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);			// Э������ΪIP
	ARPFrame.HLen = 6;		// Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;		//Э���ַ����Ϊ4
	ARPFrame.Operation = htons(0x0001);		// ����ΪARP����
	ARPFrame.SendIP = scrIP;
	ARPFrame.RecvIP = targetIP;

	int result = pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));

	return result;
}

// �̴�ARP���н���MAC��ַ
int get_mac(pcap_t* p, ULONG targetIP, ULONG scrIP, BYTE* mac)
{
	pcap_pkthdr* pkt_header = new pcap_pkthdr[1500];
	const u_char* pkt_data;
	int flag = 0;
	ARPFrame_t* ARPFrame;

	while (!flag) 
	{
		int res = pcap_next_ex(p, &pkt_header, &pkt_data);
		if (res == 0) 
		{
			continue;
		}

		if (res == 1) 
		{
			ARPFrame = (ARPFrame_t*)pkt_data;
			if (ARPFrame->SendIP == targetIP && ARPFrame->RecvIP == scrIP) 
			{
				for (int i = 0; i < 6; i++) {
					mac[i] = ARPFrame->SendHa[i];
				}
				flag = 1;
			}
		}
	}

	return 1;
}

// ������У���
void setchecksum(Data_t* temp)
{
    temp->IPHeader.Checksum = 0;
    unsigned int sum = 0;
    WORD* t = (WORD*)&temp->IPHeader;	//ÿ16λΪһ��
    for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
    {
        sum += t[i];
        while (sum >= 0x10000)		//������������лؾ�
        {
            int s = sum >> 16;
            sum -= 0x10000;
            sum += s;
        }
    }
    temp->IPHeader.Checksum = ~sum;//���ȡ��
}


// ��ӡIP���ݰ�
void print_ip_packet(Data_t* IPPacket)
{
	cout << "[IP���ݰ���Ϣ]" << endl;
	cout << "  IP�汾: IPv" << ((IPPacket->IPHeader.Ver_HLen & 0xf0) >> 4) << endl;
	cout << "  IPЭ���ײ�����: " << (IPPacket->IPHeader.Ver_HLen & 0x0f) << endl;
	cout << "  ��������: " << dec << IPPacket->IPHeader.TOS << endl;
	cout << "  ���ݰ��ܳ���: " << dec << ntohs(IPPacket->IPHeader.TotalLen) << endl;
	cout << "  ��ʶ: " << "0x" << ntohs(IPPacket->IPHeader.ID) << endl;
	cout << "  ����ʱ��: " << dec << IPPacket->IPHeader.TTL << endl;
	cout << "  Э��: " << dec << IPPacket->IPHeader.Protocol << endl;
	cout << "  ԴIP��ַ: "; printIP(IPPacket->IPHeader.SrcIP); cout << endl;
	cout << "  Ŀ��IP: "; printIP(IPPacket->IPHeader.DstIP); cout << endl;
}






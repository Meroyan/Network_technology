#include "router.h"

int main()
{
	pcap_if_t* alldevs = nullptr;	//指向设备链表首部的指针
	pcap_if_t* d = nullptr;
	pcap_addr_t* a = nullptr;		//表示接口地址指针

	router_table* rt = new router_table[ROUTER_TABLE_SIZE];
	int rt_length = 0;//路由表的初始长度

	ULONG local_ip;
	BYTE local_mac[6];

	int num = 0;

	// 初始化
	num = in_dev(alldevs, d, a);

	//选择网卡
	cout << "请选择设备（1-" << num << "):" << endl;
	int dev_select_num = 0;
	cin >> dev_select_num;

	while (dev_select_num < 1 || dev_select_num > num)
	{
		cout << "字符非法，请重新输入（1-" << num << "):" << endl;
		cin >> dev_select_num;
		if (dev_select_num >= 1 && dev_select_num <= num)
		{
			break;
		}
	}

	//转到选择的设备
	d = alldevs;
	for (int i = 0; i < dev_select_num - 1; i++)
	{
		d = d->next;
	}

	//打印选择的设备的详细信息
	cout << "您选择的设备信息为：" << d->name << ";" << endl;
	cout << "描述信息：" << d->description << endl;

	//打印选择网卡的IP、子网掩码、广播地址
	for (a = d->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			cout << "IP地址：";
			printIP((((sockaddr_in*)a->addr)->sin_addr).s_addr);
			local_ip = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));

			cout << "   ";
			cout << "子网掩码：";
			printIP((((sockaddr_in*)a->netmask)->sin_addr).s_addr);
			cout << "   ";
			cout << "广播地址：";
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
			
			// 本机信息作为默认路由
			additem(rt, rt_length, temp);
		}
	}

	char errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区

	//打开网络接口
	pcap_t* handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
	if (pcap_open == NULL)
	{
		cout << "打开设备" << dev_select_num << "的网络接口失败：" << errbuf << endl;
		return 1;
	}

	// 设置过滤器
	set_filter(handle, d);

	// 发送ARP请求获取本机MAC地址
	BYTE scrMAC[6] = { 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 };
	ULONG virIP = inet_addr("112.112.112.112");
	send_arp_req(handle, scrMAC, virIP, local_ip);
	get_mac(handle, local_ip, virIP, local_mac);

	cout << " 本机IP：";
	printIP(local_ip);
	cout << "    本机MAC：";
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
	cout << "是否要修改路由表:" << endl;
	cout << "  1.是\n  2.否" << endl;
	cin >> op1;

	if (op1 == 2)
	{
		fin = 0;
		cout << "当前路由表为：" << endl;
		print_rt(rt, rt_length);
	}

	while (fin)
	{
		int op2 = 0;
		cout << "请选择你要进行的操作:" << endl;
		cout << "  1.增加路由表项\n  2.删除路由表项\n  3.打印当前路由表" << endl;

		cin >> op2;

		if (op2 == 1)
		{
			cout << " [增加] 请输入目的网络号:";
			cin >> desnet;
			cout << " [增加] 请输入子网掩码:";
			cin >> netmask;
			cout << " [增加] 请输入下一跳步:";
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
			cout << " [删除] 请输入要删除的路由项索引：";
			cin >> num;

			if (num == 0 || num == 1)
			{
				cout << " [警告] 不能删除默认路由！" << endl;
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
			cout << " [警告] 输入非法！请重新输入" << endl;
		}

		int op3;
		cout << "是否要修改路由表:" << endl;
		cout << "  1.是\n  2.否" << endl;
		cin >> op3;

		if (op3 == 2)
		{
			fin = 0;
			cout << "当前路由表为：" << endl;
			print_rt(rt, rt_length);
			break;
		}

	}


	ULONG nextIP;  // 路由的下一站
	BYTE nextMac[6];
	int Count = 0;  // 发送次数
	Data_t* IPPacket;
	pcap_pkthdr* pkt_header = new pcap_pkthdr[1500];
	const u_char* pkt_data;

	while (1)
	{
		int ret = pcap_next_ex(handle, &pkt_header, &pkt_data);  // 获取数据包

		if (ret) 
		{
			IPPacket = (Data_t*)pkt_data;

			// 存储
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

			// 检查数据包的目的IP与本机IP是否一致，一致1，不一致0
			bool ip_compare = 1;
			for (int i = 0; i < 6; i++)
			{
				if (local_ip != IPPacket->IPHeader.DstIP)
				{
					ip_compare = 0;
				}
			}

			// 检查数据包的目的MAC与本机MAC是否一致，一致1，不一致0
			bool mac_compare = 1;
			for (int i = 0; i < 6; i++)
			{
				if (local_mac[i] != IPPacket->FrameHeader.DesMAC[i])
				{
					mac_compare = 0;
				}
			}

			// 检查是否是IPV4，是1，不是0
			bool is_ipv4 = (FrameType == 0x0800);

			// 如果目的IP不是本机IP，目的MAC地址是本机MAC--转发
			if (is_ipv4 && !ip_compare && mac_compare)
			{
				print_ip_packet(IPPacket);

				// 选路
				nextIP = search(rt, rt_length, IPPacket->IPHeader.DstIP);

				if (nextIP == 0)
				{
					nextIP = IPPacket->IPHeader.DstIP;
				}
				else if (nextIP == 0xffffffff)
				{
					cout << " [警告] 不可达。无法转发数据包，请重试！" << endl;
					Count = 8;
				}

				// 发送ARP请求，获取下一跳MAC
				send_arp_req(handle, local_mac, local_ip, nextIP);
				get_mac(handle, nextIP, local_ip, nextMac);

				cout << " 下一跳IP：";
				printIP(nextIP);
				cout << "    下一跳MAC：";
				for (int i = 0; i < 6; i++)
				{
					cout << hex << (int)nextMac[i];
					if (i != 5)cout << "-";
					else cout << endl;
				}

				// 更改IP数据包的目的MAC地址
				Data_t* temp_packet;
				temp_packet = (Data_t*)send_packet;
				for (int i = 0; i < 6; i++)
				{
					temp_packet->FrameHeader.DesMAC[i] = nextMac[i];
				}

				// TTL减1
				temp_packet->IPHeader.TTL -= 1;

				temp_packet->IPHeader.Checksum = 0;  // 清零校验和
				setchecksum(temp_packet);

				// 将修改后的TTL同步
				memcpy(temp_packet + sizeof(FrameHeader_t) + offsetof(IPHeader_t, TTL), &temp_packet->IPHeader.TTL, sizeof(temp_packet->IPHeader.TTL));

				// 同步校验和
				memcpy(temp_packet + sizeof(FrameHeader_t) + offsetof(IPHeader_t, Checksum), &temp_packet->IPHeader.Checksum, sizeof(temp_packet->IPHeader.Checksum));

				// 发送
				if (!pcap_sendpacket(handle, send_packet, Len))
				{
					Data_t* t;
					t = (Data_t*)send_packet;
					cout << " [转发] ";
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


// √
int in_dev(pcap_if_t*& alldevs, pcap_if_t*& d, pcap_addr_t*& a)
{
	char errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区

	//获取当前网卡列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, //获取本机的接口设备
		NULL, //无需认证
		&alldevs, //指向设备列表首部
		errbuf //出错信息保存缓冲区
	) == -1)
	{
		cout << "获取本机网卡列表时出错:" << errbuf << endl;
		return 0;
	}

	int num = 0;

	// 打印网卡的列表
	for (d = alldevs; d != NULL; d = d->next)
	{
		num++;
		cout << num << ". " << d->name << "->" << d->description << ";" << endl;

		for (a = d->addresses; a != NULL; a = a->next)
		{
			if (a->addr->sa_family == AF_INET)
			{
				cout << "IP地址：";
				printIP((((sockaddr_in*)a->addr)->sin_addr).s_addr);
				cout << "   ";
				cout << "子网掩码：";
				printIP((((sockaddr_in*)a->netmask)->sin_addr).s_addr);
				cout << "   ";
				cout << "广播地址：";
				printIP((((sockaddr_in*)a->broadaddr)->sin_addr).s_addr);
				cout << endl << endl;
			}
		}
	}

	return num;
}

// √路由选择函数，最长匹配，返回值为下一跳的IP地址
ULONG search(router_table* t, int tLength, ULONG DesIP)
{
	ULONG best_desnet = 0;  //最优匹配的目的网络
	int best = -1;
	for (int i = 0; i < tLength; i++)
	{
		if ((t[i].netmask & DesIP) == t[i].desnet)
		{
			if (t[i].desnet >= best_desnet)//最长匹配
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

// √计算子网掩码的前缀长度
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

// √向路由表中添加项（插入时按前缀长度排序）
bool additem(router_table* t, int& tLength, router_table item) 
{
	if (tLength == ROUTER_TABLE_SIZE)  // 路由表满，不能添加
	{
		cout << " [增加] 添加失败！路由表项已满，请先删除不常用的表项！" << endl;
		return false;
	}

	// 检查路由表中是否已存在相同的路由项
	for (int i = 0; i < tLength; i++) {
		if (t[i].desnet == item.desnet && t[i].netmask == item.netmask && t[i].nexthop == item.nexthop) 
		{
			cout << " [增加] 添加失败！已存在相同路由表项！" << endl;
			return false;  // 如果已存在完全相同的路由项，返回false
		}
	}

	// 获取新路由项的前缀长度
	int itemPrefixLength = get_pre_length(item.netmask);

	// 将新项插入到路由表中，并保持路由表按前缀长度排序
	int insertIndex = tLength;
	for (int i = 0; i < tLength; i++) {
		// 通过比较前缀长度来决定插入位置，前缀长度长的排在前面
		int existingPrefixLength = get_pre_length(t[i].netmask);
		if (existingPrefixLength < itemPrefixLength) {
			insertIndex = i;
			break;
		}
	}

	// 将元素插入到找到的合适位置
	for (int i = tLength; i > insertIndex; i--) {
		t[i] = t[i - 1];  // 向后移动元素，为新项腾出空间
	}

	t[insertIndex] = item;  // 将新项放到正确的位置
	tLength++;  // 更新路由表的长度
	cout << " [增加] 添加成功！当前路由表为：" << endl;
	print_rt(t, tLength);

	return true;
}

// √从路由表中删除项
bool deleteitem(router_table* t, int& tLength, int index)
{
	if (tLength == 0)   //路由表空，不能删除
	{
		cout << " [警告] 删除失败！当前路由表为空表" << endl;
		return false;

	}

	if (index == 0 || index == 1)
	{
		cout << " [警告] 删除失败！不能删除默认路由" << endl;
		return false;
	}

	for (int i = 0; i < tLength; i++)
	{
		if (i == index)   //删除以index索引的表项
		{
			for (; i < tLength - 1; i++)
				t[i] = t[i + 1];
			tLength = tLength - 1;
			cout << " [删除] 删除成功！当前路由表为：" << endl;
			print_rt(t, tLength);
			
			return true;
		}
	}

	cout << " [警告] 删除失败！当前路由表中不存在该项！" << endl;
	return false;   //路由表中不存在该项则不能删除
}

// 打印路由表
void print_rt(router_table* t, int& tLength)
{
	cout << setfill('-') << setw(10) << ""
		<< setw(25) << ""
		<< setw(25) << ""
		<< setw(25) << ""
		<< setfill(' ') << endl;

	cout << left << setw(10) << "索引"
		<< setw(25) << "目的网络"
		<< setw(25) << "子网掩码"
		<< setw(25) << "下一站路由"
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
	// 拼接命令字符串
	string cmd = "route add " + desnet + " mask " + netmask + " " + nexthop;

	// 调用系统命令
	int result = system(cmd.c_str());

	if (result == 0) {
		cout << "[添加] 路由成功!" << endl;
	}
	else {
		cout << "[警告] 添加路由失败!" << endl;
	}
}

// 对路由表内容进行操作
int router_op(router_table* rt, int& rt_length)
{
	ULONG DesNet, NetMask, NextHop;
	char* desnet = new char[20];
	char* netmask = new char[20];
	char* nexthop = new char[20];

	while (1)
	{
		int op = 0;
		cout << "请选择你要进行的操作:" << endl;
		cout << "  1.增加路由表项\n  2.删除路由表项\n  3.打印当前路由表" << endl;
		cout << "  4.退出修改" << endl;

		cin >> op;

		if (op == 1)
		{
			cout << " [增加] 请输入目的网络号:";
			cin >> desnet;
			cout << " [增加] 请输入子网掩码:";
			cin >> netmask;
			cout << " [增加] 请输入下一跳步:";
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
			cout << " [删除] 请输入要删除的路由项索引：";
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
			cout << " [警告] 输入非法！请重新输入" << endl;
		}

	}

}

// √设置过滤器
int set_filter(pcap_t* handle, pcap_if_t* d)
{
	u_int net_mask;
	char packet_filter[] = "ip or arp";
	struct bpf_program fcode;

	net_mask = ((sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;

	if (pcap_compile(handle, &fcode, packet_filter, 1, net_mask) < 0)
	{
		cout << " [警告] 编译过滤器失败！" << endl;
		return 0;
	}

	if (pcap_setfilter(handle, &fcode) < 0) 
	{
		cout << " [警告] 设置过滤器时出错！" << endl;
		return 0;
	}

	return 1;
}

// √发送ARP请求
int send_arp_req(pcap_t* handle, BYTE* srcMAC, ULONG scrIP, ULONG targetIP)
{
	ARPFrame_t ARPFrame;

	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff; //目的Mac地址设置为广播地址
		ARPFrame.FrameHeader.SrcMAC[i] = srcMAC[i]; //源MAC地址
		ARPFrame.SendHa[i] = srcMAC[i];
		ARPFrame.RecvHa[i] = 0x00; //目的MAC地址设置为0
	}

	ARPFrame.FrameHeader.FrameType = htons(0x0806);	// 帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);			// 硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);			// 协议类型为IP
	ARPFrame.HLen = 6;		// 硬件地址长度为6
	ARPFrame.PLen = 4;		//协议地址长度为4
	ARPFrame.Operation = htons(0x0001);		// 操作为ARP请求
	ARPFrame.SendIP = scrIP;
	ARPFrame.RecvIP = targetIP;

	int result = pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));

	return result;
}

// √从ARP包中解析MAC地址
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

// √设置校验和
void setchecksum(Data_t* temp)
{
    temp->IPHeader.Checksum = 0;
    unsigned int sum = 0;
    WORD* t = (WORD*)&temp->IPHeader;	//每16位为一组
    for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
    {
        sum += t[i];
        while (sum >= 0x10000)		//如果溢出，则进行回卷
        {
            int s = sum >> 16;
            sum -= 0x10000;
            sum += s;
        }
    }
    temp->IPHeader.Checksum = ~sum;//结果取反
}


// 打印IP数据包
void print_ip_packet(Data_t* IPPacket)
{
	cout << "[IP数据包信息]" << endl;
	cout << "  IP版本: IPv" << ((IPPacket->IPHeader.Ver_HLen & 0xf0) >> 4) << endl;
	cout << "  IP协议首部长度: " << (IPPacket->IPHeader.Ver_HLen & 0x0f) << endl;
	cout << "  服务类型: " << dec << IPPacket->IPHeader.TOS << endl;
	cout << "  数据包总长度: " << dec << ntohs(IPPacket->IPHeader.TotalLen) << endl;
	cout << "  标识: " << "0x" << ntohs(IPPacket->IPHeader.ID) << endl;
	cout << "  生存时间: " << dec << IPPacket->IPHeader.TTL << endl;
	cout << "  协议: " << dec << IPPacket->IPHeader.Protocol << endl;
	cout << "  源IP地址: "; printIP(IPPacket->IPHeader.SrcIP); cout << endl;
	cout << "  目的IP: "; printIP(IPPacket->IPHeader.DstIP); cout << endl;
}






#define HAVE_REMOTE
#include <pcap.h>
#include<winsock.h>
#include <vector>

pcap_t *pcapHandle;
int PacketCount;

struct ETHER_HEADER
{
    unsigned char EtherDestHost[6];
    unsigned char EtherSrcHost[6];
    unsigned short EtherProtocol;
};

struct IP_HEADER
{
	u_char	ver_ihl;			// 高4位：版本；低4位：首部长度
	u_char	tos;				// type of service服务类型
	u_short	TotalLen;			// 总长度
	u_short identification;		//标识，主机每发一个报文，加1，分片重组时会用到该字段。
	u_short flags_fo;			//flags(3bit)+Fragment Offset(13bit)
	u_char	ttl;				//time to live
	u_char	proto;				//协议：下一层协议。
	u_short	crc;				//Header checksum首部检验和，只检验数据包的首部，不检验数据部分
	in_addr SrcIp;				//Source address源IP
	in_addr	DestIp;				//Destionation address目的IP
	u_int	op_pad;				//Option + Padding
};

struct TCP_HEADER
{
	u_short SrcPort;			//Source Port源端口
	u_short DestPort;			//Destination Port目的端口
	u_int	SeqNumber;			//Sequence Number序列号
	u_int	AckNumber;			//Acknowledgment Number确认号
	u_char	DataOffset;			//数据偏移
	u_char	Flags;				//控制标志
	u_short	Window;				//窗口，流量控制
	u_short	Checksum;			//校验字段，TCP首部和数据
	u_short UrgentPointer;		//紧急指针
	//u_int	Options;			//选项字段
};

struct UDP_HEADER
{
	u_short SrcPort;			//源端口
	u_short DestPort;			//目的端口
	u_short Length;				//UDP首部和数据
	u_short Checksum;			//UDP首部和数据的校验和
};

//IP协议枚举类型
enum Proto {TCP=0,UDP};
//必要的数据包信息结构体
struct Packet{
	Proto Protocol;					//协议类型，分TCP和UDP两种
	unsigned char SrcMac[6];		//源MAC
	unsigned char DestMac[6];		//目的MAC
	in_addr SrcIp;					//源IP
	in_addr DestIp;					//目的IP
	unsigned short SrcPort;			//源端口
	unsigned short DestPort;		//目的端口
	unsigned int Length;			//数据长度（不包括TCP或者UDP协议头）
	char* pContent;					//数据内容
};
//数据包暂存结构体
Packet p;
//数据包存储向量
std::vector<Packet> packets;

//线程参数结构体
struct ThreadArg{
	LPVOID pcapHandle;
	LPVOID pFunc;
};
ThreadArg arg;
HANDLE hThread = NULL;


BOOL InsertPacket(Packet p);
/////////////////////////////
//初始化wpcap
///////////////////////////
int InitWpcap()
{
	//网络设备指针，用来存储若干网络设备信息（一台机器可能有若干个网卡）
	pcap_if_t *pcapDev;
	//错误信息缓冲区
	char errContent[PCAP_ERRBUF_SIZE];
	//BPF过滤规则
	bpf_program filter;
	//过滤规则字符串，在这里我们忽略arp数据包
	//只获ip数据包，所以设为ip
	char bpfFilterString[]="ip";
	//掩码
	bpf_u_int32 netMask;
	//网络地址
	bpf_u_int32 netIp=0;

	//获取网络设备指针
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&pcapDev,errContent)==-1)
	{
		MessageBoxA(NULL,"获取网络设备失败","警告",MB_OK);
		return -1;
	}
	//选取合适网卡，我们找一个地址非空的设备，这个设备必然可用
	while(pcapDev->addresses==NULL)
	{
		pcapDev=pcapDev->next;
	}
	
	
	//打开网卡（pcapHandle）
	if((pcapHandle=pcap_open(pcapDev->name,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errContent))==NULL)
	{
		MessageBoxA(NULL,"打开网卡失败","警告",MB_OK);
		return -1;
	}

	//检查链路层，判断所在网络是否为以太网，这个项目只支持以太网
	if(pcap_datalink(pcapHandle)!=DLT_EN10MB)
	{
		MessageBoxA(NULL,"只支持以太网","警告",MB_OK);
		pcap_freealldevs(pcapDev);
		return -1;
	}
	if(pcapDev->addresses!=NULL)
	{
		//取得网络接口子网掩码
		netMask=((struct sockaddr_in*)(pcapDev->addresses->netmask))->sin_addr.S_un.S_addr;
	}else{
		netMask=0xFFFFFFFF;
	}
	//编译BPF过滤规则
	pcap_compile(pcapHandle,&filter,bpfFilterString,0,netIp);
	//设置过滤规则
	pcap_setfilter(pcapHandle,&filter);
	arg.pcapHandle=pcapHandle;
	//释放网络设备接口链表
	pcap_freealldevs(pcapDev);
	return 0;
}

///////////////////////////
//线程回调函数
//////////////////////////
BOOL Func(LPVOID p)
{
	ThreadArg *arg=(ThreadArg *)p;
	//注册回调函数，循环捕获数据包，每捕获到一个数据包就自动调用pFunc()进行分析
	pcap_loop((pcap_t*)arg->pcapHandle,-1,(pcap_handler)arg->pFunc,NULL);
	return TRUE;
}


//////////////////////////////////
//TCP分析回调函数
///////////////////////////////////
BOOL TcpPacketCallback(u_char *argument,const struct pcap_pkthdr *packetHdr,const u_char *packetContent)
{
	//TCP协议变量
	TCP_HEADER *TcpProtocol;

	//获得TCP协议内容
	TcpProtocol=(TCP_HEADER*)(packetContent+14+20);
	//分别填充TCP协议的源端口、目的端口及数据长度
	p.SrcPort=TcpProtocol->SrcPort;
	p.DestPort=TcpProtocol->DestPort;
	//计算TCP包的数据长度=ntohs(IpHdr->TotalLen)-sizeof(IP_HEADER)-sizeof(TCP_HEADER)
	IP_HEADER *IpHdr=(IP_HEADER*)(packetContent+14);
	int totallength=ntohs(IpHdr->TotalLen);
	int HeaderLength=totallength-40;
	p.Length=HeaderLength;

	//填充数据内容
	char *pBuf=new char[HeaderLength+1];
	memset(pBuf,0,HeaderLength+1);
	char *ptr=(char*)TcpProtocol+sizeof(TCP_HEADER);
	memcpy(pBuf,ptr,HeaderLength);
	p.pContent=pBuf;

	//将捕获到的数据包信息加入向量列表
	packets.push_back(p);

	InsertPacket(p);
	return TRUE;
}

/////////////////////////////////////
//UDP分析回调函数
/////////////////////////////////////
BOOL UdpPacketCallback(u_char *argement,const struct pcap_pkthdr *packetHdr,const u_char *packetContent)
{
	//UDP协议变量
	UDP_HEADER *UdpProtocol;
	//获取UDP协议内容
	UdpProtocol=(UDP_HEADER*)(packetContent+14+20);

	//分别填充UDP协议的源端口、目的端口及数据长度
	p.SrcPort=UdpProtocol->SrcPort;
	p.DestPort=UdpProtocol->DestPort;
	//UDP数据包长度=ntohs(UdpProtocol->Length)-sizeof(UDP_HEADER)
	int HeaderLength=ntohs(UdpProtocol->Length)-sizeof(UDP_HEADER);
	p.Length=HeaderLength;
	//填充数据内容
	char *pBuf=new char[HeaderLength+1];
	memset(pBuf,0,HeaderLength+1);
	char *ptr=(char*)UdpProtocol+sizeof(UDP_HEADER);
	memcpy(pBuf,ptr,HeaderLength);
	p.pContent=pBuf;
	//将捕获到的数据包信息加入向量列表
	packets.push_back(p);
	InsertPacket(p);
	return TRUE;
}


////////////////////////////////////
//IP分析回调函数
///////////////////////////////////
BOOL IpPacketCallback(u_char *argument,const struct pcap_pkthdr *packetHdr,const u_char *packetContent)
{
	//IP协议变量
	IP_HEADER *IpProtocol;

	//获取IP协议内容
	IpProtocol=(IP_HEADER*)(packetContent+sizeof(ETHER_HEADER));
	//填充源IP和目的IP
	p.SrcIp=IpProtocol->SrcIp;
	p.DestIp=IpProtocol->DestIp;
	
	//分析IP协议类型
	switch(IpProtocol->proto)
	{
	case IPPROTO_TCP:
		//把协议类型填充到p
		p.Protocol=TCP;
		//进一步TCP协议
		TcpPacketCallback(argument,packetHdr,packetContent);
		break;
	case IPPROTO_UDP:
		//把协议类型填充到p
		p.Protocol=UDP;
		//进一步分析UDP协议
		//UdpPacketCallback(argument,packetHdr,packetContent);
		break;
	default:
		break;
	}
	return TRUE;
}

///////////////////////////////////
//以太网分析回调函数
/////////////////////////////////
void EtherPacketCallback(u_char *argument,const struct pcap_pkthdr *packetHdr,const u_char *packetContent)
{
	//以太网协议变量
	ETHER_HEADER *EtherProtocol;
	//获取以太网协议内容
	EtherProtocol=(ETHER_HEADER*)(packetContent);

	//填充源MAC和目的MAC
	memcpy(p.SrcMac,EtherProtocol->EtherSrcHost,6);
	memcpy(p.DestMac,EtherProtocol->EtherDestHost,6);

	//IP协议分析
	IpPacketCallback(argument,packetHdr,packetContent);
}

BOOL StartSniffer()
{
	//初始化wpcap
	InitWpcap();

	//数目清零
	PacketCount = 0;

	//清空数据包信息
	for(unsigned int i=0;i<packets.size();i++)
	{
		delete packets[i].pContent;
	}
	packets.clear();

	//arg就是一个参数结构体,它也是全局的
	arg.pcapHandle=pcapHandle;
	arg.pFunc=EtherPacketCallback;

	//利用回调函数捕获数据包，线程句柄hThread是全局变量，这样方便结束该线程的时候使用
	hThread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)Func,(LPVOID)&arg,NULL,NULL);
	if(hThread==NULL)
	{
		MessageBoxA(NULL,"嗅探失败",NULL,NULL);
		return FALSE;
	}
	return TRUE;
}
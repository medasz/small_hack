#define HAVE_REMOTE
#include "resource.h"
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include <commctrl.h>
#include "Protocol.h"

//#pragma comment(lib,"Ws2_32.lib")

/////////////////////////////////
//UI相关变量声明部分
///////////////////////////////
HWND hDlg = NULL;
BOOL Sending = FALSE;

ETHER_HEADER EtherHead={0};
ARP_HEADER ArpHead={0};


/////////////////////////////////////////////////////
//MAC字符串转换
/////////////////////////////////////////////////////
BOOL MacStrToMac(WCHAR *MacStr,unsigned char *Mac)
{
	WCHAR *str = MacStr;
	int i;
	int low,high;
	char temp;
	for(i=0;i<6;i++)
	{
		if(str[0]-L'0'>=0&&str[0]-L'0'<=9)
		{
			high = str[0]-L'0';
		}else if(str[0]-L'a'>=0&&str[0]-L'a'<=5)
		{
			high = str[0]-L'a'+10;
		}else if(str[0]-L'A'>=0&&str[0]-L'A'<=5)
		{
			high = str[0]-L'A'+10;
		}

		if(str[1]-L'0'>=0&&str[1]-L'0'<=9)
		{
			low = str[1]-L'0';
		}else if(str[1]-L'a'>=0&&str[1]-L'a'<=5)
		{
			low = str[1]-L'a'+10;
		}else if(str[1]-L'A'>=0&&str[1]-L'A'<=5)
		{
			low = str[1]-L'A'+10;
		}
		Mac[i]=high*16+low;
		str+=3;
	}
	return TRUE;
}

////////////////////////////////////////////////////////
//填充协议头函数
////////////////////////////////////////////////////////
BOOL FillHeaders(){
	//源、目的IP地址
	DWORD IpSrc=0;
	DWORD IpDest=0;
	//源、目的MAC地址
	WCHAR MacSrc[18]={0};
	WCHAR MacDest[18]={0};
	//从UI获取IP和MAC
	SendMessage(GetDlgItem(hDlg,IDC_IP_SRC),IPM_GETADDRESS,0,(LPARAM)&IpSrc);
	SendMessage(GetDlgItem(hDlg,IDC_IP_DEST),IPM_GETADDRESS,0,(LPARAM)&IpDest);
	GetDlgItemText(hDlg,IDC_MAC_SRC,MacSrc,18);
	GetDlgItemText(hDlg,IDC_MAC_DEST,MacDest,18);
	//大小定基转换
	IpSrc = htonl(IpSrc);
	//填充，ArpHead是全局变量
	//memcpy(ArpHead.SrcIp,&IpSrc,sizeof(char)*4);
	ArpHead.SrcIp=IpSrc;
	//大小定基转换
	IpDest = htonl(IpDest);
	//填充
	//memcpy(ArpHead.DestIp,&IpDest,sizeof(char)*4));
	ArpHead.DestIp=IpDest;
	//MAC字符串转换到实际MAC地址并填充，EtherHead为全局变量
	MacStrToMac(MacSrc,ArpHead.EtherSrcHost);
	MacStrToMac(MacSrc,EtherHead.EtherSrcHost);
	MacStrToMac(MacDest,ArpHead.EtherDestHost);
	MacStrToMac(MacDest,EtherHead.EtherDestHost);
	//填充其他字段，上层协议类型，x0806为ARP协议
	EtherHead.EtherType=htons(0x0806);
	//硬件地址类型，x0001为以太网类型
	ArpHead.HardwareType=htons(0x0001);
	//上层协议类型，x0800为IP协议
	ArpHead.ProtocolType=htons(0x0800);
	//硬件地址长度，MAC地址长度为字节
	ArpHead.HardwareLength =6;
	//IP地址长度,字节
	ArpHead.ProtocolLength =4;
	//填充为x0002表示ARP响应
	ArpHead.OprationCode = htons(0x0002);
	return TRUE;
}

/////////////////////////////////////////////////////
//发送函数
///////////////////////////////////////////////////
BOOL SendArpPacket(){
	//winpcap句柄
	pcap_t *pcapHandle;
	//网络设备指针
	pcap_if_t *pcapDev;
	//存储错误信息
	char errContent[PCAP_ERRBUF_SIZE];
	//数据包缓冲区
	unsigned char buff[100]={0};
	//填充协议首部
	FillHeaders();
	//以太网协议首部和ARP协议首部填充到缓冲区
	memcpy(buff,&EtherHead,sizeof(EtherHead));
	memcpy(buff+sizeof(EtherHead),&ArpHead,sizeof(ArpHead));
	//获取网络设备指针
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&pcapDev,errContent)==-1)
	{
		MessageBoxA(NULL,"获取网络设备失败","警告",MB_OK);
		return FALSE;
	}
	//选择合适网卡
	while(pcapDev->addresses==NULL)
	{
		pcapDev=pcapDev->next;
	}
	//打开网卡
	if((pcapHandle=pcap_open(pcapDev->name,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errContent))==NULL)
	{
		MessageBoxA(NULL,"打开网卡失败","警告",MB_OK);
		return FALSE;
	}
	//循环发送，Sending为全局变量
	while(Sending)
	{
		pcap_sendpacket(pcapHandle,buff,sizeof(buff)/*size*/);
		Sleep(100);
		SetDlgItemText(hDlg,IDC_STATIC_LIGHT,L"发送中...");
		Sleep(100);
		SetDlgItemText(hDlg,IDC_STATIC_LIGHT,L"");
	}
	//释放设备列表
	pcap_freealldevs(pcapDev);
	//关闭WinPcap句柄
	pcap_close(pcapHandle);
	return TRUE;
}










/////////////////////////////
//UI相关函数声明部分
//////////////////////////////
//窗口过程回调函数
LRESULT CALLBACK DlgProc(HWND hDlgMain,UINT uMsg,WPARAM wParam,LPARAM lParam);

////////////////////////////////////////////
//UI主函数
///////////////////////////////////////////
int WINAPI WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nShowCmd){
	//窗口函数
	DialogBox(hInstance,MAKEINTRESOURCE(IDD_DIALOG),NULL,(DLGPROC)DlgProc);
}

//////////////////////////////////////////
//窗口过程回调函数
////////////////////////////////////////
LRESULT CALLBACK DlgProc(HWND hDlgMain,UINT uMsg,WPARAM wParam,LPARAM lParam){
	hDlg=hDlgMain;
	switch(uMsg){
		case WM_INITDIALOG:
			break;
		case WM_NOTIFY:
			break;
		case WM_COMMAND:
			switch(LOWORD(wParam)){
				case IDC_BUTTON:
					if(!Sending){
						Sending=TRUE;
						CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)SendArpPacket,NULL,0,NULL);
						SetDlgItemText(hDlg,IDC_BUTTON,L"停止发送");
					}else{
						Sending=FALSE;
						SetDlgItemText(hDlg,IDC_BUTTON,L"开始发送");
					}
					break;
				default:
					break;
			}
			break;
		case WM_CLOSE:
			EndDialog(hDlg,NULL);
			DestroyWindow(hDlg);
			break;
		default:
			break;
	}
	return 0;
}
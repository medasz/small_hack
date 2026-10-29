#include "resource.h"
#include<Windows.h>
#include<commctrl.h>
#include <vector>

HWND hDlg;
HWND hList;

// 函数声明必须位于调用位置之前
BOOL StartSniffer();
BOOL StopSniffer();
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
extern std::vector<Packet> packets;  // 只声明，不分配空间
extern int PacketCount;

LRESULT CALLBACK DlgProc(HWND hDlgMain,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	hDlg=hDlgMain;
	//列结构
	LVCOLUMN LvCol;
	LVITEM LvItem;
	LPNMITEMACTIVATE lpnmitem;
	LPNMHDR lpnmhdr;
	static BOOL Flag = TRUE;
	switch(uMsg)
	{
		//下面是初始化窗口的消息，在这里面我们初始化了list control
	case WM_INITDIALOG:
		InitCommonControls();
		hList=GetDlgItem(hDlg,IDC_LIST);

		memset(&LvCol,0,sizeof(LvCol));
		LvCol.mask=LVCF_FMT|LVCF_WIDTH|LVCF_TEXT|LVCF_SUBITEM;
		LvCol.fmt=LVCFMT_LEFT;
		LvCol.cx=0x25;
		//初始化列表，添加COLUMN
		LvCol.pszText=L"编号";
		SendMessage(hList,LVM_INSERTCOLUMN,0,(LPARAM)&LvCol);
		LvCol.pszText=L"协议";
		LvCol.cx=0x25;
		SendMessage(hList,LVM_INSERTCOLUMN,1,(LPARAM)&LvCol);
		LvCol.pszText=L"源MAC";
		LvCol.cx=0x80;
		SendMessage(hList,LVM_INSERTCOLUMN,2,(LPARAM)&LvCol);
		LvCol.pszText=L"源IP";
		LvCol.cx=0x60;
		SendMessage(hList,LVM_INSERTCOLUMN,3,(LPARAM)&LvCol);
		LvCol.pszText=L"源Port";
		LvCol.cx=0x30;
		SendMessage(hList,LVM_INSERTCOLUMN,4,(LPARAM)&LvCol);
		LvCol.pszText=L"目的MAC";
		LvCol.cx=0x80;
		SendMessage(hList,LVM_INSERTCOLUMN,5,(LPARAM)&LvCol);
		LvCol.pszText=L"目的IP";
		LvCol.cx=0x60;
		SendMessage(hList,LVM_INSERTCOLUMN,7,(LPARAM)&LvCol);
		LvCol.pszText=L"目的Port";
		LvCol.cx=0x40;
		SendMessage(hList,LVM_INSERTCOLUMN,7,(LPARAM)&LvCol);
		LvCol.pszText=L"数据长度";
		LvCol.cx=0x40;
		SendMessage(hList,LVM_INSERTCOLUMN,8,(LPARAM)&LvCol);
		//设置为整行选取
		ListView_SetExtendedListViewStyleEx(GetDlgItem(hDlg,IDC_LIST),0,LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_HEADERDRAGDROP);
		memset(&LvItem,0,sizeof(LvItem));
		break;
		
		//下面是通知消息
	case WM_NOTIFY:
		lpnmhdr=(LPNMHDR)lParam;
		if(lpnmhdr->hwndFrom==hList)
		{
			if(lpnmhdr->code==NM_CLICK)
			{
				lpnmitem=(LPNMITEMACTIVATE)lParam;
				int isSelect = ListView_GetSelectionMark(hList);
				if(isSelect>packets.size())
				{
					break;
				}
				Packet p = packets[isSelect];
				//显示字符的进制
				char Buf[65535*3]={0};
				memset(Buf,0,sizeof(Buf));
				for(unsigned int i=0;i<p.Length;i++)
				{
					//数据字符串指针
					char *ptr=p.pContent;
					//每行显示16个字符
					if(i%16==0&&i!=0)
					{
						strcat(Buf,"\r\n");
					}
					if(ptr[i]=='\0')
					{
						strcat(Buf,"00 ");
					}else{
						char temp[10]={0};
						sprintf(temp,"%02x ",ptr[i]);
						if(strstr(temp,"ffffff")!=NULL)
						{
							strcpy(temp,temp+6);
						}
						strcat(Buf,temp);
					}
				}
				HWND hEdit1=GetDlgItem(hDlg,IDC_EDIT1);
				SetWindowTextA(hEdit1,Buf);
				//显示字符
				memset(Buf,0,sizeof(Buf));
				for(unsigned int i =0;i<p.Length;i++)
				{
					char *ptr=p.pContent;
					if(i%16==0&&i!=0)
					{
						strcat(Buf,"\r\n");
					}
					char ch = ptr[i];
					char temp[10]={0};
					sprintf(temp,"%c",ch);
					strcat(Buf,temp);
				}
				HWND hEdit2=GetDlgItem(hDlg,IDC_EDIT2);
				SetWindowTextA(hEdit2,Buf);
			}
		}
		break;

		//命令消息
	case WM_COMMAND:
		switch(LOWORD(wParam))
		{
			//当按下“开始嗅探”时，执行以下case内的代码
		case IDC_BUTTON:
			if(Flag)//flag为bool变量，表示当前是否在抓包
			{
				StartSniffer();
				Flag=FALSE;
				SetDlgItemText(hDlg,IDC_BUTTON,L"停止嗅探");
			}else{
				Flag=TRUE;
				SetDlgItemText(hDlg,IDC_BUTTON,L"开始嗅探");
			}
		default:
			break;
		}
		break;

		//关闭窗口的消息
	case WM_CLOSE:
		EndDialog(hDlg,NULL);
		DestroyWindow(hDlg);
		break;
	default:
		break;
	}
	return 0;
}


//////////////////////////////////////
//UI主函数
///////////////////////////////////////
int WINAPI WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nShowCmd)
{
	InitCommonControls();
	//窗口函数
	DialogBox(hInstance,MAKEINTRESOURCE(IDD_DIALOG),NULL,(DLGPROC)DlgProc);
	return 0;
}

/////////////////////////////////////////
//绑定一个数据包到List Control
////////////////////////////////////////
BOOL InsertPacket(Packet p)
{
	char Buf[1024];
	LVITEMA LvItem;
	LvItem.mask=LVIF_TEXT;
	LvItem.iItem=PacketCount++;
	LvItem.iSubItem=0;
	memset(Buf,0,sizeof(Buf));
	sprintf(Buf,"%d",PacketCount);
	LvItem.pszText=Buf;
	SendMessageA(hList,LVM_INSERTITEMA,(WPARAM)0,(LPARAM)&LvItem);
	LvItem.iSubItem = 1;
	memset(Buf,0,sizeof(Buf));
	if(p.Protocol==TCP)
	{
		memcpy(Buf,"TCP",sizeof("TCP"));
	}else{
		memcpy(Buf,"UDP",sizeof("UDP"));
	}
	SendMessageA(hList,LVM_SETITEMA,(WPARAM)0,(LPARAM)&LvItem);
	LvItem.iSubItem=2;
	memset(Buf,0,sizeof(Buf));
	//用sprintf函数实现把MAC信息转换成标准可读字符串并绑定到List Control
	sprintf(Buf,"%02x:%02x:%02x:%02x:%02x:%02x",p.SrcMac[0],p.SrcMac[1],p.SrcMac[2],p.SrcMac[3],p.SrcMac[4],p.SrcMac[5]);
	LvItem.pszText=strupr(Buf);
	SendMessageA(hList,LVM_SETITEMA,(WPARAM)0,(LPARAM)&LvItem);
	LvItem.iSubItem=3;
	memset(Buf,0,sizeof(Buf));
	//用sprintf函数和ntohs函数实现把IP信息转换成标准可读字符串，并绑定到List Control
	sprintf(Buf,"%s",inet_ntoa(p.SrcIp));
	LvItem.pszText=Buf;
	SendMessageA(hList,LVM_SETITEMA,(WPARAM)0,(LPARAM)&LvItem);
	LvItem.iSubItem=4;
	memset(Buf,0,sizeof(Buf));
	//用sprintf函数和ntohs函数实现把Port信息转换成标准可读字符串，并绑定到List Control
	sprintf(Buf,"%d",ntohs(p.SrcPort));
	LvItem.pszText=Buf;
	SendMessageA(hList,LVM_SETITEMA,(WPARAM)0,(LPARAM)&LvItem);
	LvItem.iSubItem=5;
	memset(Buf,0,sizeof(Buf));
	sprintf(Buf,"%02x:%02x:%02x:%02x:%02x:%02x",p.DestMac[0],p.DestMac[1],p.DestMac[2],p.DestMac[3],p.DestMac[4],p.DestMac[5]);
	LvItem.pszText=strupr(Buf);
	SendMessageA(hList,LVM_SETITEMA,(WPARAM)0,(LPARAM)&LvItem);
	LvItem.iSubItem=6;
	memset(Buf,0,sizeof(Buf));
	sprintf(Buf,"%s",inet_ntoa(p.DestIp));
	LvItem.pszText=Buf;
	SendMessageA(hList,LVM_SETITEMA,(WPARAM)0,(LPARAM)&LvItem);
	LvItem.iSubItem=7;
	memset(Buf,0,sizeof(Buf));
	sprintf(Buf,"%d",ntohs(p.DestPort));
	LvItem.pszText=Buf;
	SendMessageA(hList,LVM_SETITEMA,(WPARAM)0,(LPARAM)&LvItem);
	LvItem.iSubItem=8;
	memset(Buf,0,sizeof(Buf));
	sprintf(Buf,"%d",p.Length);
	LvItem.pszText=Buf;
	SendMessageA(hList,LVM_SETITEMA,(WPARAM)0,(LPARAM)&LvItem);
	return TRUE;
}
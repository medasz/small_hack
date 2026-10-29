#include "resource.h"
#include <winsock2.h>
#include <Windows.h>
#include <stdio.h>
#include <commctrl.h>

#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"comctl32.lib")

BOOL InitPortScan();
DWORD WINAPI MainThread(LPVOID lpParam);
DWORD WINAPI PortScanThread(LPVOID LpParam);
LRESULT InsertInfo(char * info);
HWND hDlg = NULL;
/////////////////////////////
//窗口过程回调函数
/////////////////////////////
LRESULT CALLBACK DlgProc(HWND hDlgMain,UINT uMsg,WPARAM wParam,LPARAM lParam);
//主扫描线程参数结构体
struct MainThreadParam
{
	DWORD StartIp;		//开始IP
	DWORD EndIp;		//结束IP
	DWORD StartPort;	//开始端口
	DWORD EndPort;		//结束端口
	HANDLE hCopyEvent;	//事件句柄，用来通知其父线程参数复制完毕
};

//connect线程参数的结构体定义
struct ThreadParam
{
	DWORD Ip;			//connect的目标IP
	DWORD Port;			//connect的目标端口
	HANDLE hCopyOkEvent;//事件对象，用来通知其父线程参数复制完毕
	HANDLE hThreadNum;//信号量对象，通过对它的操作来限制总线程数
};
///////////////////////////////////////////
//开始扫描
///////////////////////////////////////////
BOOL StartScanner(DWORD StartIp,DWORD EndIp,DWORD StartPort,DWORD EndPort)
{
	//初始化端口扫描器
	InitPortScan();
	//主扫描线程参数
	MainThreadParam param;
	//主扫描线程的“参数复制完毕”事件对象，来通知其父线程参数复制完毕
	HANDLE hMainCopyEvent = CreateEvent(NULL,TRUE,FALSE,NULL);
	//填充MainThreadParam参数结构体
	param.hCopyEvent=hMainCopyEvent;
	param.StartIp=StartIp;
	param.EndIp=EndIp;
	param.StartPort=StartPort;
	param.EndPort=EndPort;
	//创建主扫描线程
	CreateThread(NULL,0,MainThread,(LPVOID*)&param,0,NULL);
	//等待hMainCopyEvent变为有信号状态
	WaitForSingleObject(hMainCopyEvent,INFINITE);
	//重置hMainCopyEvent为无信号状态
	ResetEvent(hMainCopyEvent);
	return TRUE;
}



/////////////////////////////////////
//端口扫描器初始化
/////////////////////////////////////
BOOL InitPortScan()
{
	WSADATA WsaData;
	//构建Socket版本信息，在此表明Socket版本为2.2
	WORD WsaVersion = MAKEWORD(2,2);
	//调用WSAStartup()初始化网络
	if(WSAStartup(WsaVersion,&WsaData)!=0)
	{
		MessageBoxA(NULL,"WSAStartup fail;",NULL,NULL);
		return FALSE;
	}
	return TRUE;

}

//////////////////////////////////////
//扫描主线程
//////////////////////////////////////
DWORD WINAPI MainThread(LPVOID lpParam)
{
	MainThreadParam Param;
	//将参数复制
	MoveMemory(&Param,lpParam,sizeof(Param));
	//将Param.hCopyEvent设置为有信号状态，通知其父线程参数复制完毕
	SetEvent(Param.hCopyEvent);
	ThreadParam threadParam = {0};
	//创建其子线程的“参数复制完成”事件对象，并作为参数传入PortScanThread()
	HANDLE hThreadCopyOkEvent = CreateEvent(NULL,TRUE,FALSE,NULL);
	threadParam.hCopyOkEvent=hThreadCopyOkEvent;
	//创建一个信号量对象来控制子线程的总数，在此定义总子线程数不得超过256个
	HANDLE hThreadNum = CreateSemaphore(NULL,256,256,NULL);
	threadParam.hThreadNum=hThreadNum;
	//循环创建新线程，在每个新线程中进行connect
	for(DWORD Ip=Param.StartIp;Ip<=Param.EndIp;Ip++)
	{
		for(DWORD Port=Param.StartPort;Port<=Param.EndPort;Port++)
		{
			//等待hThreadNum发出信号，即等待总线程数小于256
			DWORD WaitRes = WaitForSingleObject(hThreadNum,200);
			if(WaitRes==WAIT_OBJECT_0)
			{
				threadParam.Ip=Ip;
				threadParam.Port=Port;
				CreateThread(NULL,0,PortScanThread,&threadParam,0,NULL);
				//等待其子线程发出“参数复制完毕”的信号
				WaitForSingleObject(threadParam.hCopyOkEvent,INFINITE);
				//重置threadParam.hCopyOkEvent为无信号状态
				ResetEvent(threadParam.hCopyOkEvent);
			}else if(WaitRes==WAIT_TIMEOUT)
			{
				Port--;
				continue;
			}
		}
	}
	return 0;
}

/////////////////////////////////////
//connect线程函数
/////////////////////////////////////
DWORD WINAPI PortScanThread(LPVOID LpParam)
{
	ThreadParam Param;
	//将参数复制
	MoveMemory(&Param,LpParam,sizeof(Param));
	//将hCopyOkEvent设为有信号状态来通知扫描主线程修改其子线程参数结构体，并
	//创建下一个子线程
	SetEvent(Param.hCopyOkEvent);
	SOCKET Sock;
	SOCKADDR_IN SockAddr={0};
	//创建Socket
	Sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if(Sock==INVALID_SOCKET)
	{
		MessageBoxA(NULL,"INVALID_SOCKET",NULL,NULL);
	}
	//填充IP地址及端口信息
	SockAddr.sin_family=AF_INET;
	SockAddr.sin_addr.s_addr=htonl(Param.Ip);
	SockAddr.sin_port=htons(Param.Port);
	//将IP地址转换为字符串
	char *IpChar = inet_ntoa(SockAddr.sin_addr);
	char str[200];
	//进行connect
	if(connect(Sock,(SOCKADDR *)&SockAddr,sizeof(SockAddr))==0)
	{
		sprintf(str,"%s : %d 连接成功\n",IpChar,Param.Port);
	}else{
		sprintf(str,"%s : %d 连接失败\n",IpChar,Param.Port);
	}
	//添加显示信息
	InsertInfo(str);
	//释放一个信号量计数
	ReleaseSemaphore(Param.hThreadNum,1,NULL);
	//关闭socket
	closesocket(Sock);
	return 0;
}

LRESULT InsertInfo(char * info)
{
	HWND hList = GetDlgItem(hDlg,IDC_LIST_RST);
	LRESULT index = SendMessageA(hList,LB_ADDSTRING,0,(LPARAM)info);
	SendMessage(hList,LB_SETTOPINDEX,index,0);
	return index;
}


/////////////////////////////////////
//UI主函数
/////////////////////////////////////
int WINAPI WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nShowCmd)
{
	INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_INTERNET_CLASSES;   // IP Address 控件需要这个
    InitCommonControlsEx(&icex);
	return DialogBox(hInstance,MAKEINTRESOURCE(IDD_DIALOG),NULL,(DLGPROC)DlgProc);
}

//////////////////////////////////////////
//窗口过程回调函数
/////////////////////////////////////////
LRESULT CALLBACK DlgProc(HWND hDlgMain,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	//主窗口句柄
	hDlg = hDlgMain;
	//起止IP
	DWORD StartIp;
	DWORD EndIp;
	//起止端口
	DWORD StartPort;
	DWORD EndPort;
	//判断扫描状态
	static BOOL Flag = TRUE;
	switch(uMsg)
	{
		//初始化窗口消息
	case WM_INITDIALOG:
		return TRUE;
		//命令消息
	case WM_COMMAND:
		switch(LOWORD(wParam))
		{
			//“开始扫描”按钮被按下
		case IDC_BUTTON_START:
			if(Flag)
			{
				//清空List Box
				SendMessage(GetDlgItem(hDlg,IDC_LIST_RST),LB_RESETCONTENT,NULL,NULL);
				//获取起止IP
				SendMessage(GetDlgItem(hDlg,IDC_IP_START),IPM_GETADDRESS,0,(LPARAM)&StartIp);
				SendMessage(GetDlgItem(hDlg,IDC_IP_END),IPM_GETADDRESS,0,(LPARAM)&EndIp);
				//获取起止端口
				StartPort = GetDlgItemInt(hDlg,IDC_EDIT_STARTPORT,NULL,FALSE);
				EndPort = GetDlgItemInt(hDlg,IDC_EDIT_ENDPORT,NULL,FALSE);
				//开始扫描
				StartScanner(StartIp,EndIp,StartPort,EndPort);
			}
			break;
		default:
			break;
		}
		break;
		//关闭窗口消息
	case WM_CLOSE:
		EndDialog(hDlg,WM_CLOSE);
		DestroyWindow(hDlg);
		break;
	default:
		break;
	}
	return 0;
}
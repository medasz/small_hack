#include "resource.h"
#include <Windows.h>

//全局钩子句柄
HHOOK hHook = NULL;

/////////////////
//函数声明部分
////////////////
//鼠标钩子过程
LRESULT CALLBACK HookProc(int nCode,WPARAM wparam,LPARAM lparam);
//窗口过程
int CALLBACK DlgProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);


//主函数
int APIENTRY WinMain(__in HINSTANCE hInstance,__in_opt HINSTANCE hPrevInstance,__in_opt LPSTR lpCmdLine,__in int nShowCmd)
{
	return DialogBox(hInstance,MAKEINTRESOURCE(IDD_DIALOG),NULL,DlgProc);
}

/////////////////////////////////////////////
//窗口过程处理函数
//////////////////////////////////////////////
int CALLBACK DlgProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	switch(uMsg)
	{
	case WM_COMMAND:
		{
			switch(LOWORD(wParam))
			{
			case IDCANCEL:
				{
					UnhookWindowsHookEx(hHook);
					EndDialog(hDlg,wParam);
				}
				break;
			case IDOK:
				{
					hHook = SetWindowsHookEx(WH_MOUSE_LL,HookProc,GetModuleHandle(NULL),0);
					if (hHook == NULL)
					{
						DWORD err = GetLastError();

						char buf[256];
						wsprintfA(
							buf,
							"Hook安装失败，错误码：%lu",
							err
						);

						MessageBoxA(
							hDlg,
							buf,
							"错误",
							MB_OK | MB_ICONERROR
						);
					}
				}
				break;
			}
		}
		break;
	case WM_CLOSE:
		{
			EndDialog(hDlg,WM_CLOSE);
		}
		break;
	}
	return 0;
}

///////////////////////////////
//鼠标钩子过程
//////////////////////////////
LRESULT CALLBACK HookProc(int code,WPARAM wparam,LPARAM lparam)
{
	HWND hWnd;
	POINT point;
	//获取鼠标位置
	GetCursorPos(&point);
	//得到鼠标的窗口句柄
	hWnd = WindowFromPoint(point);
	//得到窗口风格
	long nStyle = GetWindowLong(hWnd,GWL_STYLE);
	MSLLHOOKSTRUCT * event = (MSLLHOOKSTRUCT *)lparam;
	//是否为密码左键
	if(wparam == WM_LBUTTONDOWN)
	{
		//是否为密码框
		if(nStyle&ES_PASSWORD)
		{
			SendMessage(hWnd,EM_SETPASSWORDCHAR,0,0);
		}
	}
	return CallNextHookEx(hHook,code,wparam,lparam);
}
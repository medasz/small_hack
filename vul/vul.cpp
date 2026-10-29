#include <windows.h>
#include <stdio.h>
char src[]=
		"\x55"											//push ebp							;保存栈底（为了使测试ShellCode时比较方便，还是按一般函数的格式来写，但以后就不需要了）
		"\x8B\xEC"										//mov ebp,esp						;更新ebp,构造新栈
		"\x66\x81\xEC\x04\x04"							//sub sp,0x0404						;将栈顶抬高，开辟新空间
		"\x33\xFF"										//xor edi,edi
		"\x57"											//push edi							;首先填入"mmm"字符串的结束符
		"\xC6\x04\x24\x6D"								//mov byte ptr [esp+00h],6dh		;填入三个m
		"\xC6\x44\x24\x01\x6D"							//mov byte ptr [esp+01h],6dh
		"\xC6\x44\x24\x02\x6D"							//mov byte ptr [esp+02h],6dh
		"\x57"											//push edi							;压入MessageBoxA的最后一个参数
		"\x8D\x44\x24\x04"								//lea eax,[esp+04h]
		"\x50"											//push eax							;压入"mmm"的地址，即倒数第二个参数
		"\x50"											//push eax							;压入"mmm"的地址，即倒数第三个参数
		"\x57"											//push edi							;压入第一个参数
		"\xB8\xEA\x07\xD5\x77"							//mov eax,0x77d507ea
		"\xFF\xD0"										//call eax							;调用MessageBoxA
		"\x8B\xE5"										//mov esp,ebp						;恢复堆栈
		"\x5D"											//pop ebp							;恢复堆栈
		"\xC3";											//ret
int main()
{
	
	LoadLibraryA("user32.dll");
	//FARPROC pfunc = GetProcAddress(handle,"MessageBoxA");
	//printf("MessageBoxA address = %p\n", (void*)pfunc);
	((void(*)(void))&src)();
}
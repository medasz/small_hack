.386
.model flat, stdcall


.code

main:
    ; ======== main: 初始化，获取kernel32基址 ========
    sub  sp, 0104h              ; 抬高栈顶，分配局部空间
    mov  ebp, esp               ; 保存栈底
    xor  eax, eax               ; 寄存器初始化
    mov  ax, 3233h
    push eax
    push 72657375h              ; 压入"user32"字符串
    mov  ax, 6d6dh
    push eax                    ; 压入"mm"，供MessageBoxA使用
    cdq                         ; 相当于 xor edx, edx
    assume fs:nothing           ; 告知MASM fs不指向已知段
    mov  ebx, fs:[edx+30h]     ; 获取PEB地址
    mov  ecx, [ebx+0ch]        ; PEB->Ldr
    mov  ecx, [ecx+1ch]        ; Ldr->InInitializationOrderModuleList
    mov  ecx, [ecx]            ; 第一个模块
    mov  ecx, [ecx+08h]        ; 获取kernel32.dll基址
    push ecx                    ; 用ecx保存kernel32.dll基址并压入

    push 0c917432h             ; 压入LoadLibraryA的hash值
    push ecx                    ; 压入kernel32.dll基址
    mov  bl, 01h               ; bl=1，标识当前执行阶段
    jmp  FindFunc               ; 转到FindFunc寻找LoadLibraryA的地址

    ; ======== MainTemp: 根据bl决定跳转到哪个分支 ========
MainTemp:
    cmp  bl, 01h
    jz   MainTemp1
    cmp  bl, 02h
    jz   MainTemp2
    cmp  bl, 03h
    jz   MainTemp3

    ; ======== MainTemp1: 调用LoadLibraryA加载user32 ========
MainTemp1:
    lea  ecx, dword ptr [ebp-08h]   ; 压入"user32"地址
    push ecx
    call eax                         ; 调用LoadLibraryA
    push 1E380A6Ah                  ; 压入MessageBoxA的hash值
    push eax                         ; 压入user32基址
    mov  bl, 02h
    jmp  FindFunc                    ; 寻找MessageBoxA

    ; ======== MainTemp2: 调用MessageBoxA ========
MainTemp2:
    cdq
    push edx
    lea  ecx, dword ptr [ebp-0ch]   ; 压入"mm"地址
    push ecx
    push ecx
    push edx
    call eax                         ; 调用MessageBoxA
    push 4fd18963h                  ; 压入ExitProcess的hash值
    push dword ptr [ebp-10h]        ; 压入kernel32基址
    mov  bl, 03h
    jmp  FindFunc                    ; 跳转寻找ExitProcess地址

    ; ======== MainTemp3: 调用ExitProcess ========
MainTemp3:
    cdq
    push edx
    call eax                         ; 调用ExitProcess

    ; ======== FindFunc: 在DLL导出表中查找目标函数 ========
    ; 紧接MainTemp3，距第一个 jmp FindFunc 恰好57字节
FindFunc:
    push ebp
    mov  ebp, esp
    push ebx                         ; 保存寄存器的值

    mov  ebx, dword ptr [ebp+04h]  ; 获得动态链接库基址
    mov  eax, [ebx+3ch]            ; PE头的偏移
    mov  ecx, [eax+ebx+78h]       ; 导出表的偏移
    add  ecx, ebx                   ; 导出表的地址

    mov  edx, [ecx+20h]            ; 函数名导出表偏移
    add  edx, ebx                   ; 函数名导出表地址
    xor  edi, edi                   ; edi清零，用于计数

FindFuncLoop:
    inc  edi                         ; 计数递增
    mov  esi, [edx+edi*4]          ; 取函数名偏移
    add  esi, ebx                   ; 加基址得函数名地址
    push esi                         ; 压入函数名地址（作为GetHash参数）
    jmp  GetHash                    ; 向前跳转到GetHash（GetHash在后面）

FindFuncTemp:
    cmp  eax, dword ptr [ebp+08h]  ; 比较hash值是否匹配
    jnz  FindFuncLoop              ; 若不同，继续循环
    mov  eax, [ecx+1ch]            ; 函数偏移导出表的偏移
    add  eax, ebx                   ; 函数偏移导出表的地址
    mov  eax, [eax+edi*4]          ; 函数的偏移
    add  eax, ebx                   ; 函数的实际地址（返回值在eax中）
    jmp  FindFuncRetrun
    nop

FindFuncRetrun:
    pop  ebx                         ; 恢复寄存器
    mov  esp, ebp                   ; 恢复堆栈
    pop  ebp
    add  esp, 08h                   ; 平衡堆栈（清理2个参数：基址+hash值）
    jmp  MainTemp                   ; 向后跳转回MainTemp继续执行

    ; ======== GetHash: 计算函数名hash值 ========
    ; 放在FindFuncRetrun之后，jmp GetHash为向前跳，jmp FindFuncTemp为向后跳
GetHash:
    push ebp
    mov  ebp, esp
    push ebx                         ; 保存寄存器的值
    push ecx                         ; 保存寄存器的值
    push edx                         ; 保存寄存器的值
    xor  eax, eax                   ; 初始化hash累计寄存器
    xor  ebx, ebx                   ; 初始化
    cdq                              ; 相当于 xor edx, edx
    mov  ecx, dword ptr [ebp+04h]  ; ecx = 要hash的函数名地址

HashLoop:
    cmp  dl, byte ptr [ecx]         ; 与\x00比较，判断是否到结尾
    jz   GetHashReturn              ; 已到结尾则跳出循环
    ror  eax, 7                     ; eax循环右移7位
    movsx ebx, byte ptr [ecx]      ; 取当前字符到ebx
    add  eax, ebx                   ; 累积到eax
    inc  ecx                        ; 指向下一个字符
    jmp  HashLoop                   ; 循环
    nop

GetHashReturn:
    pop  edx                        ; 恢复各个寄存器
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    add  esp, 04h                   ; 平衡堆栈（清理1个参数：函数名指针）
    jmp  FindFuncTemp               ; 向后跳转回FindFuncTemp继续比较hash



END main

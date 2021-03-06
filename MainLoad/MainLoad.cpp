// MainLoad.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include "loader2.h"
#ifndef _WIN64
#define DLLPATH L".\\MainLoad32.dll"
#define LOADECODE L".\\LOADECODE32.code"
#else
#define DLLPATH L".\\MainLoad64.dll"
#define LOADECODE L".\\LOADECODE64.code"
#endif 
void SaveShellCode()
{
	
	
	DWORD size = 0, ssss=0;
	WORD* Memx = (WORD*)MemLoadLibrary2;
	while (*Memx != 0xCCCC)
	{
		Memx++;
		size += 2;
	}
	
	printf("MemLoadLibrary2=%p codesite=%X\n", MemLoadLibrary2, size);
	HANDLE hFile = CreateFile(LOADECODE, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, NULL, NULL);
	if (hFile)
	{
		WriteFile(hFile, MemLoadLibrary2, size, &ssss, NULL);
		CloseHandle(hFile);
	}
	
	
}
void Test1()
{
	HANDLE hFile = CreateFile(DLLPATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile)
	{

		DWORD fileSize = GetFileSize(hFile, NULL);
		DWORD RSize = 0;
		VOID *pBuffer = malloc(fileSize);
		ReadFile(hFile, pBuffer, fileSize, &RSize, NULL);
		HMODULE NTDLL = GetModuleHandleA("ntdll");
		PARAMX param;
		RtlZeroMemory(&param, sizeof(PARAMX));
		param.lpFileData = pBuffer;
		param.DataLength = fileSize;
		param.LdrGetProcedureAddress = (LdrGetProcedureAddressT)GetProcAddress(NTDLL, "LdrGetProcedureAddress");;
		param.dwNtAllocateVirtualMemory = (NtAllocateVirtualMemoryT)GetProcAddress(NTDLL, "NtAllocateVirtualMemory");
		param.pLdrLoadDll = (LdrLoadDllT)GetProcAddress(NTDLL, "LdrLoadDll");
		param.RtlInitAnsiString = (RtlInitAnsiStringT)GetProcAddress(NTDLL, "RtlInitAnsiString");
		param.RtlAnsiStringToUnicodeString = (RtlAnsiStringToUnicodeStringT)GetProcAddress(NTDLL, "RtlAnsiStringToUnicodeString");
		param.RtlFreeUnicodeString = (RtlFreeUnicodeStringT)GetProcAddress(NTDLL, "RtlFreeUnicodeString");
		PVOID pModule = (PVOID)MemLoadLibrary2(&param);
		printf("pModule=%p \n", pModule);
		CloseHandle(hFile);
		free(pBuffer);
	}
}

void Test2()
{
	SIZE_T dWrited = 0;
	HANDLE hFile = CreateFile(DLLPATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	HANDLE hFile2 = CreateFile(LOADECODE, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile && hFile2)
	{
		//获取DLL数据
		DWORD fileSize = GetFileSize(hFile, NULL);
		DWORD RSize = 0;
		VOID *pBuffer = malloc(fileSize);
		ReadFile(hFile, pBuffer, fileSize, &RSize, NULL);

		//获取shellcode
		DWORD fileSize2 = GetFileSize(hFile2, NULL);

		VOID *pBuffer2 = malloc(fileSize2);
		ReadFile(hFile2, pBuffer2, fileSize2, &RSize, NULL);

		HMODULE NTDLL = GetModuleHandleA("ntdll");
		PARAMX param;
		RtlZeroMemory(&param, sizeof(PARAMX));
		param.lpFileData = pBuffer;
		param.DataLength = fileSize;
		param.LdrGetProcedureAddress = (LdrGetProcedureAddressT)GetProcAddress(NTDLL, "LdrGetProcedureAddress");;
		param.dwNtAllocateVirtualMemory = (NtAllocateVirtualMemoryT)GetProcAddress(NTDLL, "NtAllocateVirtualMemory");
		param.pLdrLoadDll = (LdrLoadDllT)GetProcAddress(NTDLL, "LdrLoadDll");
		param.RtlInitAnsiString = (RtlInitAnsiStringT)GetProcAddress(NTDLL, "RtlInitAnsiString");
		param.RtlAnsiStringToUnicodeString = (RtlAnsiStringToUnicodeStringT)GetProcAddress(NTDLL, "RtlAnsiStringToUnicodeString");
		param.RtlFreeUnicodeString = (RtlFreeUnicodeStringT)GetProcAddress(NTDLL, "RtlFreeUnicodeString");
		
		//开始远程注入
		HANDLE hProcess = GetCurrentProcess();//目标进程句柄
		//申请内存,把shellcode和DLL数据,和参数复制到目标进程
		PBYTE  pAddress = (PBYTE)VirtualAllocEx(hProcess, 0, fileSize+ fileSize2+sizeof(PARAMX)+0x100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//安全起见,大小多加0x100
		param.lpFileData = pAddress;//修成下DLL数据的地址
		WriteProcessMemory(hProcess, pAddress, pBuffer, fileSize, &dWrited);//DLL数据写入到目标
		WriteProcessMemory(hProcess, pAddress+ fileSize, pBuffer2, fileSize2, &dWrited);//shellcode写入到目标
		WriteProcessMemory(hProcess, pAddress+ fileSize+ fileSize2, &param, sizeof(PARAMX), &dWrited);//参数写入到目标
	
		//启动注入线程=pAddress+ fileSize,参数=pAddress+ fileSize+ fileSize2;
		HANDLE hThread= CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)(pAddress + fileSize), pAddress + fileSize + fileSize2, 0,0);
		if (hThread)
		{
			DWORD dExecCode = 0;
			printf("等待注入线程执行完毕....\n");
			WaitForSingleObject(hThread, -1);
			GetExitCodeThread(hThread, &dExecCode);
#ifdef _WIN64

			printf("注入完成....%p\n", dExecCode+ (((DWORD64)pAddress>>32)<<32));//如果是64位,基于内存申请的地址逐步累加,可以大概算出注入的模块基址
#else
			printf("注入完成....%p \n", dExecCode);//如果是32位注入,这里的dExecCode=注入的模块基址
#endif 

			//释放掉申请的内存
			VirtualFreeEx(hProcess, pAddress, 0, MEM_FREE);
			CloseHandle(hThread);
			CloseHandle(hProcess);
		}
	
		CloseHandle(hFile);
		free(pBuffer);
		CloseHandle(hFile2);
		free(pBuffer2);
		
	}
}
#ifdef _EXE
int main()
{
    std::cout << "Hello World!\n"; 
	SaveShellCode();
	Test1();
	Test2();
	getchar();
}
#else
DWORD WINAPI TestThread(PVOID lpram)
{
	wchar_t msg[100] = {0};
	wsprintf(msg, L"模块地址=%p", lpram);
	MessageBox(0, msg, 0, 0);
	return 0;
}
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		CreateThread(0, 0, TestThread, lpReserved, 0, 0);
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}
#endif // _CONSOLE

#include <Windows.h>
#include <Winternl.h>
#ifdef _WIN64
typedef  DWORD64 DWORDX;
#else
typedef  DWORD32 DWORDX;
#endif
typedef NTSTATUS(WINAPI *LdrGetProcedureAddressT)(IN PVOID DllHandle,IN PANSI_STRING ProcedureName OPTIONAL,IN ULONG ProcedureNumber OPTIONAL,OUT FARPROC *ProcedureAddress);
typedef VOID (WINAPI *RtlFreeUnicodeStringT)(_Inout_ PUNICODE_STRING UnicodeString);
typedef  VOID (WINAPI *RtlInitAnsiStringT)(_Out_    PANSI_STRING DestinationString,_In_opt_ PCSZ         SourceString);
typedef NTSTATUS (WINAPI *RtlAnsiStringToUnicodeStringT)(_Inout_ PUNICODE_STRING DestinationString,_In_ PCANSI_STRING SourceString,_In_ BOOLEAN AllocateDestinationString);
typedef NTSTATUS(WINAPI *LdrLoadDllT)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
typedef BOOL (APIENTRY *ProcDllMain)(LPVOID, DWORD, LPVOID );
typedef NTSTATUS (WINAPI *NtAllocateVirtualMemoryT)(IN HANDLE ProcessHandle,IN OUT PVOID *BaseAddress,IN ULONG ZeroBits,IN OUT PSIZE_T RegionSize,IN ULONG AllocationType,IN ULONG Protect);

struct PARAMX
{
	PVOID lpFileData;
	DWORD DataLength;
	LdrGetProcedureAddressT LdrGetProcedureAddress;
	NtAllocateVirtualMemoryT dwNtAllocateVirtualMemory;
	LdrLoadDllT pLdrLoadDll;
	RtlInitAnsiStringT RtlInitAnsiString;
	RtlAnsiStringToUnicodeStringT RtlAnsiStringToUnicodeString;
	RtlFreeUnicodeStringT RtlFreeUnicodeString;

	
};

 DWORDX WINAPI MemLoadLibrary2(PARAMX *X)//2502
{

	LPCVOID lpFileData = X->lpFileData;
	DWORDX DataLength = X->DataLength;

	/****************初始化调用函数********************/
	LdrGetProcedureAddressT LdrGetProcedureAddress = (X->LdrGetProcedureAddress);
	
	NtAllocateVirtualMemoryT pNtAllocateVirtualMemory = (X->dwNtAllocateVirtualMemory);
	LdrLoadDllT pLdrLoadDll = (X->pLdrLoadDll);
	RtlInitAnsiStringT RtlInitAnsiString= X->RtlInitAnsiString;
	RtlAnsiStringToUnicodeStringT RtlAnsiStringToUnicodeString=X->RtlAnsiStringToUnicodeString;
	RtlFreeUnicodeStringT RtlFreeUnicodeString = X->RtlFreeUnicodeString;
	
	ProcDllMain pDllMain = NULL;
	void *pMemoryAddress = NULL;
	
	
	
	ANSI_STRING ansiStr;
	UNICODE_STRING UnicodeString;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNTHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;
	int ImageSize=0;

	int nAlign=0;
	int i=0;
	
	
	//检查数据有效性，并初始化
	/*********************CheckDataValide**************************************/
	//	PIMAGE_DOS_HEADER pDosHeader;
	//检查长度
	if(DataLength > sizeof(IMAGE_DOS_HEADER)) 
	{
		pDosHeader = (PIMAGE_DOS_HEADER)lpFileData; // DOS头
		//检查dos头的标记
		if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) goto CODEEXIT; //0×5A4D : MZ
		
		//检查长度
		if((DWORDX)DataLength < (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) ) goto CODEEXIT;
		//取得pe头
		pNTHeader = (PIMAGE_NT_HEADERS)( (DWORDX)lpFileData + pDosHeader->e_lfanew); // PE头
		//检查pe头的合法性
		if(pNTHeader->Signature != IMAGE_NT_SIGNATURE) goto CODEEXIT; //0×00004550: PE00
		if((pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) //0×2000: File is a DLL
			goto CODEEXIT;
		if((pNTHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0) //0×0002: 指出文件可以运行
			goto CODEEXIT;
		if(pNTHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
			goto CODEEXIT;
		
		
		//取得节表（段表）
		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORDX)pNTHeader + sizeof(IMAGE_NT_HEADERS));
		//验证每个节表的空间
		for( i=0; i< pNTHeader->FileHeader.NumberOfSections; i++)
		{
			if((pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData) > (DWORD)DataLength) goto CODEEXIT;
		}
		
		/**********************************************************************/
		nAlign = pNTHeader->OptionalHeader.SectionAlignment; //段对齐字节数

		//ImageSize = pNTHeader->OptionalHeader.SizeOfImage;
		//// 计算所有头的尺寸。包括dos, coff, pe头 和 段表的大小
		ImageSize = (pNTHeader->OptionalHeader.SizeOfHeaders + nAlign - 1) / nAlign * nAlign;
		// 计算所有节的大小
		for( i=0; i < pNTHeader->FileHeader.NumberOfSections; ++i)
		{
			//得到该节的大小
			int CodeSize = pSectionHeader[i].Misc.VirtualSize ;
			int LoadSize = pSectionHeader[i].SizeOfRawData;
			int MaxSize = (LoadSize > CodeSize)?(LoadSize):(CodeSize);
			
			int SectionSize = (pSectionHeader[i].VirtualAddress + MaxSize + nAlign - 1) / nAlign * nAlign;
			if(ImageSize < SectionSize)
				ImageSize = SectionSize; //Use the Max;
		}
		if (ImageSize==0) goto CODEEXIT;

		// 分配虚拟内存
		SIZE_T uSize = ImageSize;
		pNtAllocateVirtualMemory((HANDLE)-1, &pMemoryAddress, 0, &uSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if(pMemoryAddress != NULL)
		{
			
			// 计算需要复制的PE头+段表字节数
			int HeaderSize = pNTHeader->OptionalHeader.SizeOfHeaders;
			int SectionSize = pNTHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
			int MoveSize = HeaderSize + SectionSize;
			//复制头和段信息
			for ( i = 0; i < MoveSize; i++)
			{
				*((PCHAR)pMemoryAddress + i) = *((PCHAR)lpFileData+i);
			}
			//memmove(pMemoryAddress, lpFileData, MoveSize);//为了少用一个API,直接用上面的单字节复制数据就行了
			
			//复制每个节
			for(i=0; i < pNTHeader->FileHeader.NumberOfSections; ++i)
			{
				if(pSectionHeader[i].VirtualAddress == 0 || pSectionHeader[i].SizeOfRawData == 0)continue;
				// 定位该节在内存中的位置
				void *pSectionAddress = (void *)((DWORDX)pMemoryAddress + pSectionHeader[i].VirtualAddress);
				// 复制段数据到虚拟内存
			//	memmove((void *)pSectionAddress,(void *)((DWORDX)lpFileData + pSectionHeader[i].PointerToRawData),	pSectionHeader[i].SizeOfRawData);
				//为了少用一个API,直接用上面的单字节复制数据就行了
				for (size_t k = 0; k < pSectionHeader[i].SizeOfRawData; k++)
				{
					*((PCHAR)pSectionAddress + k) = *((PCHAR)lpFileData + pSectionHeader[i].PointerToRawData + k);
				}
			}
			/*******************重定位信息****************************************************/
			
			if(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress >0
				&& pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size>0)
			{
				
				DWORDX Delta = (DWORDX)pMemoryAddress - pNTHeader->OptionalHeader.ImageBase;
				DWORDX * pAddress;
				//注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址
				PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((DWORDX)pMemoryAddress
					+ pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
				while((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
				{
					WORD *pLocData = (WORD *)((DWORDX)pLoc + sizeof(IMAGE_BASE_RELOCATION));
					//计算本节需要修正的重定位项（地址）的数目
					int NumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);
					for(  i=0 ; i < NumberOfReloc; i++)
					{
						if( (DWORDX)(pLocData[i] & 0xF000) == 0x00003000 || (DWORDX)(pLocData[i] & 0xF000) == 0x0000A000) //这是一个需要修正的地址
						{
							// 举例：
							// pLoc->VirtualAddress = 0×1000;
							// pLocData[i] = 0×313E; 表示本节偏移地址0×13E处需要修正
							// 因此 pAddress = 基地址 + 0×113E
							// 里面的内容是 A1 ( 0c d4 02 10) 汇编代码是： mov eax , [1002d40c]
							// 需要修正1002d40c这个地址
							pAddress = (DWORDX *)((DWORDX)pMemoryAddress + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
							*pAddress += Delta;
						}
					}
					//转移到下一个节进行处理
					pLoc = (PIMAGE_BASE_RELOCATION)((DWORDX)pLoc + pLoc->SizeOfBlock);
				}
				/***********************************************************************/
			}
			
			/******************* 修正引入地址表**************/
			DWORDX Offset = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
			if(Offset == 0) 
				goto CODEEXIT; //No Import Table
		
			PIMAGE_IMPORT_DESCRIPTOR pID = (PIMAGE_IMPORT_DESCRIPTOR)((DWORDX) pMemoryAddress + Offset);
		
			PIMAGE_IMPORT_BY_NAME pByName = NULL;
			while(pID->Characteristics != 0 )
			{
				PIMAGE_THUNK_DATA pRealIAT = (PIMAGE_THUNK_DATA)((DWORDX)pMemoryAddress + pID->FirstThunk);
				PIMAGE_THUNK_DATA pOriginalIAT = (PIMAGE_THUNK_DATA)((DWORDX)pMemoryAddress + pID->OriginalFirstThunk);
				//获取dll的名字
				char* pName = (char*)((DWORDX)pMemoryAddress + pID->Name);
				HANDLE hDll = 0;
		
				RtlInitAnsiString(&ansiStr, pName);
				
				RtlAnsiStringToUnicodeString(&UnicodeString, &ansiStr, true);
				pLdrLoadDll(NULL, NULL, &UnicodeString, &hDll);
				RtlFreeUnicodeString(&UnicodeString);

				if(hDll == NULL) {
					
					goto CODEEXIT; //NOT FOUND DLL
				}
				
				//获取DLL中每个导出函数的地址，填入IAT
				//每个IAT结构是 ：
				// union { PBYTE ForwarderString;
				// PDWORDX Function;
				// DWORDX Ordinal;
				// PIMAGE_IMPORT_BY_NAME AddressOfData;
				// } u1;
				// 长度是一个DWORDX ，正好容纳一个地址。
				for( i=0; ;i++)
				{
					if(pOriginalIAT[i].u1.Function == 0)break;
					FARPROC lpFunction = NULL;
					if(IMAGE_SNAP_BY_ORDINAL(pOriginalIAT[i].u1.Ordinal)) //这里的值给出的是导出序号
					{
						if (IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal) )
						{
			
							LdrGetProcedureAddress(hDll, NULL, IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal), &lpFunction);
						}
					}
					else//按照名字导入
					{
						//获取此IAT项所描述的函数名称
						pByName = (PIMAGE_IMPORT_BY_NAME)((DWORDX)pMemoryAddress + (DWORDX)(pOriginalIAT[i].u1.AddressOfData));
						if ((char *)pByName->Name)
						{
							RtlInitAnsiString(&ansiStr, (char *)pByName->Name);
							LdrGetProcedureAddress(hDll, &ansiStr, 0, &lpFunction);
						
						}

					}
					
					//标记***********
					
					if(lpFunction != NULL) //找到了！
						pRealIAT[i].u1.Function =(DWORDX) lpFunction;
					else
						goto CODEEXIT;
				}
				
				//move to next
				pID = (PIMAGE_IMPORT_DESCRIPTOR)( (DWORDX)pID + sizeof(IMAGE_IMPORT_DESCRIPTOR));
			}
			
			/***********************************************************/
			//修正基地址
			pNTHeader->OptionalHeader.ImageBase = (DWORDX)pMemoryAddress;

			//NtProtectVirtualMemory((HANDLE)-1, &pMemoryAddress, (PSIZE_T)&ImageSize, PAGE_EXECUTE_READ, &oldProtect);
			pDllMain =(ProcDllMain) (pNTHeader->OptionalHeader.AddressOfEntryPoint +(DWORDX) pMemoryAddress);
			
			pDllMain(0, DLL_PROCESS_ATTACH, pMemoryAddress);//这里的参数1本来应该传的是(HMODULE)pMemoryAddress,但是没必要,因为无法使用资源,所以没必要,要使用资源,论坛有其他人说过如何使用

		}
	}
	
CODEEXIT:

	return (DWORDX)pMemoryAddress;


}

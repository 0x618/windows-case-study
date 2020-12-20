#include <stdio.h>
#include <windows.h>


int main(int argc, char argv[], char envp[]) {

	DWORD dwKernel32Base = 0;
	DWORD dwPEB = 0;
	DWORD dwPEBLDRData = 0;
	DWORD dwLDRList = 0;
	DWORD dwSizeOfImage = 0;

	DWORD dwImageExportDirectory = 0;
	DWORD dwNumberOfFunctions = 0;

	DWORD dwNamePointerTable = 0;
	DWORD dwFunctionPointerTable = 0;
	char* dwFunctionName;
	DWORD dwFunctionAddressRva = 0;
	DWORD dwFunctionAddress = 0;
	DWORD dwFunctionOffset = 0;
	char* sGetVersion = "GetVersion";
	DWORD dwVersion = 0;
	DWORD dwVersionEasy = GetVersion();

	HINSTANCE hWinAPI = 0;
	DWORD dwFunctionAddressEasy = 0;

	__asm
	{
		// --- Part 1 --- //

		mov eax, fs:[0x30]		// get base address of PEB from fs register
		mov dwPEB, eax			// move PEB base address into variable

		mov eax, [eax + 0x0c]	// get _PEB_LDR_DATA from within PEB
		mov dwPEBLDRData, eax	// and save address to variable

		mov eax, [eax + 0x14]	// get head of loaded modules doubly linked list
		mov dwLDRList, eax		// save address to variable
		

		// now we can traverse the linked list containing the loaded modules by following the ptr contained in eax.
		// the first entry is the executable being run, then ntdll.dll, and finally, kernel32.dll

		mov eax, [eax]			// load address of project_part01.exe
		mov eax, [eax]			// load address of ntdll.dll
		mov eax, [eax + 0x10]	// load address of kernel32.dll!
		
		mov dwKernel32Base, eax	// save address to variable for printing




		// --- Part 2 --- //

		// get SizeOfImage of Kernel32
		// SizeOfImage unsigned int value located at offset 0x138 from PE base

		add eax, 0x138
		mov dwSizeOfImage, eax


		// get Export Table of Kernel32
		// ptr to IMAGE_EXPORT_DIRECTORY data structure located at offset 0x170 from PE base, (or +0x28 from SizeOfImage)

		add eax, 0x28
		mov dwImageExportDirectory, eax 	// save ptr to IMAGE_EXPORT_DIRECTORY
		mov eax, [eax]						// load relative virtual address (RVA) of IMAGE_EXPORT_DIRECTORY
		add eax, dwKernel32Base				// add RVA of IMAGE_EXPORT_DIRECTORY to base address of Kernel32 to get virtual address of IMAGE_EXPORT_DIRECTORY
		add eax, 0x14 						// move to Number of Functions unsigned int value located at offset 0x14 from the base of IMAGE_EXPORT_DIRECTORY
		mov dwNumberOfFunctions, eax 		// save address of value to variable for printing




		// --- Part 3 --- //

		// search through export table for GetVersion
		add eax, 0xC						// navigate to pointer to Name Pointer Table in order to search through export function names
		mov eax, [eax]						// dereference pointer to Name Pointer Table RVA
		add eax, dwKernel32Base				// add Name Pointer Table RVA to base address of PE to get virtual address
		mov dwNamePointerTable, eax			// save pointer address to variable for printing


		// this subroutine iterates through the function name strings in the Name Pointer Table
		// and compares each string against the sGetVersion string until a match is found.

		xor edx, edx						// set edx = 0 to use as counter
		search_name_table:
			mov eax, dwNamePointerTable		// get VA of Name Pointer Table
			add eax, edx					// add counter to address
			mov eax, [eax]					// dereference to get RVA of function name
			add eax, dwKernel32Base			// add RVA to PE base to get virtual address of function name
			mov dwFunctionName, eax			// save VA for printing

			mov ecx, 11						// specify number of bytes to compare between strings ("GetVersion" is 10 characters + a null byte = 11)
			mov esi, eax					// compare function name (VA stored in eax)
			mov edi, sGetVersion			// against sGetVersion
			cld								// clear DF to ensure bytes are compared from 0->11
			repe cmpsb						// perform recursive byte comparison of strings;
											// set ZF=1 if all bytes match, otherwise, set ZF=0

			jz function_found				// if function names match, exit loop

			add edx, 4						// else, increment counter to select next function name in the list
			jnz search_name_table			// and return to beginning of loop

		function_found:						// function name found!
			add edx, 4						// increment counter and
			mov dwFunctionOffset, edx		// save final offset for printing


		// now that a function offset has been found, we can use that same offset to locate the RVA of the function pointer
		// for the corresponding function

		mov eax, dwKernel32Base				// this block adds up the PE base + the IMAGE_EXPORT_DIRECTORY offset + 0x1C
		mov ebx, dwImageExportDirectory		// to get the RVA of the Function Pointer Table
		add eax, [ebx]						// these function pointers are in exactly the same order as the function names,
		add eax, 0x1C						// and since we already have the offset, we know exactly where the pointer to
											// our desired function is in the list!
		mov eax, [eax]						// dereference the sum of our offsets to get the RVA of the Function Pointer Table

		add eax, dwKernel32Base				// get PE base
		mov dwFunctionPointerTable, eax		// save VA of Function Pointer Table

		add eax, dwFunctionOffset			// add function offset to Function Pointer Table VA
		mov eax, [eax]						// dereference to get RVA of Function
		mov dwFunctionAddressRva, eax		// save RVA

		add eax, dwKernel32Base				// add PE base to RVA to get VA
		mov dwFunctionAddress, eax			// save VA

		call eax							// call function
		mov dwVersion, eax					// save return value
	}


	printf("--------------------Part1-------------------\n");
	printf("[*] Found _PEB Base at 0x%08x\n", dwPEB);
	printf("[*] Found _PEB_LDR_DATA Base at 0x%08x\n", dwPEBLDRData);
	printf("[*] Found start of loaded module list at 0x%08x\n", dwLDRList);
	printf("[*] Found Kernel32 Base at 0x%08x\n", dwKernel32Base);

	printf("\n--------------------Part2-------------------\n");
	printf("[*] Found Kernel32 SizeOfImage attribute at 0x%08x.  The SizeOfImage for Kernel32 is %u bytes.\n", dwSizeOfImage, *((unsigned int *)dwSizeOfImage));
	printf("[*] Found IMAGE_EXPORT_DIRECTORY at 0x%08x\n", dwImageExportDirectory);
	printf("[*] Found number of exported functions within Kernel32 PE at 0x%08x.  There are %u functions in the export table.\n", dwNumberOfFunctions, *((unsigned int *)dwNumberOfFunctions));

	printf("\n--------------------Part3-------------------\n");
	printf("[*] Found NamePointerTable at 0x%08x\n", dwNamePointerTable);
	printf("[*] API function name %s found at 0x%08x, offset 0x%04x\n", dwFunctionName, dwFunctionName, dwFunctionOffset);
	printf("[*] Address table of functions found at 0x%08x\n", dwFunctionPointerTable);
	printf("[*] %s RVA = 0x%08x\n", dwFunctionName, dwFunctionAddressRva);
	printf("[*] %s VA = 0x%08x\n", dwFunctionName, dwFunctionAddress);

	// this block gets the VA of the GetVersion Win32 API call
	// using LoadLibrary and GetProcAddress (the easy way)
	hWinAPI = LoadLibrary(TEXT("kernel32.dll"));
	if(hWinAPI != NULL){
		dwFunctionAddressEasy = GetProcAddress(hWinAPI, sGetVersion);
		printf("[*] GetProcAddress shows that %s is in fact at 0x%08x\n", sGetVersion, dwFunctionAddressEasy);
	}

	printf("\n[*] High-level API call result = %08x, assembly API call result = %08x\n", dwVersionEasy, dwVersion);

	// check if the return values of the function calls matches;
	if(dwVersion == dwVersionEasy){
		// isolate the bits associated with each part of the Windows version
		int build = dwVersion>>16;
		int ver2 = (dwVersion<<16)>>24;
		int ver1 = (dwVersion<<24)>>24;

		printf("\n***  Success!  Windows is version %d.%d.%d ***\n", ver1, ver2, build);
	} else {
		printf("--------------------Failure!--------------------\n");
	}
    // keep cmd window open
	while(1){}
}

/*
	Sources:
	https://resources.infosecinstitute.com/topic/the-export-directory/
	https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2
	https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversion
	https://c9x.me/x86/html/file_module_x86_id_279.html
*/

#include "stdafx.h"
#include "CHook.h"
#include <tlhelp32.h>
#include <conio.h>
#include <string>

using namespace std;

bool CHook::debugInitialized = false;
DEBUG_HOOK_INFO CHook::debugHookInfos[4];

//	Constructor
CHook::CHook() {
	debugHookInfo.targetFunc = NULL;
	debugHookInfo.hookFunc = NULL;
	bHooked = false;

	if(!debugInitialized) {
		typedef PVOID(WINAPI *pfun)(ULONG, PVECTORED_EXCEPTION_HANDLER);
		pfun pAddVectoredExceptionHandler;

		HMODULE hMod = GetModuleHandle("ntdll.dll");
		if(hMod) {
			string sztmp = "R";sztmp += "t";sztmp += "l";sztmp += "A";sztmp += "d";sztmp += "d";sztmp += "V";sztmp += "e";sztmp += "c";
			sztmp += "t";sztmp += "o";sztmp += "r";sztmp += "e";sztmp += "d";sztmp += "E";sztmp += "x";sztmp += "c";sztmp += "e";sztmp += "p";
			sztmp += "t";sztmp += "i";sztmp += "o";sztmp += "n";sztmp += "H";sztmp += "a";sztmp += "n";sztmp += "d";sztmp += "l";sztmp += "e";
			sztmp += "r";

			pAddVectoredExceptionHandler = (pfun)GetProcAddress(hMod, sztmp.c_str());
			if(pAddVectoredExceptionHandler != NULL) {
				pAddVectoredExceptionHandler(0, (PVECTORED_EXCEPTION_HANDLER)DebugHookHandler);
			}
		}
		debugInitialized = true;
	}
}

CHook::~CHook() {
	Unhook();
}

bool CHook::SetHardwareBreakpoint(FARPROC hookFrom,FARPROC hookTo, HWBRK_TYPE type, HWBRK_SIZE size, FARPROC nextAddress) {
	if(bHooked) {
		return false;
	}
#ifdef USE_VMPSDK
	VMBEGIN
#endif

	int i = SetDebugBreak(hookFrom, type, size);
	_cprintf("idr %d\n",i);

	if(i == -1) {
		return false;
	}
	debugHookInfo.targetFunc = hookFrom;
	debugHookInfo.hookFunc = hookTo;
	debugHookInfo.type = type;
	debugHookInfo.size = size;
	debugHookInfo.nextAddress = nextAddress;

	debugHookInfos[i] = debugHookInfo;

	bHooked = true;

	_cprintf("hookFrom 0x%08X hookTo 0x%08X \n",hookFrom,hookTo);

#ifdef USE_VMPSDK
	VMEND
#endif

	return true;
}

bool CHook::Unhook() {
	if(!bHooked) {
		return false;
	}

	DWORD i;
	for(i = 0; debugHookInfos[i].targetFunc != debugHookInfo.targetFunc; i++);
	_cprintf("clear reg dr%d targetFuncs 0x%08x m_hookFrom 0x%08X m_hookTo 0x%08X\n",
		i, debugHookInfos[i].targetFunc, debugHookInfo.targetFunc, debugHookInfo.hookFunc);
	debugHookInfos[i].targetFunc = NULL;
	debugHookInfos[i].hookFunc = NULL;
	if(ClearDebugBreak(i)) {
		bHooked = false;
	}

	if(!bHooked) {
		return true;
	}
	return false;
}

__forceinline void CHook::SetBits(DWORD_PTR& dw, int lowBit, int bits, int newValue) {
	DWORD_PTR mask = (1 << bits) - 1;
	dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
}

__forceinline void CHook::setDr7Flag(DWORD &dr7, int drIndex, HWBRK_TYPE type, HWBRK_SIZE size) {
	int st = 0;
	if (type == HWBRK_TYPE_CODE)
		st = 0;
	if (type == HWBRK_TYPE_WRITE)
		st = 1;
	if (type == HWBRK_TYPE_READWRITE)
		st = 3;
	int le = 0;
	if (size == HWBRK_SIZE_1)
		le = 0;
	if (size == HWBRK_SIZE_2)
		le = 1;
	if (size == HWBRK_SIZE_4)
		le = 3;
	if (size == HWBRK_SIZE_8)
		le = 2;

	SetBits(dr7, 16 + drIndex*4, 2, st);
	SetBits(dr7, 18 + drIndex*4, 2, le);
	SetBits(dr7, drIndex*2,1,1);
}

__forceinline void CHook::resetDr7Flag(DWORD &dr7, int drIndex) {
	int flagBit = drIndex * 2;
	dr7 &= ~(1 << flagBit);
}

__forceinline int CHook::SetDebugBreak(FARPROC address, HWBRK_TYPE type, HWBRK_SIZE size) {
	int retval = -1;
	DWORD ret;
	HANDLE thSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);

	Thread32First(thSnap, &te);
	do {
		if(te.th32OwnerProcessID != GetCurrentProcessId()) {
			continue;
		}
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
		_cprintf("hThread: %08X err: %d\n", hThread, GetLastError());
		CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		ret = GetThreadContext(hThread, &ctx);
		_cprintf("GetThreadContext ret: %d\n", ret);
		_cprintf("set threadID %8d source Dr7=0x%08X\n",te.th32ThreadID,ctx.Dr7);
		if(!ctx.Dr0) {
			ctx.Dr0 = MakePtr(DWORD, address, 0);
			retval = 0;
		} else if(!ctx.Dr1) {
			ctx.Dr1 = MakePtr(DWORD, address, 0);
			retval = 1;
		} else if(!ctx.Dr2) {
			ctx.Dr2 = MakePtr(DWORD, address, 0);
			retval = 2;
		} else if(!ctx.Dr3) {
			ctx.Dr3 = MakePtr(DWORD, address, 0);
			retval = 3;
		} else {
			retval = -1;
		}

		if (retval != -1) {
			setDr7Flag(ctx.Dr7, retval, type, size);
		}

		_cprintf("set threadID %8d target Dr7=0x%08X\n",te.th32ThreadID,ctx.Dr7);
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		ret = SetThreadContext(hThread, &ctx);
		_cprintf("SetThreadContext ret: %d\n", ret);
		CloseHandle(hThread);
	} while(Thread32Next(thSnap, &te));

	return retval;
}

bool CHook::ClearDebugBreak(DWORD index) {
	HANDLE thSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);
	Thread32First(thSnap, &te);
	do {
		if(te.th32OwnerProcessID != GetCurrentProcessId()) {
			continue;
		}
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
		CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		GetThreadContext(hThread, &ctx);
		_cprintf("clear idx%d  threadID %d source Dr0 0x%08X  Dr7 0x%08X\n",index,te.th32ThreadID,ctx.Dr0,ctx.Dr7);
		switch(index)
		{
		case 0:
			ctx.Dr0 = 0;
			resetDr7Flag(ctx.Dr7, 0);
			break;
		case 1:
			ctx.Dr1 = 0;
			resetDr7Flag(ctx.Dr7, 1);
			break;
		case 2:
			ctx.Dr2 = 0;
			resetDr7Flag(ctx.Dr7, 2);
			break;
		case 3:
			ctx.Dr3 = 0;
			resetDr7Flag(ctx.Dr7, 3);
			break;
		default:
			return false;
		}
		_cprintf("clear idx%d  threadID %d source Dr0 0x%08X  Dr7 0x%08X\n",index,te.th32ThreadID,ctx.Dr0,ctx.Dr7);
		SetThreadContext(hThread, &ctx);
		CloseHandle(hThread);
	} while(Thread32Next(thSnap, &te));

	return true;
}

LONG CALLBACK CHook::DebugHookHandler(PEXCEPTION_POINTERS ExceptionInfo) {
	__asm pushad;
	if(ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
		// Excute
		for(int i = 0; i < 4; i++) {
			if(ExceptionInfo->ContextRecord->Eip == (DWORD)debugHookInfos[i].targetFunc) {
				ExceptionInfo->ContextRecord->Eip = (DWORD)debugHookInfos[i].hookFunc;
				__asm popad;
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
		// Read or Write
		for (int i=0; i<4; i++) {
			if(ExceptionInfo->ContextRecord->Eip == (DWORD)debugHookInfos[i].nextAddress) {
				ExceptionInfo->ContextRecord->Eip = (DWORD)debugHookInfos[i].hookFunc;
				__asm popad;
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}

		_cprintf("eip %08X don't has handler\n", ExceptionInfo->ContextRecord->Eip);
	}

	__asm popad;
	return EXCEPTION_CONTINUE_SEARCH;
}

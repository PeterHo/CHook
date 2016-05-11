#pragma once

#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))

enum HWBRK_TYPE
{
	HWBRK_TYPE_CODE,
	HWBRK_TYPE_READWRITE,
	HWBRK_TYPE_WRITE,
};

enum HWBRK_SIZE
{
	HWBRK_SIZE_1,
	HWBRK_SIZE_2,
	HWBRK_SIZE_4,
	HWBRK_SIZE_8,
};

typedef struct tagDEBUG_HOOK_INFO
{
	// 需要下硬件断点的地址,可能是代码地址也可能是读写的内存
	FARPROC targetFunc;
	// 触发硬件断点时的处理函数
	FARPROC hookFunc;
	// 硬件断点类型,读写执行
	HWBRK_TYPE type;
	// 硬件断点大小 1 2 4 8
	HWBRK_SIZE size;
	// 当硬件断点为读写时,需要提供读写指令的下一条指令地址,用于判断触发的是哪个调试寄存器
	FARPROC nextAddress;
} DEBUG_HOOK_INFO;

class CHook
{
public:
	CHook();
	~CHook();

	// 添加硬件断点
	bool SetHardwareBreakpoint(FARPROC hookFrom,FARPROC hookTo, HWBRK_TYPE Type, HWBRK_SIZE Size, FARPROC nextAddress);
	// 直接添加硬件执行断点
	bool DebugHook(FARPROC hookFrom, FARPROC hookTo) {
		return SetHardwareBreakpoint(hookFrom, hookTo, HWBRK_TYPE_CODE, HWBRK_SIZE_1, 0);
	}
	bool Unhook();

	bool IsHooked() const { return bHooked; };
	FARPROC GetTarget() const { return debugHookInfo.targetFunc; };
	FARPROC GetHookFunc() const { return debugHookInfo.hookFunc; };

private:
	DEBUG_HOOK_INFO debugHookInfo;
	bool bHooked;

	static bool debugInitialized;
	static DEBUG_HOOK_INFO debugHookInfos[4];

	static void SetBits(DWORD_PTR& dw, int lowBit, int bits, int newValue);
	static void setDr7Flag(DWORD &dr7, int drIndex, HWBRK_TYPE type, HWBRK_SIZE size);
	static void resetDr7Flag(DWORD &dr7, int drIndex);
	static int SetDebugBreak(FARPROC address, HWBRK_TYPE type, HWBRK_SIZE size);
	static bool ClearDebugBreak(DWORD index);

	static LONG CALLBACK DebugHookHandler(PEXCEPTION_POINTERS ExceptionInfo);
};

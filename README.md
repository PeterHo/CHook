# CHook

能对本进程内所有线程下硬件的读写执行断点
参考了网上的众多代码

使用方法
```
#include "CHook.h"

// 注意要是全局变量
CHook *hook1;
CHook *hook2;

// 处理断点的中间函数,处理完成后返回到hookMidFunRetAddr
DWORD hookMidFunRetAddr = 0x00401000;
void __declspec(naked)hookMidFun() {
	__asm {
		pushad;
    // Do Some Thing
		popad;
		push [hookMidFunRetAddr];
		ret;
	}
}

void fun() {
  hook1 = new CHook();
  FARPROC srcAddr; // 下断点的地址
  // 设置一个硬件读写断点
  // srcAddr
  // 需要中断的读写内存的地址
  // hookMidFun
  // 当硬件断点被触发时调用的处理函数
  // HWBRK_TYPE_READWRITE
  // 表示是一个读写断点
  // HWBRK_SIZE_1
  // 表示断点长度为1
  // hookMidFunRetAddr
  // 为读写srcAddr处指令的下条指令的地址
  // 因为当硬件读写断点触发时不能获取读写内存的地址,而只能获取触发时指令的地址,因此需要用此参数来帮助程序识别触发的是哪一个断点
  hook1->SetHardwareBreakpoint(srcAddr, hookMidFun, HWBRK_TYPE_READWRITE, HWBRK_SIZE_1, (FARPROC)hookMidFunRetAddr);

  hook2 = new CHook();
  // 设置一个硬件执行断点
  // srcAddr
  // 需要中断的指令地址
  // hookMidFun
  // 当硬件断点被触发时调用的处理函数
  hook2->DebugHook(srcAddr, hookMidFun);
}
```

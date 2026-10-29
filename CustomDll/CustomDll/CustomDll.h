#ifdef CustomDLL_EXPORTS				//预定义宏
#define CustomDLL_API __declspec(dllexport)
#else
#define CustomDLL_API __declspec(dllimport)
#endif
//声明自定义导出函数
CustomDLL_API int DLLFuncAdd(int a,int b);
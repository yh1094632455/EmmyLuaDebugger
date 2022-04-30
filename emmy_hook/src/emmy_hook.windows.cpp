#include "emmy_hook/emmy_hook.h"
#include <cassert>
#include <mutex>
#include <set>
#include <unordered_map>
#include "emmy_debugger/emmy_facade.h"
#include "emmy_debugger/api/lua_api.h"
#include <ShlObj.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include "easyhook.h"
#include "libpe/libpe.h"
#include "io.h"
#include "emmy_debugger/proto/socket_server_transporter.h"
#include "shared/shme.h"
#if WIN32
#include "DebugHelp.h"
#endif


#define MAKE_PTR(cast, ptr, addValue ) (cast)( (DWORD)(ptr)+(DWORD)(addValue))
typedef TRACED_HOOK_HANDLE HOOK_HANDLE;
typedef NTSTATUS HOOK_STATUS;

HOOK_STATUS Hook(void* InEntryPoint,
                 void* InHookProc,
                 void* InCallback,
                 HOOK_HANDLE OutHandle);

HOOK_STATUS UnHook(HOOK_HANDLE InHandle);

typedef int (*_lua_pcall)(lua_State* L, int nargs, int nresults, int errfunc);

typedef int (*_lua_pcallk)(lua_State* L, int nargs, int nresults, int errfunc, lua_KContext ctx, lua_KFunction k);

typedef int (*_lua_resume_54)(lua_State* L, lua_State* from, int nargs, int* nresults);

typedef int (*_lua_resume_53_52)(lua_State* L, lua_State* from, int narg);

typedef int (*_lua_resume_51)(lua_State* L, int narg);

typedef HMODULE (WINAPI *LoadLibraryExW_t)(LPCWSTR lpFileName, HANDLE hFile, DWORD dwFlags);

LoadLibraryExW_t LoadLibraryExW_dll = nullptr;
bool                            g_initializedDebugHelp = false;
bool                            g_LoadDebugHelp = false;
std::string                     g_symbolsDirectory;
std::mutex mutexPostLoadModule;
std::set<std::string> loadedModules;
std::set<std::string>   g_warnedAboutLua;   // Indivates that we've warned the module contains Lua functions but none were loaded.
std::set<std::string>   g_warnedAboutPdb;   // Indicates that we've warned about a module having a mismatched PDB.
HOOK_STATUS Hook(void* InEntryPoint,
                 void* InHookProc,
                 void* InCallback,
                 HOOK_HANDLE OutHandle)
{
	const auto hHook = new HOOK_TRACE_INFO();
	ULONG ACLEntries[1] = {0};
	HOOK_STATUS status = LhInstallHook(
		InEntryPoint,
		InHookProc,
		InCallback,
		hHook);
	assert(status == 0);
	status = LhSetExclusiveACL(ACLEntries, 0, hHook);
	assert(status == 0);
	return status;
}

std::string GetEnvironmentVariable1(const std::string& name)
{

    DWORD size = ::GetEnvironmentVariable(name.c_str(), NULL, 0);

    std::string result;

    if (size > 0)
    {
    
        char* buffer = new char[size];
        buffer[0] = 0;

        GetEnvironmentVariable(name.c_str(), buffer, size);

        result = buffer;
        delete [] buffer;

    }

    return result;

}

std::string GetApplicationDirectory()
{

    char fileName[_MAX_PATH];
    GetModuleFileNameEx(GetCurrentProcess(), NULL, fileName, _MAX_PATH);

    char* term = strrchr(fileName, '\\'); 

    if (term != NULL)
    {
        *term = 0;
    }

    return fileName;

}
HOOK_STATUS UnHook(HOOK_HANDLE InHandle)
{
	ULONG ACLEntries[1] = {0};
	const HOOK_STATUS status = LhSetExclusiveACL(ACLEntries, 0, InHandle);
	return status;
}

int lua_pcall_worker(lua_State* L, int nargs, int nresults, int errfunc)
{
	EmmyFacade::Get().SendLog(LogType::Info, "lua_pcall_worker");
	LPVOID lp;
	LhBarrierGetCallback(&lp);
	const auto pcall = (_lua_pcall)lp;
	EmmyFacade::Get().Attach(L);
	EmmyFacade::Get().SendLog(LogType::Info, "EmmyFacade::Get().Attach(L)");
	return pcall(L, nargs, nresults, errfunc);
}

int lua_pcallk_worker(lua_State* L, int nargs, int nresults, int errfunc, lua_KContext ctx, lua_KFunction k)
{
	LPVOID lp;
	LhBarrierGetCallback(&lp);
	const auto pcallk = (_lua_pcallk)lp;
	EmmyFacade::Get().Attach(L);
	return pcallk(L, nargs, nresults, errfunc, ctx, k);
}

int lua_error_worker(lua_State* L)
{
	typedef int (*dll_lua_error)(lua_State*);
	EmmyFacade::Get().Attach(L);
	LPVOID lp;
	LhBarrierGetCallback(&lp);
	const auto error = (dll_lua_error)lp;
	// EmmyFacade::Get().BreakHere(L);
	return error(L);
}

int lua_resume_worker_54(lua_State* L, lua_State* from, int nargs, int* nresults)
{
	LPVOID lp;
	LhBarrierGetCallback(&lp);
	const auto luaResume = (_lua_resume_54)lp;
	EmmyFacade::Get().Attach(L);
	return luaResume(L, from, nargs, nresults);
}

int lua_resume_worker_53_52(lua_State* L, lua_State* from, int nargs)
{
	LPVOID lp;
	LhBarrierGetCallback(&lp);
	const auto luaResume = (_lua_resume_53_52)lp;
	EmmyFacade::Get().Attach(L);
	return luaResume(L, from, nargs);
}

int lua_resume_worker_51(lua_State* L, int nargs)
{
	LPVOID lp;
	LhBarrierGetCallback(&lp);
	const auto luaResume = (_lua_resume_51)lp;
	EmmyFacade::Get().Attach(L);
	return luaResume(L, nargs);
}

#define HOOK(FN, WORKER, REQUIRED) {\
	const auto it = symbols.find(""#FN"");\
	if (it != symbols.end()) {\
		const auto ptr = (void*)it->second; \
		const auto hHook = new HOOK_TRACE_INFO(); \
		Hook(ptr, (void*)(WORKER), ptr, hHook); \
	} else if (REQUIRED) {\
		printf("[ERR]function %s not found.\n", ""#FN"");\
		return;\
	}\
}

#define EXIST_SYMBOL(FN) (symbols.find(""#FN"") != symbols.end())

void HookLuaFunctions(std::unordered_map<std::string, DWORD64>& symbols)
{
	if (symbols.empty())
		return;
	// lua 5.1
	HOOK(lua_pcall, lua_pcall_worker, false);
	// lua 5.2
	HOOK(lua_pcallk, lua_pcallk_worker, false);
	// HOOK(lua_error, lua_error_worker, true);

	// lua5.4
	if (EXIST_SYMBOL(lua_newuserdatauv)) 
	{
		HOOK(lua_resume, lua_resume_worker_54, false);
		EmmyFacade::Get().SendLog(LogType::Info, "lua_resume_worker_54");
	}
	else if(EXIST_SYMBOL(lua_rotate) || EXIST_SYMBOL(lua_callk)) //lua5.3 lua5.2
	{
		HOOK(lua_resume, lua_resume_worker_53_52, false);
		EmmyFacade::Get().SendLog(LogType::Info, "lua_resume_worker_53_52");
	}
	else // lua5.1 or luajit
	{
		HOOK(lua_resume, lua_resume_worker_51, false);
		if (EXIST_SYMBOL(lua_pcall)) {
			EmmyFacade::Get().SendLog(LogType::Info, "EXIST_SYMBOL lua_pcall");
		}
		if (EXIST_SYMBOL(lua_pcallk)) {
			EmmyFacade::Get().SendLog(LogType::Info, "EXIST_SYMBOL lua_pcallk");
		}
		EmmyFacade::Get().SendLog(LogType::Info, "lua_resume_worker_51");
	}
}

bool GetFileExists(const char* fileName)
{
	return GetFileAttributes(fileName) != INVALID_FILE_ATTRIBUTES;
}


void ReplaceExtension(char fileName[_MAX_PATH], const char* extension)
{

	char* start = strrchr(fileName, '.');

	if (start == NULL)
	{
		strcat(fileName, extension);
	}
	else
	{
		strcpy(start + 1, extension);
	}

}

void GetFileTitle(const char* fileName, char fileTitle[_MAX_PATH])
{

	const char* slash1 = strrchr(fileName, '\\');
	const char* slash2 = strrchr(fileName, '/');

	const char* pathEnd = max(slash1, slash2);

	if (pathEnd == NULL)
	{
		// There's no path so the whole thing is the file title.
		strcpy(fileTitle, fileName);
	}
	else
	{
		strcpy(fileTitle, pathEnd + 1);
	}

}

void GetFilePath(const char* fileName, char path[_MAX_PATH])
{

	const char* slash1 = strrchr(fileName, '\\');
	const char* slash2 = strrchr(fileName, '/');

	const char* pathEnd = max(slash1, slash2);

	if (pathEnd == NULL)
	{
		// There's no path on the file name.
		path[0] = 0;
	}
	else
	{
		size_t length = pathEnd - fileName + 1;
		memcpy(path, fileName, length);
		path[length] = 0;
	}

}
#if WIN32


bool LocateSymbolFile(const IMAGEHLP_MODULE64& moduleInfo, char fileName[_MAX_PATH])
{

	// The search order for symbol files is described here:
	// http://msdn2.microsoft.com/en-us/library/ms680689.aspx

	// This function doesn't currently support the full spec.

	const char* imageFileName = moduleInfo.LoadedImageName;

	// First check the absolute path specified in the CodeView data.
	if (GetFileExists(moduleInfo.CVData))
	{
		strncpy(fileName, moduleInfo.CVData, _MAX_PATH);
		return true;
	}

	char symbolTitle[_MAX_PATH];
	GetFileTitle(moduleInfo.CVData, symbolTitle);

	// Now check in the same directory as the image.

	char imagePath[_MAX_PATH];
	GetFilePath(imageFileName, imagePath);

	strcat(imagePath, symbolTitle);

	if (GetFileExists(imagePath))
	{
		strncpy(fileName, imagePath, _MAX_PATH);
		return true;
	}

	return false;

}

BOOL CALLBACK GatherSymbolsCallback(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext)
{

	std::unordered_map<std::string, DWORD64>* symbols = reinterpret_cast<std::unordered_map<std::string, DWORD64>*>(UserContext);

	if (pSymInfo != NULL && pSymInfo->Name != NULL)
	{
		EmmyFacade::Get().SendLog(LogType::Info, "\t[B]Lua symbol: %s %08X", pSymInfo->Name,pSymInfo->Address);
		symbols->insert(std::make_pair(pSymInfo->Name, pSymInfo->Address));
	}

	return TRUE;

}
#endif
static PIMAGE_NT_HEADERS PEHeaderFromHModule(HMODULE hModule)
{
	PIMAGE_NT_HEADERS pNTHeader = 0;

	__try
	{
		if (PIMAGE_DOS_HEADER(hModule)->e_magic != IMAGE_DOS_SIGNATURE)
			__leave;

		pNTHeader = PIMAGE_NT_HEADERS(PBYTE(hModule)
			+ PIMAGE_DOS_HEADER(hModule)->e_lfanew);

		if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
			pNTHeader = 0;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return pNTHeader;
}


bool GetModuleImports(HANDLE hProcess, HMODULE hModule, std::vector<std::string>& imports)
{

	PIMAGE_NT_HEADERS pExeNTHdr = PEHeaderFromHModule(hModule);

	if (!pExeNTHdr)
	{
		return false;
	}

	DWORD importRVA = pExeNTHdr->OptionalHeader.DataDirectory
		[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!importRVA)
	{
		return false;
	}

	// Convert imports RVA to a usable pointer
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = MAKE_PTR(PIMAGE_IMPORT_DESCRIPTOR,
		hModule, importRVA);

	// Iterate through each import descriptor, and redirect if appropriate
	while (pImportDesc->FirstThunk)
	{
		PSTR pszImportModuleName = MAKE_PTR(PSTR, hModule, pImportDesc->Name);
		imports.push_back(pszImportModuleName);
		pImportDesc++;  // Advance to next import descriptor
	}

	return true;
}
#if WIN32



BOOL CALLBACK FindSymbolsCallback(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext)
{
	bool* found = reinterpret_cast<bool*>(UserContext);
	*found = true;
	return FALSE;
}

bool ScanForSignature(DWORD64 start, DWORD64 length, const char* signature)
{

	unsigned int signatureLength = strlen(signature);

	for (DWORD64 i = start; i < start + length - signatureLength; ++i)
	{

		void* p = reinterpret_cast<void*>(i);

		// Check that we have read access to the data. For some reason under Windows
		// Vista part of the DLL is not accessible (possibly some sort of new delay
		// loading mechanism for DLLs?)
		if (IsBadReadPtr(reinterpret_cast<LPCSTR>(p), signatureLength))
		{
			break;
		}

		if (memcmp(p, signature, signatureLength) == 0)
		{
			return true;
		}

	}

	return false;

}
#endif
void LoadSymbolsRecursively(HANDLE hProcess, HMODULE hModule)
{
	char moduleName[_MAX_PATH];
	ZeroMemory(moduleName, _MAX_PATH);
	DWORD nameLen = GetModuleBaseName(hProcess, hModule, moduleName, _MAX_PATH);
	if (nameLen == 0 || loadedModules.find(moduleName) != loadedModules.end())
		return;
	
	if (!g_initializedDebugHelp)
	{
#if WIN32



		if (!SymInitialize_dll(hProcess, g_symbolsDirectory.c_str(), FALSE))
		{
			return;
		}
		g_initializedDebugHelp = true;
#endif // !WIN32
	}
	loadedModules.insert(moduleName);
	char modulePath[_MAX_PATH];
	// skip modules in c://WINDOWS
	{
		ZeroMemory(modulePath, _MAX_PATH);
		DWORD fileNameLen = GetModuleFileNameEx(hProcess, hModule, modulePath, _MAX_PATH);
		if (fileNameLen == 0)
			return;

		char windowsPath[MAX_PATH];
		if (SHGetFolderPath(nullptr, CSIDL_WINDOWS, nullptr, SHGFP_TYPE_CURRENT, windowsPath) == 0)
		{
			std::string module_path = modulePath;
			if (module_path.find(windowsPath) != std::string::npos)
			{
				return;
			}
		}
	}
	// skip emmy modules
	{
		static const char* emmyModules[] = {"emmy_hook.dll", "EasyHook.dll","dbghelp.dll"};
		std::string module_path = modulePath;
		for (const char* emmyModuleName : emmyModules)
		{
			if (strcmp(moduleName, emmyModuleName) == 0)
				return;
		}
	}

	EmmyFacade::Get().SendLog(LogType::Info, "analyze: %s", moduleName);
	char pdbFileName[_MAX_PATH];
	strcpy(pdbFileName, modulePath);
	ReplaceExtension(pdbFileName, "pdb");
	std::unordered_map<std::string, DWORD64> symbols;
	if (GetFileExists(pdbFileName)) {
		//return
#if WIN32
		MODULEINFO moduleInfo = { 0 };
		GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo));
		char moduleFileName[_MAX_PATH];
		GetModuleFileNameEx(hProcess, hModule, moduleFileName, _MAX_PATH);
		EmmyFacade::Get().SendLog(LogType::Info, "modulePath analyze: %s", moduleFileName);
		//return;
		DWORD64 base = SymLoadModule64_dll(hProcess, nullptr, moduleFileName, moduleName, (DWORD64)moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage);
		IMAGEHLP_MODULE64 module;
		memset(&module, 0, sizeof(module));
		module.SizeOfStruct = sizeof(module);
		EmmyFacade::Get().SendLog(LogType::Info, "modulePath analyze: %s", moduleInfo.SizeOfImage);
		//return;
		BOOL result = SymGetModuleInfo64_dll(hProcess, base, &module);
		if (result && module.SymType == SymNone) {
			SymUnloadModule64_dll(hProcess, base);
			base = SymLoadModule64_dll(hProcess, NULL, pdbFileName, moduleName, (DWORD64)moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage);

			if (base != 0)
			{
				result = SymGetModuleInfo64_dll(hProcess, base, &module);
			}
			else
			{
				result = FALSE;
			}
		}
		if (result)
		{
			if (g_warnedAboutPdb.find(modulePath) == g_warnedAboutPdb.end())
			{
				if (strlen(module.CVData) > 0 && (module.SymType == SymExport || module.SymType == SymNone))
				{
					char symbolFileName[_MAX_PATH];
					if (LocateSymbolFile(module, symbolFileName))
					{
						char message[1024];
						_snprintf(message, 1024, "Warning 1002: Symbol file '%s' located but it does not match module '%s'", symbolFileName, modulePath);
						EmmyFacade::Get().SendLog(LogType::Warning,message);
					}
					g_warnedAboutPdb.insert(modulePath);
				}
			}
		}
		if (base != 0)
		{
			SymEnumSymbols_dll(hProcess, base, "lua*", GatherSymbolsCallback, reinterpret_cast<PVOID>(&symbols));
		}
		if (g_warnedAboutLua.find(modulePath) == g_warnedAboutLua.end())
		{
			bool foundLuaFunctions = false;
			if (base != 0)
			{
				SymEnumSymbols_dll(hProcess, base, "lua_*", FindSymbolsCallback, &foundLuaFunctions);
			}
			if (!foundLuaFunctions)
			{
				bool luaFile = ScanForSignature((DWORD64)hModule, moduleInfo.SizeOfImage, "$Lua:");
				if (luaFile)
				{
					char message[1024];
					_snprintf(message, 1024, "Warning 1001: '%s' appears to contain Lua functions however no Lua functions could located with the symbolic information", modulePath);
					EmmyFacade::Get().SendLog(LogType::Warning, message);
				}
			}
			g_warnedAboutLua.insert(modulePath);
		}
		HookLuaFunctions(symbols);
		std::vector<std::string> imports;
		GetModuleImports(hProcess, hModule, imports);
		for (unsigned int i = 0; i < imports.size(); ++i)
		{
			HMODULE hImportModule = GetModuleHandle(imports[i].c_str());
			if (hImportModule != NULL)
			{
				LoadSymbolsRecursively(hProcess, hImportModule);
			}
		}
#endif
	}
	else {
		EmmyFacade::Get().SendLog(LogType::Info, "modulePath analyze: %s", modulePath);
	PE pe = {};
	PE_STATUS st = peOpenFile(&pe, modulePath);

	if (st == PE_SUCCESS)
		st = peParseExportTable(&pe, INT32_MAX);
	if (st == PE_SUCCESS && PE_HAS_TABLE(&pe, ExportTable))
	{
		PE_FOREACH_EXPORTED_SYMBOL(&pe, pSymbol)
		{
			if (PE_SYMBOL_HAS_NAME(pSymbol))
			{
				const char* name = pSymbol->Name;
				 if (name[0] == 'l' && name[1] == 'u' && name[2] == 'a')
				{
					auto addr = (uint64_t)hModule;
					addr += pSymbol->Address.VA - pe.qwBaseAddress;
					symbols[pSymbol->Name] = addr;
					
					EmmyFacade::Get().SendLog(LogType::Info, "\t[B]Lua symbol: %s", name);
				}
			}
		}
	}

	HookLuaFunctions(symbols);

	// imports
	if (st == PE_SUCCESS)
		st = peParseImportTable(&pe);
	if (st == PE_SUCCESS && PE_HAS_TABLE(&pe, ImportTable))
	{
		PE_FOREACH_IMPORTED_MODULE(&pe, pModule)
		{
			HMODULE hImportModule = GetModuleHandle(pModule->Name);
			LoadSymbolsRecursively(hProcess, hImportModule);
		}
	}
}
}

void PostLoadLibrary(HMODULE hModule)
{
	extern HINSTANCE g_hInstance;
	if (hModule == g_hInstance)
	{
		return;
	}

	HANDLE hProcess = GetCurrentProcess();
	if (!g_LoadDebugHelp) {
		EmmyFacade::Get().SendLog(LogType::Info, "LoadDebugHelp");
		extern HINSTANCE g_hInstance;
#if WIN32
		if (!LoadDebugHelp(g_hInstance))
		{
			EmmyFacade::Get().SendLog(LogType::Info, "LoadDebugHelp failed");
		}
		const char* symbolsDirectory = static_cast<const char*>("");
		g_symbolsDirectory = symbolsDirectory;
		g_symbolsDirectory += ";" + GetApplicationDirectory();
		g_symbolsDirectory += ";" + ::GetEnvironmentVariable1("_NT_SYMBOL_PATH");
		g_symbolsDirectory += ";" + ::GetEnvironmentVariable1("_NT_ALTERNATE_SYMBOL_PATH");
		EmmyFacade::Get().SendLog(LogType::Info, "FindAndHook %s", g_symbolsDirectory);
		g_LoadDebugHelp = true;
#endif

	}
	char moduleName[_MAX_PATH];
	GetModuleBaseName(hProcess, hModule, moduleName, _MAX_PATH);

	std::lock_guard<std::mutex> lock(mutexPostLoadModule);
	LoadSymbolsRecursively(hProcess, hModule);
}

HMODULE WINAPI LoadLibraryExW_intercept(LPCWSTR fileName, HANDLE hFile, DWORD dwFlags)
{
	
	// We have to call the loader lock (if it is available) so that we don't get deadlocks
	// in the case where Dll initialization acquires the loader lock and calls LoadLibrary
	// while another thread is inside PostLoadLibrary.
	HMODULE hModule = LoadLibraryExW_dll(fileName, hFile, dwFlags);

	if (hModule != nullptr)
	{
		PostLoadLibrary(hModule);
	}
	return hModule;
}

void HookLoadLibrary()
{
	HMODULE hModuleKernel = GetModuleHandle("KernelBase.dll");
	if (hModuleKernel == nullptr)
		hModuleKernel = GetModuleHandle("kernel32.dll");
	if (hModuleKernel != nullptr)
	{
		// LoadLibraryExW is called by the other LoadLibrary functions, so we
		// only need to hook it.

		// TODO hook!!!
		LoadLibraryExW_dll = (LoadLibraryExW_t)GetProcAddress(hModuleKernel, "LoadLibraryExW");

		// destroy these functions.
		const auto hHook = new HOOK_TRACE_INFO();
		ULONG ACLEntries[1] = {0};
		HOOK_STATUS status = LhInstallHook(
			(void*)LoadLibraryExW_dll,
			(void*)LoadLibraryExW_intercept,
			(PVOID)nullptr,
			hHook);
		assert(status == 0);
		status = LhSetExclusiveACL(ACLEntries, 0, hHook);
		assert(status == 0);
	}
}

void redirect(int port)
{
	HANDLE readStdPipe = NULL, writeStdPipe = NULL;

	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = nullptr;

	CreatePipe(&readStdPipe, &writeStdPipe, &saAttr, 0);

	const auto oldStdout = _dup(_fileno(stdout));
	const auto oldStderr = _dup(_fileno(stderr));

	if (oldStdout == -1 || oldStderr == -1)
	{
		printf("stdout or stderr redirect error");
		if (oldStdout != -1)
		{
			_close(oldStdout);
		}
		if (oldStderr != -1)
		{
			_close(oldStderr);
		}

		return;
	}

	const auto stream = _open_osfhandle(reinterpret_cast<long>(writeStdPipe), 0);
	FILE* capture = nullptr;
	if (stream == -1)
	{
		printf("capture stream open fail");
		_dup2(oldStdout, _fileno(stdout));
		_dup2(oldStderr, _fileno(stderr));

		_close(oldStdout);
		_close(oldStderr);

		return;
	}
	capture = _fdopen(stream, "wt");

	// stdout now refers to file "capture" 
	if (_dup2(_fileno(capture), _fileno(stdout)) == -1)
	{
		printf("Can't _dup2 stdout to capture");

		_dup2(oldStdout, _fileno(stdout));
		_dup2(oldStderr, _fileno(stderr));

		_close(oldStdout);
		_close(oldStderr);

		return;
	}

	// stderr now refers to file "capture" 
	if (_dup2(_fileno(capture), _fileno(stderr)) == -1)
	{
		printf("Can't _dup2 stderr to capture");

		_dup2(oldStdout, _fileno(stdout));
		_dup2(oldStderr, _fileno(stderr));

		_close(oldStdout);
		_close(oldStderr);

		return;
	}
	setvbuf(stdout, nullptr, _IONBF, 0);
	setvbuf(stderr, nullptr, _IONBF, 0);
	// 1024 - 65535
	while (port > 0xffff) port -= 0xffff;
	while (port < 0x400) port += 0x400;
	port++;

	const auto transport = std::make_shared<SocketServerTransporter>();
	std::string err;
	const auto suc = transport->Listen("localhost", port, err);

	if (!suc)
	{
		printf("capture log error : %s", err.c_str());

		_dup2(oldStdout, _fileno(stdout));
		_dup2(oldStderr, _fileno(stderr));

		_close(oldStdout);
		_close(oldStderr);

		return;
	}

	std::thread thread([transport,readStdPipe,oldStdout]()
	{
		char buf[1024] = {0};
		while (true)
		{
			DWORD readWord;
			ZeroMemory(buf, 1024);
			const bool suc = ReadFile(readStdPipe, buf, 1024, &readWord, nullptr);

			if (suc && readWord > 0)
			{
				_write(oldStdout, buf, readWord);
				transport->Send(buf, readWord);
			}
		}
	});
	thread.detach();
}

int StartupHookMode(void* lpParam)
{
	const int pid = (int)GetCurrentProcessId();
	EmmyFacade::Get().StartupHookMode(pid);

	if (lpParam != nullptr && ((RemoteThreadParam*)lpParam)->bRedirect)
	{
		redirect(pid);
	}

	return 0;
}

void FindAndHook()
{
	EmmyFacade::Get().SendLog(LogType::Info, "FindAndHook");
	/*if (!g_LoadDebugHelp) {
		EmmyFacade::Get().SendLog(LogType::Info, "LoadDebugHelp");
		extern HINSTANCE g_hInstance;
		if (!LoadDebugHelp(g_hInstance))
		{
			EmmyFacade::Get().SendLog(LogType::Info, "LoadDebugHelp failed");
		}
		const char* symbolsDirectory = static_cast<const char*>("");
		g_symbolsDirectory = symbolsDirectory;
		g_symbolsDirectory += ";" + GetApplicationDirectory();
		g_symbolsDirectory += ";" + ::GetEnvironmentVariable1("_NT_SYMBOL_PATH");
		g_symbolsDirectory += ";" + ::GetEnvironmentVariable1("_NT_ALTERNATE_SYMBOL_PATH");
		EmmyFacade::Get().SendLog(LogType::Info, "FindAndHook %s", g_symbolsDirectory);
		g_LoadDebugHelp = true;

	}*/
	HookLoadLibrary();

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
	if (hSnapshot)
	{
		MODULEENTRY32 module;
		module.dwSize = sizeof(MODULEENTRY32);
		BOOL moreModules = Module32First(hSnapshot, &module);
		while (moreModules)
		{
			PostLoadLibrary(module.hModule);
			moreModules = Module32Next(hSnapshot, &module);
		}
	}
	else
	{
		HMODULE module = GetModuleHandle(nullptr);
		PostLoadLibrary(module);
	}
	CloseHandle(hSnapshot);
}

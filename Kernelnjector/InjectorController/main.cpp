#include <main.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "[*] Usage: " << argv[0] << " <target pid>" << std::endl;
        return -1;
    }

    ULONG TargetPid;

    TargetPid = std::stoul(argv[1]);

    std::wcout << L"[*] sending injection request " << L" to driver for target process -> " << TargetPid << std::endl;

    INJECTION_INFO InjectionInfo;
    InjectionInfo.TargetPid = TargetPid;


    SendInjectionRequest(&InjectionInfo);

    return 0;
}
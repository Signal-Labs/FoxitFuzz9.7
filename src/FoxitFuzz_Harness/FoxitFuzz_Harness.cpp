/*
FoxitFuzz_Harness.cpp - simple console wrapper for ConvertToPDF_x86.dll.
Created by Christopher Vella (@Kharosx0).
Modified and updated from Richard Johnsons (@richinseattle / rjohnson@moflow.org) work on versions 9.0 and 7.3.4. Significant changes were made to update this for Foxit API version 9.7

NOTES:

Must install the foxit pdf printer globally
ConvertToPDF_x86.dll and FoxitReader.exe must be in path

afl-fuzz.exe -i %INPUT_DIR% -o foxit_out -D %DynamoRIO_ROOT%\bin32 -t 20000 -- -coverage_module ConvertToPDF_x86.dll -target_module FoxitFuzz_Harness.exe -target_method convert_to_pdf -nargs 2 -fuzz_iterations 5000  -- %CD%\FoxitFuzz_Harness.exe @@ c:\temp\junk1.pdf
*/

#include <Windows.h>
#include <String.h>
#include <iostream>
#include <DbgHelp.h>
using namespace std;


typedef void* (__stdcall* CreateFXPDFConvertor_t)();
typedef int(__thiscall* InitLocale_t)(void* _this, int, wchar_t* lc_str);
typedef int(__thiscall* InitPrinter_t)(void* _this, wchar_t* printer_name);
typedef int(__thiscall* InitPdfConverter_t)(void* _this, int mode, const wchar_t* lang);
typedef int(__thiscall* FoxitSDKMsgStart_t)(void* _this, int mode);
typedef void(__thiscall* Release_t)(void* _this);
typedef int(__thiscall* ConvertToPdf_t)(void* _this, wchar_t* convert_buf, int p2, int p3, int p4, int p5, int p6, int p7, int p8, int p9, int p10, int p11, int p12);


ULONG FoxitReader = NULL;

typedef struct ConverterFuncTable_t
{
    ConvertToPdf_t     ConvertToPdf;
    FoxitSDKMsgStart_t FoxitSDKMsgStart;
    InitPrinter_t      InitPrinter;
    InitPdfConverter_t InitPdfConverter;
    InitLocale_t       InitLocale;
    void* p5;
    void* p6;
    void* p7;
    void* p8;
    Release_t Release;

} ConverterFuncTable;


typedef struct ConverterClass_t
{
    ConverterFuncTable_t* vfp_table;
} ConverterClass;


const char* target_library = "ConvertToPDF_x86.dll";
const char* target_function = "CreateFXPDFConvertor";

wchar_t* printer_name = (wchar_t*)L"Foxit Reader PDF Printer";

ConverterClass* pdfconverter = NULL;


int init_target_library()
{
    int retVal = 0;

    CreateFXPDFConvertor_t CreateFXPDFConvertor = (CreateFXPDFConvertor_t)GetProcAddress(LoadLibraryA(target_library), target_function);

    // create an instance of CreateFXPDFConvertor
    pdfconverter = (ConverterClass*)CreateFXPDFConvertor();
    ConverterFuncTable* vfp_table = pdfconverter->vfp_table;

    cout << "Function table:   " << endl;
    cout << "CreateFXPDFConvertor: " << hex << CreateFXPDFConvertor << endl;
    cout << "InitPdfConverter:     " << hex << vfp_table->InitPdfConverter << "  CreateFXPDFConvertor+0x" << hex << (unsigned long)vfp_table->InitPdfConverter - (unsigned long)CreateFXPDFConvertor << endl;
    cout << "InitPrinter:          " << hex << vfp_table->InitPrinter << "  CreateFXPDFConvertor+0x" << hex << (unsigned long)vfp_table->InitPrinter - (unsigned long)CreateFXPDFConvertor << endl;
    cout << "ConvertToPdf:         " << hex << vfp_table->ConvertToPdf << "  CreateFXPDFConvertor+0x" << hex << (unsigned long)vfp_table->ConvertToPdf - (unsigned long)CreateFXPDFConvertor << endl << endl;



    // init converter 
    cout << "Calling InitPdfConverter\n";
    const wchar_t* lang = L"en-US";
    retVal = vfp_table->InitPdfConverter(pdfconverter, 2, lang);
    if (retVal)
        cout << "Error: InitPdfConverter(): " << retVal << endl;

    cout << "Calling FoxitSDKMsgStart\n";
    retVal = vfp_table->FoxitSDKMsgStart(pdfconverter, 2);
    if (retVal)
        cout << "Error: FoxitSDKMsgStart(): " << retVal << endl;


    // init printer device  
    cout << "Calling InitPrinter\n";
    retVal = vfp_table->InitPrinter(pdfconverter, printer_name);
    if (retVal)
        cout << "Error: InitPrinter(): " << retVal << endl;

    return retVal;
}

extern "C" __declspec(dllexport) int wmain(int argc, wchar_t* argv[]);
extern "C" __declspec(dllexport) int convert_to_pdf(ConvertToPdf_t convert, wchar_t* converter_buf);

int convert_to_pdf(ConvertToPdf_t convert, wchar_t* converter_buf)
{
    return convert(pdfconverter, converter_buf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}


void ParseIAT(HINSTANCE h)
{
    // Find the IAT size
    DWORD ulsize = 0;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(h, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulsize);
    if (!pImportDesc)
        return;

    // Loop names
    for (; pImportDesc->Name; pImportDesc++)
    {
        PSTR pszModName = (PSTR)((PBYTE)h + pImportDesc->Name);
        if (!pszModName)
            break;

        HINSTANCE hImportDLL = LoadLibraryA(pszModName);
        if (!hImportDLL)
        {
            // ... (error)
        }

        // Get caller's import address table (IAT) for the callee's functions
        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
            ((PBYTE)h + pImportDesc->FirstThunk);

        // Replace current function address with new function address
        for (; pThunk->u1.Function; pThunk++)
        {
            FARPROC pfnNew = 0;
            size_t rva = 0;
#ifdef _WIN64
            if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
#else
            if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
#endif
            {
                // Ordinal
#ifdef _WIN64
                size_t ord = IMAGE_ORDINAL64(pThunk->u1.Ordinal);
#else
                size_t ord = IMAGE_ORDINAL32(pThunk->u1.Ordinal);
#endif

                PROC* ppfn = (PROC*)&pThunk->u1.Function;
                if (!ppfn)
                {
                    // ... (error)
                }
                rva = (size_t)pThunk;

                char fe[100] = { 0 };
                sprintf_s(fe, 100, "#%u", ord);
                pfnNew = GetProcAddress(hImportDLL, (LPCSTR)ord);
                if (!pfnNew)
                {
                    // ... (error)
                }
            }
            else
            {
                // Get the address of the function address
                PROC* ppfn = (PROC*)&pThunk->u1.Function;
                if (!ppfn)
                {
                    // ... (error)
                }
                rva = (size_t)pThunk;
                PSTR fName = (PSTR)h;
                fName += pThunk->u1.Function;
                fName += 2;
                if (!fName)
                    break;
                pfnNew = GetProcAddress(hImportDLL, fName);
                if (!pfnNew)
                {
                    // ... (error)
                }
            }

            // Patch it now...
            auto hp = GetCurrentProcess();
            if (!WriteProcessMemory(hp, (LPVOID*)rva, &pfnNew, sizeof(pfnNew), NULL) && (ERROR_NOACCESS == GetLastError()))
            {
                DWORD dwOldProtect;
                if (VirtualProtect((LPVOID)rva, sizeof(pfnNew), PAGE_WRITECOPY, &dwOldProtect))
                {
                    if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID*)rva, &pfnNew, sizeof(pfnNew), NULL))
                    {
                        // ... (error)
                    }
                    if (!VirtualProtect((LPVOID)rva, sizeof(pfnNew), dwOldProtect, &dwOldProtect))
                    {
                        // ... (error)
                    }
                }
            }
        }
    }
}

int wmain(int argc, wchar_t* argv[])
{
    int retVal = 0;

    int converter_buf_count = 0;
    int converter_buf_size = 0;
    wchar_t* converter_buf = NULL;

    wchar_t* input_path = NULL;
    wchar_t* output_path = (wchar_t*)L"nul";

    cout << "foxit-fuzz (target v9.7) - @Kharos" << endl << endl;

    if (argc < 3)
    {
        wcout << "usage: " << argv[0] << " <input> <output>" << endl;
        return -1;
    }

    if (GetFileAttributesW(argv[1]) == -1)
    {
        cout << "error: input file path" << endl;
        return -1;
    }
    input_path = argv[1];
    output_path = argv[2];

    // setup buffer for converting PDF
    FoxitReader = (ULONG)LoadLibraryA("FoxitReader.exe");
    ParseIAT((HINSTANCE)FoxitReader);
    HANDLE heapId = GetProcessHeap();
    DWORD oldProtect;
    VirtualProtect((LPVOID)((ULONG)FoxitReader + (0x4726114)), sizeof(HANDLE), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((void*)((ULONG)FoxitReader + (0x4726114)), &heapId, sizeof(HANDLE));
    ULONG FoxitReaderOffset = FoxitReader + 0x036f5690;
    ULONG val2 = 0x0b;
    ULONG valEnd = 0x07;
    converter_buf_size = 0x1e50;
    converter_buf = (wchar_t*)calloc(1, converter_buf_size);
    printf("ConverterBuf:%p\n", converter_buf);
    cout << "Adding Foxit Offset\n";
    memcpy(converter_buf, &FoxitReaderOffset, sizeof(ULONG));
    cout << "Adding Foxit val2\n";
    memcpy(converter_buf + sizeof(ULONG) / 2, &val2, sizeof(ULONG));
    cout << "Applying converter_buf changes\n";
    const wchar_t* foxitVer = L"Foxit Reader Printer Version 9.7.1.2227";
    wcsncpy(converter_buf + (0xb68 / 2), foxitVer, wcslen(foxitVer));
    cout << "Applying input path\n";
    wcsncpy(converter_buf + (0x1624 / 2), input_path, wcslen(input_path));
    cout << "Applying output path\n";
    wcsncpy(converter_buf + (0x182c / 2), output_path, wcslen(output_path));
    cout << "Applying last valEnd\n";
    memcpy(converter_buf + (0x1e4c / 2), &valEnd, sizeof(ULONG));
    cout << "Calling initlibrary\n";
    // create pdfconverter class and initialize library 
    if (init_target_library())
    {
        cout << "Error intializing target library" << endl;
        return -1;
    }


    // execute wrapper for fuzzing
    cout << "Calling ConvertToPDF\n";
    retVal = convert_to_pdf(pdfconverter->vfp_table->ConvertToPdf, converter_buf);
    free(converter_buf);

    if (retVal)
    {
        cout << "Error: ConvertToPdf(): " << retVal << endl;
        return -1;
    }


    return 0;
}

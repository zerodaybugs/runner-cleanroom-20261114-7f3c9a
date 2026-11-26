#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objidl.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

typedef HRESULT (STDAPICALLTYPE *MetaDataGetDispenserFn)(REFCLSID, REFIID, LPVOID*);
typedef void (WINAPI *CreateSymReaderFn)(GUID*, void**);
typedef HRESULT (STDMETHODCALLTYPE *QI_fn)(void*, REFIID, void**);
typedef ULONG (STDMETHODCALLTYPE *Release_fn)(void*);
typedef HRESULT (STDMETHODCALLTYPE *OpenScope_fn)(void*, LPCWSTR, DWORD, REFIID, IUnknown**);
typedef HRESULT (STDMETHODCALLTYPE *ReaderInitialize_fn)(void*, IUnknown*, const WCHAR*, const WCHAR*, IStream*);
typedef HRESULT (STDMETHODCALLTYPE *ReaderGetDocuments_fn)(void*, ULONG, ULONG*, void**);
typedef HRESULT (STDMETHODCALLTYPE *ReaderGetUserEntryPoint_fn)(void*, ULONG*);
typedef HRESULT (STDMETHODCALLTYPE *DocGetURL_fn)(void*, ULONG, ULONG*, WCHAR*);
typedef HRESULT (STDMETHODCALLTYPE *DocFindClosestLine_fn)(void*, ULONG, ULONG*);
typedef HRESULT (STDMETHODCALLTYPE *DocHasEmbeddedSource_fn)(void*, BOOL*);
typdef HRESULT (STDMETHODCALLTYPE *DocGetSourceLength_fn)(void*, ULONG*);
typedef HRESULT (STDMETHODCALLTYPE *DocGetSourceRange_fn)(void*, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG*, BYTE*);
typedef HRESULT (STDMETHODCALLTYPE *Destroy_fn)(void*);

typedef HRESULT (STDMETHODCALLTYPE *ReaderGetMethodFromDocumentPosition_fn)(void*, void*, ULONG, ULONG, void**);
typedef HRESULT (STDMETHODCALLTYPE *ReaderGetMethodsFromDocumentPosition_fn)(void*, void*, ULONG, ULONG, ULONG, ULONG*, void**);
typedef HRESULT (STDMETHODCALLTYPE *MethodGetToken_fn)(void*, ULONG*);
typedef HRESULT (STDMETHODCALLTYPE *MethodGetSequencePointCount_fn)(void*, ULONG*);
typedef HRESULT (STDMETHODCALLTYPE *MethodGetSequencePoints_fn)(void*, ULONG, ULONG*, ULONG*, void**, ULONG*, ULONG*, ULONG*, ULONG*);

static const GUID CLSID_CorMetaDataDispenser_Local = {0xe5cb7a31,0x7512,0x11d2,{0x89,0xce,0x00,0x80,0xc7,0x92,0xe5,0xd8}};
static const GUID IID_IMetaDataDispenser_Local = {0x809c652e,0x7396,0x11d2,{0x97,0x71,0x00,0xa0,0xc9,0xb4,0xd5,0x0c}};
static const GUID IID_IMetaDataImport_Local = {0x7dac8207,0xd3ae,0x4c75,{0x9b,0x67,0x92,0x80,0x1a,0x49,0x7d,0x44}};
static const GUID CLSID_CorSymReader_SxS_Local = {0x0a3976c5,0x4529,0x4ef8,{0xb0,0xb0,0x42,0xee,0xd3,0x70,0x82,0xcd}};
static const GUID IID_ISymUnmanagedReader_Local = {0xb4ce6286,0x2a6b,0x3712,{0xa3,0xb7,0x1e,0xe1,0xda,0xd4,0x67,0xb5}};
static const GUID IID_ISymUnmanagedDispose_Local = {0x969708d2,0x05e5,0x4861,{0xa3,0xb0,0x96,0xe4,0x73,0xcd,0xf6,0x3f}};

static void** vt(void* obj) { return obj ? *(void***)obj : NULL; }
static HRESULT qi(void* obj, REFIID iid, void** out) { return ((QI_fn)vt(obj)[0])(obj, iid, out); }
static ULONG rel(void* obj) { return obj ? ((Release_fn)vt(obj)[2])(obj) : 0; }
static void phr(const wchar_t* name, HRESULT hr) { wprintf(L"%ls hr=0x%08lX\n", name, (unsigned long)hr); fflush(stdout); }



#ifdef _MSC_VER
#define THISCALL __thiscall
#define FASTCALL __fastcall
#else
#define THISCALL __attribute__((thiscall))
#define FASTCALL __attribute__((fastcall))
#endif

typedef unsigned char (THISCALL *GetLinesColumnsPrivateX86_fn)(void*, ULONG*, ULONG*, USHORT*, ULONG*, ULONG*, void*, void*);
static GetLinesColumnsPrivateX86_fn g_original_get_lines_columns_x86 = NULL;
static volatile LONG g_hook_hits_x86 = 0;

static int write_rel_jump_x86(BYTE* at, const void* target, SIZE_T overwrite)
{
    DWORD old = 0;
    if (!VirtualProtect(at, overwrite, PAGE_EXECUTE_READWRITE, &old)) return 0;
    at[0] = 0xE9;
    *(LONG*)(at + 1) = (LONG)((const BYTE*)target - (at + 5));
    for (SIZE_T i = 5; i < overwrite; i++) at[i] = 0x90;
    FlushInstructionCache(GetCurrentProcess(), at, overwrite);
    { DWORD ignored = 0; VirtualProtect(at, overwrite, old, &ignored); }
    return 1;
}

static unsigned char FASTCALL hooked_get_lines_columns_x86(
    void* self, void* unused_edx,
    ULONG* p1, ULONG* p2, USHORT* p3, ULONG* p4, ULONG* capacity, void* lines, void* columns)
{
    LONG hit = InterlockedIncrement(&g_hook_hits_x86);
    ULONG v1 = p1 ? *p1 : 0, v2 = p2 ? *p2 : 0, v4 = p4 ? *p4 : 0;
    USHORT v3 = p3 ? *p3 : 0;
    ULONG incoming = capacity ? *capacity : 0;
    (void)unused_edx;
    wprintf(L"HOOK_ENTER hit=%ld self=%p p1=%lu p2=%lu p3=%u p4=%lu capacity=%lu lines=%p columns=%p\n",
        hit, self, v1, v2, (unsigned)v3, v4, incoming, lines, columns);
    fflush(stdout);

    if (hit <= 256)
    {
        BYTE* lineBuf = (BYTE*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        BYTE* colBuf = (BYTE*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (lineBuf && colBuf)
        {
            SIZE_T lineChanged=0,lineFirst=(SIZE_T)-1,lineLast=0,colChanged=0,colFirst=(SIZE_T)-1,colLast=0;
            ULONG a1=v1,a2=v2,a4=v4,cap=1; USHORT a3=v3;
            unsigned char ok;
            memset(lineBuf, 0xA5, 4096); memset(colBuf, 0xA5, 4096);
            ok = g_original_get_lines_columns_x86(
                self, p1 ? &a1 : NULL, p2 ? &a2 : NULL, p3 ? &a3 : NULL,
                p4 ? &a4 : NULL, &cap, lineBuf, colBuf);
            for (SIZE_T i=8;i<1024;i++) if(lineBuf[i]!=0xA5){if(lineFirst==(SIZE_T)-1)lineFirst=i;lineLast=i;lineChanged++;}
            for (SIZE_T i=4;i<1024;i++) if(colBuf[i]!=0xA5){if(colFirst==(SIZE_T)-1)colFirst=i;colLast=i;colChanged++;}
            wprintf(L"HOOK_PROBE hit=%ld ok=%u reported=%lu line_oob_bytes=%llu line_first=%lld line_last=%llu col_oob_bytes=%llu col_first=%lld col_last=%llu\n",
                hit,(unsigned)ok,cap,(unsigned long long)lineChanged,
                lineFirst==(SIZE_T)-1?-1LL:(long long)lineFirst,(unsigned long long)lineLast,
                (unsigned long long)colChanged,colFirst==(SIZE_T)-1?-1LL:(long long)colFirst,(unsigned long long)colLast);
            fflush(stdout);
            if (lineBuf) VirtualFree(lineBuf,0,MEM_RELEASE);
            if (colBuf) VirtualFree(colBuf,0,MEM_RELEASE);
        }
    }
    return g_original_get_lines_columns_x86(self,p1,p2,p3,p4,capacity,lines,columns);
}

static int install_get_lines_columns_hook_x86(HMODULE module, ULONG_PTR rva)
{
    const SIZE_T stolen = 6; /* push ebp; mov ebp,esp; sub esp,0x18 */
    BYTE* target = (BYTE*)module + rva;
    BYTE* trampoline = (BYTE*)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(!trampoline){wprintf(L"HOOK_ALLOC_FAILED gle=%lu\n",GetLastError());return 0;}
    memcpy(trampoline,target,stolen);
    if (!write_rel_jump_x86(trampoline+stolen,target+stolen,5)) return 0;
    g_original_get_lines_columns_x86=(GetLinesColumnsPrivateX86_fn)trampoline;
    if (!write_rel_jump_x86(target,hooked_get_lines_columns_x86,stolen)) return 0;
    wprintf(L"HOOK_INSTALLED module=%p rva=0x%lX target=%p trampoline=%p\n",module,(unsigned long)rva,target,trampoline);
    fflush(stdout);
    return 1;
}

static void dirname_w(const wchar_t* path, wchar_t* out, size_t cap)
{
    wcsncpy(out, path, cap - 1); out[cap - 1] = 0;
    wchar_t* a = wcsrchr(out, L'\\'); wchar_t* b = wcsrchr(out, L'/'); wchar_t* p = a > b ? a : b;
    if (p) *p = 0; else wcscpy(out, L".");
}


static int check_u32_guard(const wchar_t* name, ULONG* p, ULONG expected)
{
    if (p[1] != expected) { wprintf(L"CANARY_CORRUPTION %ls expected=0x%08lX actual=0x%08lX\\n", name, expected, p[1]); fflush(stdout); return 1; }
    return 0;
}
static int check_ptr_guard(const wchar_t* name, void** p, void* expected)
{
    if (p[1] != expected) { wprintf(L"CANARY_CORRUPTION %ls expected=%p actual=%p\\n", name, expected, p[1]); fflush(stdout); return 1; }
    return 0;
}
static int exercise_method(void* method, ULONG docIndex)
{
    HRESULT hr; ULONG token=0, count=0;
    hr=((MethodGetToken_fn)vt(method)[3])(method,&token);
    wprintf(L"DOC[%lu].METHOD token_hr=0x%08lX token=0x%08l\\n",docIndex,(unsigned long)hr,token);
    hr=((MethodGetSequencePointCount_fn)vt(method)[4])(method,&count);
    wprintf(L"DOC[%lu].SP_COUNT hr=0x%08lX count=%lu\\n",docIndex,(unsigned long)hr,count);
    if(FAILED(hr)||count>1000000)return 0;
    const ULONG C=0xC0DEC0DE; void* const P=(void*)(ULONG_PTR)0x33334444UL;
    ULONG offsets[2]={0,C}, sl[2]={0,C}, sc[2]={0,C}, el[2]={0,C}, ec[2]={0,C}, void* spdocs[2]={NULL,P}; ULONG fetched=0;
    hr=((MethodGetSequencePoints_fn)vt(method)[12])(method,1,&fetched,offsets,spdocs,sl,sc,el,ec);
    wprintf(L"DOC[%lu].SP_ONE hr=0x%08lX fetched=%lu values=%lu,%lu,%lu,%lu,%lu doc=%p\\n",docIndex,(unsigned long)hr,fetched,offsets[0],sl[0],sc[0],el[0],ec[0],spdocs[0]);
    int bad=0; bad|=check_u32_guard(L"offsets",offsets,C); bad|=check_ptr_guard(L"documents",spdocs,P); bad|=check_u32_guard(L"startLines",sl,C); bad|=check_u32_guard(L"startColumns",sc,C); bad|=check_u32_guard(L"endLines",el,C); bad|=check_u32_guard(L"endColumns",ec,C);
    if(bad)return 99;
    if(count>0 && count<1000000){
      ULONG* o=(ULONG*)calloc(count,sizeof(ULONG)); ULONG* a=(ULONG*)calloc(count,sizeof(ULONG)); ULONG* b=(ULONG*)calloc(count,sizeof(ULONG)); ULONG* c=(ULONG*)calloc(count,sizeof(ULONG)); ULONG* d=(ULONG*)calloc(count,sizeof(ULONG)); void** ds=(void**)calloc(count,sizeof(void*)); ULONG all=0;
      hr=((MethodGetSequencePoints_fn)vt(method)[12])(method,count,&all,o,ds,a,b,c,d);
      wprintf(L"DOC[%lu].SP_ALL hr=0x%08lX fetched=%lu requested=%lu\\\n",docIndex,(unsigned long)hr,all,count);
      for(ULONG i=0;i<all&&i<count;i++) if(ds[i]) rel(ds[i]);
      free(o);free(a);free(b);free(c);free(d);free(ds);
    }
    if(spdocs[0]) rel(spdocs[0]);
    return 0;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 5) { fwprintf(stderr, L"usage: raw_harness.exe coreclr.dll reader.dll assembly.dll symbols.pdb [deep]\n"); return 2; }
    const int deep = argc > 5;
    wprintf(L"RAW_HARNESS_BEGIN\nCORECLR=%ls\nREADER=%ls\nASSEMBLY=%ls\nPDB=%ls\nDEEP=%d\n", argv[1],argv[2],argv[3],argv[4],deep); fflush(stdout);

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED); phr(L"CoInitializeEx", hr);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return 3;

    wchar_t dir[MAX_PATH * 4]; dirname_w(argv[1], dir, sizeof(dir)/sizeof(dir[0])); SetDllDirectoryW(dir);
    HMODULE core = LoadLibraryW(argv[1]);
    if (!core) { wprintf(L"LOAD_CORECLR_FAILED gle=%lu\n",GetLastError()); return 4; }
    wprintf(L"LOAD_CORECLR_OK base=%p\n",core); fflush(stdout);
    MetaDataGetDispenserFn getDisp=(MetaDataGetDispenserFn)GetProcAddress(core,"MetaDataGetDispenser");
    if (!getDisp) { wprintf(L"GET_METADATA_EXPORT_FAILED gle=%lu\n",GetLastError()); return 5; }

    void* dispenser=NULL;
    hr=getDisp(&CLSID_CorMetaDataDispenser_Local,&IID_IMetaDataDispenser_Local,&dispenser); phr(L"MetaDataGetDispenser",hr);
    if (FAILED(hr)||!dispenser) return 6;
    IUnknown* importer=NULL;
    hr=((OpenScope_fn)vt(dispenser)[4])(dispenser,argv[3],0,&IID_IMetaDataImport_Local,&importer); phr(L"OpenScope",hr);
    if (FAILED(hr)||!importer) return 7;

    IStream* stream=NULL;
    hr=SHCreateStreamOnFileEx(argv[4],STGM_READ|STGM_SHARE_DENY_WRITE,FILE_ATTRIBUTE_NORMAL,FALSE,NULL,&stream); phr(L"SHCreateStreamOnFileEx",hr);
    if (FAILED(hr)||!stream) return 8;

    dirname_w(argv[2],dir,sizeof(dir)/sizeof(dir[0])); SetDllDirectoryW(dir);
    HMODULE readerMod=LoadLibraryW(argv[2]);
    if (!readerMod) { wprintf(L"LOAD_READER_FAILED gle=%lu\n",GetLastError()); return 9; }
    wprintf(L"LOAD_READER_OK base=%p\n",readerMod); fflush(stdout);
    if(argc>6){ ULONG_PTR hookRva=(ULONG_PTR)wcstoul(argv[6],NULL,0); if(hookRva && !install_get_lines_columns_hook_x86(readerMod,hookRva)) return 15; }
    CreateSymReaderFn create=(CreateSymReaderFn)GetProcAddress(readerMod,"CreateSymReader");
    if (!create) { wprintf(L"GET_CREATE_READER_FAILED gle=%lu\n",GetLastError()); return 10; }

    void* raw=NULL; GUID clsid=CLSID_CorSymReader_SxS_Local; create(&clsid,&raw);
    wprintf(L"CREATE_SYM_READER raw=%p\n",raw); fflush(stdout); if(!raw)return 11;
    void* sym=NULL; hr=qi(raw,&IID_ISymUnmanagedReader_Local,&sym); phr(L"QI.Reader",hr); rel(raw);
    if(FAILED(hr)||!sym)return 12;

    hr=((ReaderInitialize_fn)vt(sym)[13])(sym,importer,NULL,NULL,stream); phr(L"Reader.Initialize",hr);
    if(FAILED(hr))return 13;

    ULONG count=0; hr=((ReaderGetDocuments_fn)vt(sym)[4])(sym,0,&count,NULL); phr(L"GetDocuments.count",hr);
    wprintf(L"DOCUMENT_COUNT=%lu\n",count); fflush(stdout); if(FAILED(hr)||count>1000000)return 14;
    void** docs=count?(void**)calloc(count,sizeof(void*)):NULL; ULONG fetched=0;
    hr=((ReaderGetDocuments_fn)vt(sym)[4])(sym,count,&fetched,docs); phr(L"GetDocuments.data",hr);
    wprintf(L"DOCUMENT_FETCHED=%lu\n",fetched); fflush(stdout);

    ULONG n=fetched<count?fetched:count;
    for(ULONG i=0;i<n;i++)
    {
        void* doc=docs[i]; if(!doc)continue;
        ULONG cch=0; hr=((DocGetURL_fn)vt(doc)[3])(doc,0,&cch,NULL);
        wprintf(L"DOC[%lu].URL_COUNT hr=0x%08lX count=%lu\n",i,(unsigned long)hr,cch);
        WCHAR* url=(WCHAR*)calloc(cch?cch:1,sizeof(WCHAR)); ULONG got=0;
        hr=((DocGetURL_fn)vt(doc)[3])(doc,cch,&got,url);
        wprintf(L"DOC[%lu].URL hr=0x%08lX fetched=%lu value=%ls\n",i,(unsigned long)hr,got,url);
        BOOL emb=FALSE; hr=((DocHasEmbeddedSource_fn)vt(doc)[10])(doc,&emb);
        wprintf(L"DOC[%lu].EMBEDDED hr=0x%08lX value=%d\n",i,(unsigned long)hr,emb?1:0);
        ULONG slen=0; hr=((DocGetSourceLength_fn)vt(doc)[11])(doc,&slen);
        wprintf(L"DOC[%lu].SOURCE_LENGTH hr=0x%08lX value=%lu\n",i,(unsigned long)hr,slen);
        ULONG closest=0; hr=((DocFindClosestLine_fn)vt(doc)[9])(doc,1,&closest);
        wprintf(L"DOC[%lu].CLOSEST_LINE hr=0x%08lX value=%lu\n",i,(unsigned long)hr,closest);
        if(deep&&emb&&slen&&slen<64*1024*1024){ BYTE* src=(BYTE*)malloc(slen); ULONG sg=0; hr=((DocGetSourceRange_fn)vt(doc)[12])(doc,0,0,0x7fffffff,0x7fffffff,slen,&sg,src); wprintf(L"DOC[%lu].SOURCE_RANGE hr=0x%08lX fetched=%lu\n",i,(unsigned long)hr,sg); free(src); }
        if(deep){
          void* method=NULL; hr=((ReaderGetMethodFromDocumentPosition_fn)vt(sym)[10])(sym,doc,closest,0,&method);
          wprintf(L"DOC[%lu].METHOD_FROM_POS hr=0x%08lX method=%p\n",i,(unsigned long)hr,method);
          if(SUCCEEDED(hr)&&method){ int er=exercise_method(method,i); rel(method); if(er==99)return 99; }
          void* oneMethods[2]={NULL,(void*)(ULONG_PTR)0x77778888UL}; ULONG methodFetched=0;
          hr=((ReaderGetMethodsFromDocumentPosition_fn)vt(sym)[17])(sym,doc,closest,0,1,&methodFetched,oneMethods);
          wprintf(L"DOC[%lu].METHODS_ONE hr=0x%08lX fetched=%lu first=%p guard=%p\n",i,(unsigned long)hr,methodFetched,oneMethods[0],oneMethods[1]);
          if(oneMethods[1]!=(void*)(ULONG_PTR)0x77778888UL){wprintf(L"CANARY_CORRUPTION methods\n");return 99;}
          if(oneMethods[0])rel(oneMethods[0]);
        }
        free(url); rel(doc);
    }
    free(docs);

    ULONG entry=0; hr=((ReaderGetUserEntryPoint_fn)vt(sym)[5])(sym,&entry); wprintf(L"ENTRY_POINT hr=0x%08lX token=0x%08lX\n",(unsigned long)hr,entry);
    void* dispObj=NULL; hr=qi(sym,&IID_ISymUnmanagedDispose_Local,&dispObj); phr(L"QI.Dispose",hr);
    if(SUCCEEDED(hr)&&dispObj){ hr=((Destroy_fn)vt(dispObj)[3])(dispObj); phr(L"Destroy",hr); rel(dispObj); }

    rel(sym); stream->lpVtbl->Release(stream); importer->lpVtbl->Release(importer); rel(dispenser);
    FreeLibrary(readerMod); FreeLibrary(core); CoUninitialize();
    wprintf(L"RAW_HARNESS_PASS\n"); fflush(stdout); return 0;
}

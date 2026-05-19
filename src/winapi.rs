use crate::strings::import_categories;

#[derive(Clone)]
pub struct ApiClassification {
    pub tier: String,
    pub family: String,
    pub semantic_relevance: String,
    pub noise_reason: Option<String>,
    pub normalized_symbol: String,
}

#[derive(Clone)]
pub struct ApiArg {
    pub index: usize,
    pub register: &'static str,
    pub name: &'static str,
}

#[derive(Clone)]
pub struct ApiMetadata {
    pub categories: Vec<String>,
    pub args: Vec<ApiArg>,
}

pub struct WinApiPrototype {
    pub return_type: &'static str,
    pub args: &'static [&'static str],
}

pub fn metadata(symbol: &str) -> ApiMetadata {
    let name = symbol
        .rsplit('!')
        .next()
        .unwrap_or(symbol)
        .to_ascii_lowercase();
    let args = match_api_args(&name);
    ApiMetadata {
        categories: import_categories(symbol),
        args,
    }
}

pub fn classify_api(symbol: &str) -> ApiClassification {
    let dll = symbol
        .split_once('!')
        .map(|(dll, _)| dll)
        .unwrap_or("")
        .to_ascii_lowercase();
    let name = symbol
        .rsplit('!')
        .next()
        .unwrap_or(symbol)
        .to_ascii_lowercase();
    let categories = import_categories(symbol);
    let family = if let Some(category) = categories.first() {
        category.clone()
    } else {
        runtime_family(&dll, &name).unwrap_or_else(|| "unknown".to_string())
    };
    let os_api = is_os_api_dll(&dll) || !categories.is_empty();
    let runtime_api = !os_api && runtime_family(&dll, &name).is_some();
    let tier = if os_api {
        "os_api"
    } else if runtime_api {
        "runtime_api"
    } else {
        "internal_api"
    }
    .to_string();
    let semantic_relevance = match tier.as_str() {
        "os_api" if malware_relevant_family(&family) => "high",
        "os_api" => "medium",
        "internal_api" => "medium",
        _ => "low",
    }
    .to_string();
    let noise_reason = (tier == "runtime_api").then(|| format!("runtime_library:{family}"));
    ApiClassification {
        tier,
        family,
        semantic_relevance,
        noise_reason,
        normalized_symbol: normalize_symbol(symbol),
    }
}

pub fn prototype(symbol: &str) -> Option<WinApiPrototype> {
    let name = symbol
        .rsplit('!')
        .next()
        .unwrap_or(symbol)
        .to_ascii_lowercase();
    let proto = match name.as_str() {
        "createfilew" => WinApiPrototype {
            return_type: "HANDLE",
            args: &["LPCWSTR", "DWORD", "DWORD", "LPSECURITY_ATTRIBUTES"],
        },
        "createfilea" => WinApiPrototype {
            return_type: "HANDLE",
            args: &["LPCSTR", "DWORD", "DWORD", "LPSECURITY_ATTRIBUTES"],
        },
        "readfile" | "writefile" | "deviceiocontrol" => WinApiPrototype {
            return_type: "BOOL",
            args: &["HANDLE", "LPVOID", "DWORD", "LPDWORD"],
        },
        "closehandle" => WinApiPrototype {
            return_type: "BOOL",
            args: &["HANDLE"],
        },
        "createprocessw" => WinApiPrototype {
            return_type: "BOOL",
            args: &[
                "LPCWSTR",
                "LPWSTR",
                "LPSECURITY_ATTRIBUTES",
                "LPSECURITY_ATTRIBUTES",
            ],
        },
        "createprocessa" => WinApiPrototype {
            return_type: "BOOL",
            args: &[
                "LPCSTR",
                "LPSTR",
                "LPSECURITY_ATTRIBUTES",
                "LPSECURITY_ATTRIBUTES",
            ],
        },
        "regopenkeyexw" | "regcreatekeyexw" => WinApiPrototype {
            return_type: "LSTATUS",
            args: &["HKEY", "LPCWSTR", "DWORD", "REGSAM"],
        },
        "regopenkeyexa" | "regcreatekeyexa" => WinApiPrototype {
            return_type: "LSTATUS",
            args: &["HKEY", "LPCSTR", "DWORD", "REGSAM"],
        },
        "regqueryvalueexw" => WinApiPrototype {
            return_type: "LSTATUS",
            args: &["HKEY", "LPCWSTR", "LPDWORD", "LPDWORD"],
        },
        "regqueryvalueexa" => WinApiPrototype {
            return_type: "LSTATUS",
            args: &["HKEY", "LPCSTR", "LPDWORD", "LPDWORD"],
        },
        "regsetvalueexw" => WinApiPrototype {
            return_type: "LSTATUS",
            args: &["HKEY", "LPCWSTR", "DWORD", "DWORD"],
        },
        "regsetvalueexa" => WinApiPrototype {
            return_type: "LSTATUS",
            args: &["HKEY", "LPCSTR", "DWORD", "DWORD"],
        },
        "virtualalloc" => WinApiPrototype {
            return_type: "LPVOID",
            args: &["LPVOID", "SIZE_T", "DWORD", "DWORD"],
        },
        "virtualallocex" => WinApiPrototype {
            return_type: "LPVOID",
            args: &["HANDLE", "LPVOID", "SIZE_T", "DWORD"],
        },
        "virtualprotect" => WinApiPrototype {
            return_type: "BOOL",
            args: &["LPVOID", "SIZE_T", "DWORD", "LPDWORD"],
        },
        "virtualprotectex" => WinApiPrototype {
            return_type: "BOOL",
            args: &["HANDLE", "LPVOID", "SIZE_T", "DWORD"],
        },
        "writeprocessmemory" => WinApiPrototype {
            return_type: "BOOL",
            args: &["HANDLE", "LPVOID", "LPCVOID", "SIZE_T"],
        },
        "readprocessmemory" => WinApiPrototype {
            return_type: "BOOL",
            args: &["HANDLE", "LPCVOID", "LPVOID", "SIZE_T"],
        },
        "openprocess" => WinApiPrototype {
            return_type: "HANDLE",
            args: &["DWORD", "BOOL", "DWORD"],
        },
        "createremotethread" | "createremotethreadex" => WinApiPrototype {
            return_type: "HANDLE",
            args: &[
                "HANDLE",
                "LPSECURITY_ATTRIBUTES",
                "SIZE_T",
                "LPTHREAD_START_ROUTINE",
            ],
        },
        "loadlibraryw" => WinApiPrototype {
            return_type: "HMODULE",
            args: &["LPCWSTR"],
        },
        "loadlibrarya" => WinApiPrototype {
            return_type: "HMODULE",
            args: &["LPCSTR"],
        },
        "getprocaddress" => WinApiPrototype {
            return_type: "FARPROC",
            args: &["HMODULE", "LPCSTR"],
        },
        "ldrloadll" => WinApiPrototype {
            return_type: "NTSTATUS",
            args: &["PWSTR", "PULONG", "PUNICODE_STRING", "PHANDLE"],
        },
        "ldrgetprocedureaddress" => WinApiPrototype {
            return_type: "NTSTATUS",
            args: &["HMODULE", "PANSI_STRING", "WORD", "PVOID"],
        },
        "ntqueryinformationprocess" => WinApiPrototype {
            return_type: "NTSTATUS",
            args: &["HANDLE", "PROCESSINFOCLASS", "PVOID", "ULONG"],
        },
        "ntmapviewofsection" => WinApiPrototype {
            return_type: "NTSTATUS",
            args: &["HANDLE", "HANDLE", "PVOID", "ULONG_PTR"],
        },
        "ntunmapviewofsection" => WinApiPrototype {
            return_type: "NTSTATUS",
            args: &["HANDLE", "PVOID"],
        },
        "ntprotectvirtualmemory" => WinApiPrototype {
            return_type: "NTSTATUS",
            args: &["HANDLE", "PVOID", "PSIZE_T", "ULONG"],
        },
        "ntallocatevirtualmemory" => WinApiPrototype {
            return_type: "NTSTATUS",
            args: &["HANDLE", "PVOID", "ULONG_PTR", "PSIZE_T"],
        },
        "ntwritevirtualmemory" | "ntreadvirtualmemory" => WinApiPrototype {
            return_type: "NTSTATUS",
            args: &["HANDLE", "PVOID", "PVOID", "SIZE_T"],
        },
        "ntcreatethreadex" => WinApiPrototype {
            return_type: "NTSTATUS",
            args: &["PHANDLE", "ACCESS_MASK", "PVOID", "HANDLE"],
        },
        "rtldecompressbuffer" => WinApiPrototype {
            return_type: "NTSTATUS",
            args: &["USHORT", "PUCHAR", "ULONG", "PUCHAR"],
        },
        "rtlcreateuserthread" => WinApiPrototype {
            return_type: "NTSTATUS",
            args: &["HANDLE", "PSECURITY_DESCRIPTOR", "BOOLEAN", "ULONG"],
        },
        "isdebuggerpresent" => WinApiPrototype {
            return_type: "BOOL",
            args: &[],
        },
        "checkremotedebuggerpresent" => WinApiPrototype {
            return_type: "BOOL",
            args: &["HANDLE", "PBOOL"],
        },
        "winhttpsendrequest" => WinApiPrototype {
            return_type: "BOOL",
            args: &["HINTERNET", "LPCWSTR", "DWORD", "LPVOID"],
        },
        "winhttpopen" => WinApiPrototype {
            return_type: "HINTERNET",
            args: &["LPCWSTR", "DWORD", "LPCWSTR", "LPCWSTR"],
        },
        "winhttpconnect" => WinApiPrototype {
            return_type: "HINTERNET",
            args: &["HINTERNET", "LPCWSTR", "INTERNET_PORT"],
        },
        "internetopenw" | "internetopena" => WinApiPrototype {
            return_type: "HINTERNET",
            args: &["LPCTSTR", "DWORD", "LPCTSTR", "LPCTSTR"],
        },
        "internetconnectw" | "internetconnecta" => WinApiPrototype {
            return_type: "HINTERNET",
            args: &["HINTERNET", "LPCTSTR", "INTERNET_PORT"],
        },
        "internetreadfile" | "internetwritefile" => WinApiPrototype {
            return_type: "BOOL",
            args: &["HINTERNET", "LPVOID", "DWORD", "LPDWORD"],
        },
        "httpsendrequestw" | "httpsendrequesta" => WinApiPrototype {
            return_type: "BOOL",
            args: &["HINTERNET", "LPCTSTR", "DWORD", "LPVOID"],
        },
        "connect" => WinApiPrototype {
            return_type: "INT",
            args: &["SOCKET", "SOCKADDR_PTR", "INT"],
        },
        "wsaconnect" => WinApiPrototype {
            return_type: "INT",
            args: &["SOCKET", "SOCKADDR_PTR", "INT", "LPWSABUF"],
        },
        "socket" => WinApiPrototype {
            return_type: "SOCKET",
            args: &["INT", "INT", "INT"],
        },
        "send" | "recv" => WinApiPrototype {
            return_type: "INT",
            args: &["SOCKET", "CHAR_PTR", "INT", "INT"],
        },
        "bcryptencrypt" => WinApiPrototype {
            return_type: "NTSTATUS",
            args: &["BCRYPT_KEY_HANDLE", "PUCHAR", "ULONG", "PVOID"],
        },
        "bcryptdecrypt" => WinApiPrototype {
            return_type: "NTSTATUS",
            args: &["BCRYPT_KEY_HANDLE", "PUCHAR", "ULONG", "PVOID"],
        },
        "bcryptgenrandom" => WinApiPrototype {
            return_type: "NTSTATUS",
            args: &["BCRYPT_ALG_HANDLE", "PUCHAR", "ULONG", "ULONG"],
        },
        "cryptencrypt" | "cryptdecrypt" => WinApiPrototype {
            return_type: "BOOL",
            args: &["HCRYPTKEY", "HCRYPTHASH", "BOOL", "DWORD"],
        },
        "crypthashdata" => WinApiPrototype {
            return_type: "BOOL",
            args: &["HCRYPTHASH", "BYTE_PTR", "DWORD", "DWORD"],
        },
        "cryptdecodeobjectex" => WinApiPrototype {
            return_type: "BOOL",
            args: &["DWORD", "LPCSTR", "BYTE_PTR", "DWORD"],
        },
        "createfilemappingw" | "createfilemappinga" => WinApiPrototype {
            return_type: "HANDLE",
            args: &["HANDLE", "LPSECURITY_ATTRIBUTES", "DWORD", "DWORD"],
        },
        "mapviewoffile" => WinApiPrototype {
            return_type: "LPVOID",
            args: &["HANDLE", "DWORD", "DWORD", "DWORD"],
        },
        "createtoolhelp32snapshot" => WinApiPrototype {
            return_type: "HANDLE",
            args: &["DWORD", "DWORD"],
        },
        "createservicew" => WinApiPrototype {
            return_type: "SC_HANDLE",
            args: &["SC_HANDLE", "LPCWSTR", "LPCWSTR", "DWORD"],
        },
        "createservicea" => WinApiPrototype {
            return_type: "SC_HANDLE",
            args: &["SC_HANDLE", "LPCSTR", "LPCSTR", "DWORD"],
        },
        "openscmanagerw" | "openscmanagera" => WinApiPrototype {
            return_type: "SC_HANDLE",
            args: &["LPCTSTR", "LPCTSTR", "DWORD"],
        },
        "startservicew" | "startservicea" => WinApiPrototype {
            return_type: "BOOL",
            args: &["SC_HANDLE", "DWORD", "LPCWSTR_PTR"],
        },
        "controlservice" | "deleteservice" => WinApiPrototype {
            return_type: "BOOL",
            args: &["SC_HANDLE"],
        },
        "shellexecutew" => WinApiPrototype {
            return_type: "HINSTANCE",
            args: &["HWND", "LPCWSTR", "LPCWSTR", "LPCWSTR"],
        },
        "shellexecutea" => WinApiPrototype {
            return_type: "HINSTANCE",
            args: &["HWND", "LPCSTR", "LPCSTR", "LPCSTR"],
        },
        "coinitializeex" => WinApiPrototype {
            return_type: "HRESULT",
            args: &["LPVOID", "DWORD"],
        },
        "coinitializesecurity" => WinApiPrototype {
            return_type: "HRESULT",
            args: &[
                "PSECURITY_DESCRIPTOR",
                "LONG",
                "SOLE_AUTHENTICATION_SERVICE_PTR",
                "PVOID",
            ],
        },
        "cocreateinstance" => WinApiPrototype {
            return_type: "HRESULT",
            args: &["REFCLSID", "LPUNKNOWN", "DWORD", "REFIID"],
        },
        "cogetclassobject" => WinApiPrototype {
            return_type: "HRESULT",
            args: &["REFCLSID", "DWORD", "LPVOID", "REFIID"],
        },
        "cosetproxyblanket" => WinApiPrototype {
            return_type: "HRESULT",
            args: &["IUnknown", "DWORD", "DWORD", "OLECHAR_PTR"],
        },
        _ => return None,
    };
    Some(proto)
}

#[cfg(test)]
pub fn argument_name(symbol: &str, index: usize) -> String {
    metadata(symbol)
        .args
        .into_iter()
        .find(|arg| arg.index == index)
        .map(|arg| arg.name.to_string())
        .unwrap_or_else(|| format!("arg{}", index))
}

fn match_api_args(name: &str) -> Vec<ApiArg> {
    if name.contains("createfile") {
        return vec![
            arg(0, "rcx", "lpFileName"),
            arg(1, "rdx", "dwDesiredAccess"),
            arg(2, "r8", "dwShareMode"),
            arg(3, "r9", "lpSecurityAttributes"),
        ];
    }
    if name.contains("regopen") || name.contains("regcreate") {
        return vec![
            arg(0, "rcx", "hKey"),
            arg(1, "rdx", "lpSubKey"),
            arg(2, "r8", "reserved_or_options"),
            arg(3, "r9", "sam_or_class"),
        ];
    }
    if name.contains("regsetvalue") || name.contains("regqueryvalue") {
        return vec![
            arg(0, "rcx", "hKey"),
            arg(1, "rdx", "lpValueName"),
            arg(2, "r8", "reserved_or_type"),
            arg(3, "r9", "dwType_or_data"),
        ];
    }
    if name.contains("createprocess") {
        return vec![
            arg(0, "rcx", "lpApplicationName"),
            arg(1, "rdx", "lpCommandLine"),
            arg(2, "r8", "lpProcessAttributes"),
            arg(3, "r9", "lpThreadAttributes"),
        ];
    }
    if name.contains("shellexecute") {
        return vec![
            arg(0, "rcx", "hwnd"),
            arg(1, "rdx", "lpOperation"),
            arg(2, "r8", "lpFile"),
            arg(3, "r9", "lpParameters"),
        ];
    }
    if name.contains("winhttp") || name.contains("internet") || name.contains("connect") {
        return vec![
            arg(0, "rcx", "handle_or_host"),
            arg(1, "rdx", "object_or_port"),
            arg(2, "r8", "flags_or_context"),
            arg(3, "r9", "reserved"),
        ];
    }
    vec![
        arg(0, "rcx", "arg0"),
        arg(1, "rdx", "arg1"),
        arg(2, "r8", "arg2"),
        arg(3, "r9", "arg3"),
    ]
}

fn arg(index: usize, register: &'static str, name: &'static str) -> ApiArg {
    ApiArg {
        index,
        register,
        name,
    }
}

fn is_os_api_dll(dll: &str) -> bool {
    [
        "advapi32",
        "api-ms-win",
        "bcrypt",
        "crypt32",
        "dnsapi",
        "iphlpapi",
        "kernel32",
        "kernelbase",
        "mpr",
        "ncrypt",
        "netapi32",
        "ntdll",
        "ole32",
        "oleaut32",
        "rpcrt4",
        "secur32",
        "shell32",
        "shlwapi",
        "urlmon",
        "user32",
        "version",
        "winhttp",
        "wininet",
        "ws2_32",
    ]
    .iter()
    .any(|needle| dll.contains(needle))
}

fn runtime_family(dll: &str, name: &str) -> Option<String> {
    let joined = format!("{dll}!{name}");
    let families: [(&str, &[&str]); 9] = [
        ("qt", &["qt5", "qt6", "qstring", "qobject"]),
        ("v8", &["v8", "icu"]),
        ("steam", &["steam", "tier0", "vstdlib"]),
        (
            "msvc_runtime",
            &["msvcp", "vcruntime", "ucrtbase", "api-ms-win-crt"],
        ),
        ("crt", &["memcpy", "memmove", "malloc", "free", "printf"]),
        ("graphics", &["d3d", "dxgi", "vulkan", "nvngx", "amd"]),
        ("audio", &["phonon", "fmod", "xaudio"]),
        ("compression", &["zlib", "lz4", "zstd"]),
        ("threading_runtime", &["tbb", "concrt"]),
    ];
    families.iter().find_map(|(family, needles)| {
        needles
            .iter()
            .any(|needle| joined.contains(needle))
            .then(|| (*family).to_string())
    })
}

fn malware_relevant_family(family: &str) -> bool {
    matches!(
        family,
        "file"
            | "process"
            | "registry"
            | "network"
            | "crypto"
            | "anti_debug"
            | "service"
            | "thread"
            | "memory"
            | "module"
    )
}

fn normalize_symbol(symbol: &str) -> String {
    let Some((dll, name)) = symbol.split_once('!') else {
        return symbol.to_string();
    };
    if name.starts_with('?') {
        if name.contains("QString") {
            return format!("{dll}!Qt QString method");
        }
        if name.contains("CUtlString") {
            return format!("{dll}!CUtlString method");
        }
        if name.contains("CBufferString") {
            return format!("{dll}!CBufferString method");
        }
        return format!("{dll}!msvc_mangled_cpp_symbol");
    }
    symbol.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_file_first_arg_is_file_name() {
        assert_eq!("lpFileName", argument_name("KERNEL32.dll!CreateFileW", 0));
    }
}

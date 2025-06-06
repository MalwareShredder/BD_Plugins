/**
 * @name FileScanner
 * @version 0.2.1
 * @description Allow user to check files before downloading them.
 * @author Malware Shredder
 * @source https://github.com/MalwareShredder/BD_Plugins/tree/main/Plugins/FileScanner
 */

// Web scraping is possible but might break the rules. API may be required for some website in the near future when they're added.
// For example VirusTotal's API.

const { UI, Net, ContextMenu } = BdApi;

const special_patterns = {
    "PsExec": new Set([
        "psserve_path",
        "Psexec",
        "Psexec service"
    ]),
    "Rubeus/KrbRelayUp": new Set([
        "KrbRelayUp.pdb",
        "KrbRelayUp.Ndr.ProxyFileInfo32",
        "KrbRelayUp.Ndr.CInterfaceStubHeader32",
        "KrbRelayUp.Asn1",
        "KrbRelayUp.Relay.Attacks.Ldap",
        "KrbCredInfo",
        "KrbRelayUp.exe",
        "KRB_CRED",
        "KerbCredOffset",
        "KERB_CHECKSUM_Initialize"
    ]),
    "Mimikatz": new Set([
        "y7i39hzmyGRNbenR",
        "arrowtower.pdb",
        ".e i P_m.X ~i!",
        "_w_Y0S4_DP",
        "mimilib.dll",
        "dpapisrv!",
        "lsasrv!",
        "kdcsvc!",
        "gentilkiwi",
        "KIWI_MSV1_0_PRIMARY_CREDENTIALS",
        "KIWI_MSV1_0_CREDENTIALS"
    ])
}

const malicious_patterns = {
    "%28%22%45%6E%61%62%6C%65%20%65%64%69%74%69%6E%67%22%29": {
        "description": "This pattern is commonly used by malwares. It detects the string ('Enable editing') in obfuscated form."
    },
    "Enable editing": {
        "description": "Encourages users to enable macros or editing in RTF documents, often used in malicious contexts."
    },
    "\objhtml": {
        "description": "This pattern is used to identify embedded HTML objects in RTF documents."
    },
    "\objdata": {
        "description": "This pattern identifies embedded binary data objects in RTF documents."
    },
    "\bin": {
        "description": "This pattern is used to identify binary data in RTF documents."
    },
    "\objautlink": {
        "description": "This pattern identifies automatic links to external content within RTF documents."
    },
    "unescape": {
        "description": "The 'unescape' function is used to decode URI-encoded characters. It can be exploited by attackers to decode malicious content encoded in URLs."
    },
    "document.write": {
        "description": "The 'document.write' method is used to dynamically write content to a document. Attackers might use it to inject malicious content into a page."
    },
    "No: 20724414": {
        "description": "This pattern is frequently seen in most of malicious RTF documents."
    },
    "%4E%6F%3A%20%32%30%37%32%34%34%31%34": {
        "description": "This pattern is frequently seen in most of malicious RTF documents."
    },
    "passwordhash": {
        "description": "There might be a password protection!"
    },
    "_0x": {
        "description": "There might be obfuscated code present in the file. The '_0x' prefix is often used to obfuscate variable and function names."
    },
    "eval": {
        "description": "The 'eval' function is commonly used by attackers to dynamically execute JavaScript code, which can be a security risk."
    },
    "atob": {
        "description": "The 'atob' function is used to decode base64-encoded strings. It can be used for obfuscation or evading security mechanisms."
    },
    "parseInt": {
        "description": "The 'parseInt' function converts a string to an integer. Attackers might use it to extract data from obfuscated strings."
    },
    "iframe": {
        "description": "The 'iframe' element is used to embed another HTML document within the current page. Attackers might use it for malicious activities like clickjacking or drive-by downloads."
    },
    "unescape": {
        "description": "The 'unescape' function is used to decode URI-encoded characters. It can be exploited by attackers to decode malicious content encoded in URLs."
    },
    "window.location": {
        "description": "The 'window.location' object is used to manipulate the current URL of the browser. Attackers might abuse it to redirect users to malicious websites or perform phishing attacks."
    },
    "setTimeout": {
        "description": "The 'setTimeout' function is used to schedule the execution of a function after a specified delay."
    },
    "document.write": {
        "description": "The 'document.write' method is used to dynamically write content to a document. Attackers might use it to inject malicious content into a page."
    },
    "XMLHttpRequest": {
        "description": "The 'XMLHttpRequest' object is used to make HTTP requests from a web page. Attackers might use it to perform cross-site request forgery (CSRF) attacks."
    },
    "fromCharCode": {
        "description": "The 'fromCharCode' method is used to create a string from a sequence of Unicode values. Attackers might use it to obfuscate malicious strings."
    },
    "pass-btn": {
        "description": "This pattern is frequently seen in phishing pages."
    },
    "Enter password": {
        "description": "This pattern is frequently seen in phishing pages."
    }
}

const registry_patterns = [
    "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN",
    "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE",
    "SOFTWARE\\AUTOIT V3\\AUTOIT",
    "SOFTWARE\\MICROSOFT\\INTERNET EXPLORER\\URLSEARCHHOOKS",
    "SOFTWARE\\MICROSOFT\\ACTIVE SETUP\\INSTALLED COMPONENTS",
    "SOFTWARE\\POLICIES\\MICROSOFT\\WINDOWS\\POWERSHELL",
    "SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SAFEBOOT",
    "SOFTWARE\\POLICIES\\MICROSOFT\\WINDOWS\\WINDOWSUPDATE",
    "SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINLOGON\\SHELL",
    "SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINLOGON\\USERINIT",
    "SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINDOWS\\APPINIT_DLLS",
    "SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINDOWS\\LOADAPPINIT_DLLS",
    "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\BROWSER HELPER OBJECTS",
    "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\SHELLSERVICEOBJECTDELAYLOAD",
    "SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINLOGON\\NOTIFY",
    "SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS",
    "SYSTEM\\CURRENTCONTROLSET\\SERVICES\\WINSOCK2\\PARAMETERS\\PROTOCOL_CATALOG9",
    "SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SESSION MANAGER\\KNOWNDLLS",
    "SOFTWARE\\MICROSOFT\\WINDOWS\\POWERSHELL\\1\\SHELLIDS\\MICROSOFT.POWERSHELL_PROFILE",
    "SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\AEDEBUG",
    "SOFTWARE\\MICROSOFT\\SHARED TOOLS\\MSCONFIG\\STARTUPREG",
    "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\CONTROL PANEL\\CPLS",
    "SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\SCHEDULE\\TASKCACHE\\TREE"
]

const windows_api = {
    "File": new Set([
        "WriteFile",
        "ReadFile",
        "OpenFile",
        "NtOpenFile",
        "CreateFileW",
        "ZwCreateFile"
    ]),
    "Dll/Resource Handling": new Set([
        "LoadLibrary",
        "LoadLibraryA",
        "LoadLibraryExW"
    ]),
    "Anti Debugging": new Set([
        "IsDebuggerPresent",
        "OutputDebugString"
    ]),
    "Process Creation": new Set([
        "CreateProcess",
        "CreateProcessA",
        "CreateProcessW"
    ]),
    "Network": new Set([
        "InternetOpen",
        "InternetOpenA",
        "InternetReadFile",
        "InternetRead",
        "connect",
        "sendto",
        "WSAConnect",
        "getaddrinfo"
    ]),
    "Service Control": new Set([
        "CreateService",
        "StartService",
        "StartServiceA"
    ]),
    "Shell Execution": new Set([
        "ShellExecute",
        "ShellExecuteW"
    ]),
    "Registry": new Set([
        "RegKeyOpen",
        "RegOpenKeyExA",
        "RegOpenKeyExW",
        "RegOpenKeyTransactedA",
        "RegQueryValueEx",
        "RegQueryValueExA",
        "RegQueryInfoKeyW",
        "RegQueryInfoKeyA",
        "RegSetValue",
        "RegGetValue"
    ]),
    "Keylogging": new Set([
        "GetAsyncKeyState",
        "GetKeyboardType",
        "GetForegroundWindow"
    ]),
    "Hooking": new Set([
        "SetWindowsHook",
        "SetWindowsHookEx",
        "SetWindowsHookExA",
        "SetWindowsHookExW"
    ])
};

module.exports = class UploadFileAsHash {
    constructor(meta) {
        this.meta = meta;
    }

    start() {
        this.startPatch();
    }

    stop() {
        this.unpatch?.();
    }

    showToast(msg, type="", timeout=5000){
        UI.showToast(msg, {type: type, timeout: timeout});
    }

    startPatch(){
        this.unpatch = ContextMenu.patch("message", (retVal, props) => {
            const msg = props?.message;
            if (!msg?.attachments.length > 0){ return;}
             retVal.props.children.props.children.push(ContextMenu.buildItem({
                label: "Analyze File",
                id: this.meta.name+"-analyze-file",
                action: async () => {
                    for (const f of msg.attachments){
                        const file = await this.fetch_file(f);
                        if (file.name == f.filename){
                            const scan_result = await this.scan(file);
                            this.display_result(scan_result);
                        }
                    }
                }
            }))
        });
    }

    async scan(file){
        const result = {
            filename: file.name,
            size: file.size,
            type: file.type,
            scan_desc: [],
            checksums: {},
            basic_analysis_result: {},
            entropy: null
        }
        const algorithms = ["md5", "sha-1", "sha-256", "sha-512"];
        this.showToast("Computing hashes", "info");
        for (const algorithm of algorithms) {
            const hash = await this.auto_hash(file, algorithm);
            result.checksums[algorithm] = hash;
        }
        this.showToast("Calculating entropy", "info")
        const entropy = await this.entropy(file);
        result.entropy = entropy;
        if (entropy > 7.5){
            result.scan_desc.push("High entropy: file may be packed or compressed.");
        }
        if (!this.is_archive(file.name)){
            this.showToast("Performing basic analysis", "info");
            result.basic_analysis_result = await this.basic_analyze(file);
        }
        return result;
    }

    async basic_analyze(file){
        const result = {
            mal_patterns: {},
            reg_patterns: [],
            spec_patterns: {},
            winapi_patterns: {}
        };
        const buffer = await file.arrayBuffer();
        const text = new TextDecoder("utf-8", { fatal: false }).decode(buffer);
        const strings = text.match(new RegExp("[\\x20-\\x7E]{3,}", 'g')) || [];

        const urlRegex = /https?:\/\/[^\s]+/i;
        const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
        const emailRegex = /\b[\w.-]+?@\w+?\.\w+?\b/;

        const urls = strings.filter(s => urlRegex.test(s));
        const ips = strings.filter(s => ipRegex.test(s));
        const emails = strings.filter(s => emailRegex.test(s));

        for (const string of strings){
            const auto_check = this.auto_check_pattern(string);
            if (!this.is_objectEmpty(auto_check.mal_patterns)){
                Object.assign(result.mal_patterns, auto_check.mal_patterns);
            }
            if (!auto_check.reg_patterns.length === 0){
                result.reg_patterns = result.reg_patterns.concat(auto_check.reg_patterns);
            }
            if (!this.is_objectEmpty(auto_check.spec_patterns)){
                Object.assign(result.spec_patterns, auto_check.spec_patterns);
            }

            if (!this.is_objectEmpty(auto_check.winapi_patterns)){
                Object.assign(result.winapi_patterns, auto_check.winapi_patterns);
            }
        }
        return result;
    }

    auto_check_pattern(str){
        const result = {
            mal_patterns: {},
            reg_patterns : [],
            spec_patterns: {},
            winapi_patterns: {}
        };
        for (const mal_pattern in malicious_patterns){
            if (malicious_patterns.hasOwnProperty(mal_pattern)){
                if (str.includes(mal_pattern)){
                    result.mal_patterns[mal_pattern] = malicious_patterns[mal_pattern].description;
                }
            }
        }
        for (const reg_pattern of registry_patterns){
            if (str.replace(/\\\\/g, '\\').includes(reg_pattern)){
                result.reg_patterns.push(reg_pattern);
            }
        }
        for (const[key,value] of Object.entries(special_patterns)){
            for (const special_pattern of value){
                if (str.includes(special_pattern)){
                    result.spec_patterns[key] = special_pattern;
                }
            }
        }
        for (const [category, patterns] of Object.entries(windows_api)){
            for (const api of patterns) {
                if (str.includes(api)) {
                    if (!result.winapi_patterns[category]) {
                        result.winapi_patterns[category] = [];
                    }
                    result.winapi_patterns[category].push(api);
                }
            }
        }
        return result;
    }

    async fetch_file(file){
        this.showToast("Fetching file. (speed depends on file size and your download speed)", "info");
        const r = await Net.fetch(file.url);
        if (r.ok){
            const arryBuffer = await r.arrayBuffer();
            const type = file.content_type;
            return new File([arryBuffer], file.filename, {type});
        }
    }

    async auto_hash(file, algorithm="md5"){
        try {
            const arrayBuffer = await file.arrayBuffer();
            if (algorithm.toLowerCase().startsWith("sha")){
                const hashBuffer = await window.crypto.subtle.digest(algorithm.toUpperCase(), arrayBuffer);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
            }
            else{
                if (algorithm.toLowerCase() == "md5"){
                    return md5(new Uint8Array(arrayBuffer));
                }
            }
            return "null";
        } catch (err) {
            return "null";
        }
    }

    async entropy(file){
        const buf = new Uint8Array(await file.arrayBuffer());
        const size = buf.length;
        const freq = new Array(256).fill(0);

        for (let i = 0; i < size; i++) freq[buf[i]]++;
        let entropy = 0;
        for (let i = 0; i < 256; i++){
            if (freq[i] === 0) continue;
            const p = freq[i] / size;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    is_archive(filename){
        return /\.(zip|rar|7z|tar|gz)$/i.test(filename);
    }

    is_objectEmpty(obj){
        return Object.keys(obj).length === 0;
    }

    display_result(result){
        const VT_url = "https://www.virustotal.com/gui/file/";
        const lines = [];
        lines.push(`**File:** ${result.filename}`);
        lines.push(`**Size:** ${result.size} bytes`);
        lines.push(`**Type:** ${result.type}`);
        lines.push(`**Entropy:** ${result.entropy}`);
        lines.push("---");
        if (result.scan_desc.length > 0){
            lines.push("**Analysis Descriptions:**");
            for (const desc of result.scan_desc){
                lines.push(`- ${desc}`);
            }
        }
        lines.push("---");
        lines.push("**Checksum Hashes**")
        for (const [algorithm, checksum] of Object.entries(result.checksums)){
            lines.push(`- ${algorithm.toUpperCase()}: \`${checksum}\``);
        }
        if (!this.is_objectEmpty(result.basic_analysis_result) && (!this.is_objectEmpty(result.basic_analysis_result.mal_patterns) || result.basic_analysis_result.reg_patterns.length > 0 || !this.is_objectEmpty(result.basic_analysis_result.spec_patterns) || !this.is_objectEmpty(result.basic_analysis_result.winapi_patterns)) && !this.is_archive(result.filename)){
            const analysis_result = result.basic_analysis_result;
            lines.push("---");
            lines.push("**Basic Pattern Analysis Reports**");
            if (!this.is_objectEmpty(analysis_result.mal_patterns)){
                lines.push("**Malicious Patterns Found:**");
                for (const [pattern, desc] of Object.entries(analysis_result.mal_patterns)){
                    lines.push(`- **Pattern (${pattern})**: \`${desc}\``);
                }
            }
            if (analysis_result.reg_patterns.length > 0){
                lines.push("**Registry Patterns Found:**");
                for (const pattern of analysis_result.reg_patterns){
                    lines.push(`- **Pattern**: \`${pattern}\``);
                }
            }
            if (!this.is_objectEmpty(analysis_result.spec_patterns)){
                lines.push("**Special Patterns Found:**");
                for (const [fam, pattern] of Object.entries(analysis_result.spec_patterns)){
                    lines.push(`- **Family (${fam})**: \`${pattern}\``);
                }
            }
            if (!this.is_objectEmpty(analysis_result.winapi_patterns)){
                lines.push("**Windows Api Patterns Found:**");
                for (const [category, apis] of Object.entries(analysis_result.winapi_patterns)){
                    lines.push(`- **${category}**:`);
                    for (const api of apis) {
                        lines.push(`\`${api}\``);
                    }
                }
            }
        }
        if (result.checksums.md5 || result.checksums["sha-256"]){
            lines.push("---");
            lines.push("Since we are not allowed to web scrape VirusTotal without using their API, this is the only way.")
            lines.push(`**[VirusTotal Link](${VT_url+(result.checksums["sha-256"] ? result.checksums["sha-256"] : result.checksums.md5)})**`);
        }
        UI.showConfirmationModal("File Analysis Reports", lines, {
            confirmText: "OK",
            cancelText: null
        });
    }
};

// minified version of md5

var md5 = (function () {
  function str2hex(input) {
    var hex_tab = "0123456789abcdef";
    var output = "";
    for (var i = 0; i < input.length; i++) {
      var x = input.charCodeAt(i);
      output += hex_tab.charAt((x >>> 4) & 0x0F) + hex_tab.charAt(x & 0x0F);
    }
    return output;
  }

  function binl2rstr(input) {
    var output = "";
    for (var i = 0; i < 32 * input.length; i += 8) {
      output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF);
    }
    return output;
  }

  function rstr2binl(input) {
    var output = Array(input.length >> 2);
    for (var i = 0; i < output.length; i++) output[i] = 0;
    for (var i = 0; i < input.length * 8; i += 8) {
      output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (i % 32);
    }
    return output;
  }

  function safe_add(x, y) {
    var lsw = (x & 0xFFFF) + (y & 0xFFFF);
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
  }

  function bit_rol(num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
  }

  function md5_cmn(q, a, b, x, s, t) {
    return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b);
  }

  function md5_ff(a, b, c, d, x, s, t) {
    return md5_cmn((b & c) | (~b & d), a, b, x, s, t);
  }

  function md5_gg(a, b, c, d, x, s, t) {
    return md5_cmn((b & d) | (c & ~d), a, b, x, s, t);
  }

  function md5_hh(a, b, c, d, x, s, t) {
    return md5_cmn(b ^ c ^ d, a, b, x, s, t);
  }

  function md5_ii(a, b, c, d, x, s, t) {
    return md5_cmn(c ^ (b | ~d), a, b, x, s, t);
  }

  function binl_md5(x, len) {
    x[len >> 5] |= 0x80 << (len % 32);
    x[14 + (((len + 64) >>> 9) << 4)] = len;

    var a = 1732584193;
    var b = -271733879;
    var c = -1732584194;
    var d = 271733878;

    for (var i = 0; i < x.length; i += 16) {
      var olda = a, oldb = b, oldc = c, oldd = d;

      a = md5_ff(a, b, c, d, x[i + 0], 7, -680876936);
      d = md5_ff(d, a, b, c, x[i + 1], 12, -389564586);
      c = md5_ff(c, d, a, b, x[i + 2], 17, 606105819);
      b = md5_ff(b, c, d, a, x[i + 3], 22, -1044525330);
      a = md5_ff(a, b, c, d, x[i + 4], 7, -176418897);
      d = md5_ff(d, a, b, c, x[i + 5], 12, 1200080426);
      c = md5_ff(c, d, a, b, x[i + 6], 17, -1473231341);
      b = md5_ff(b, c, d, a, x[i + 7], 22, -45705983);
      a = md5_ff(a, b, c, d, x[i + 8], 7, 1770035416);
      d = md5_ff(d, a, b, c, x[i + 9], 12, -1958414417);
      c = md5_ff(c, d, a, b, x[i + 10], 17, -42063);
      b = md5_ff(b, c, d, a, x[i + 11], 22, -1990404162);
      a = md5_ff(a, b, c, d, x[i + 12], 7, 1804603682);
      d = md5_ff(d, a, b, c, x[i + 13], 12, -40341101);
      c = md5_ff(c, d, a, b, x[i + 14], 17, -1502002290);
      b = md5_ff(b, c, d, a, x[i + 15], 22, 1236535329);

      a = md5_gg(a, b, c, d, x[i + 1], 5, -165796510);
      d = md5_gg(d, a, b, c, x[i + 6], 9, -1069501632);
      c = md5_gg(c, d, a, b, x[i + 11], 14, 643717713);
      b = md5_gg(b, c, d, a, x[i + 0], 20, -373897302);
      a = md5_gg(a, b, c, d, x[i + 5], 5, -701558691);
      d = md5_gg(d, a, b, c, x[i + 10], 9, 38016083);
      c = md5_gg(c, d, a, b, x[i + 15], 14, -660478335);
      b = md5_gg(b, c, d, a, x[i + 4], 20, -405537848);
      a = md5_gg(a, b, c, d, x[i + 9], 5, 568446438);
      d = md5_gg(d, a, b, c, x[i + 14], 9, -1019803690);
      c = md5_gg(c, d, a, b, x[i + 3], 14, -187363961);
      b = md5_gg(b, c, d, a, x[i + 8], 20, 1163531501);
      a = md5_gg(a, b, c, d, x[i + 13], 5, -1444681467);
      d = md5_gg(d, a, b, c, x[i + 2], 9, -51403784);
      c = md5_gg(c, d, a, b, x[i + 7], 14, 1735328473);
      b = md5_gg(b, c, d, a, x[i + 12], 20, -1926607734);

      a = md5_hh(a, b, c, d, x[i + 5], 4, -378558);
      d = md5_hh(d, a, b, c, x[i + 8], 11, -2022574463);
      c = md5_hh(c, d, a, b, x[i + 11], 16, 1839030562);
      b = md5_hh(b, c, d, a, x[i + 14], 23, -35309556);
      a = md5_hh(a, b, c, d, x[i + 1], 4, -1530992060);
      d = md5_hh(d, a, b, c, x[i + 4], 11, 1272893353);
      c = md5_hh(c, d, a, b, x[i + 7], 16, -155497632);
      b = md5_hh(b, c, d, a, x[i + 10], 23, -1094730640);
      a = md5_hh(a, b, c, d, x[i + 13], 4, 681279174);
      d = md5_hh(d, a, b, c, x[i + 0], 11, -358537222);
      c = md5_hh(c, d, a, b, x[i + 3], 16, -722521979);
      b = md5_hh(b, c, d, a, x[i + 6], 23, 76029189);
      a = md5_hh(a, b, c, d, x[i + 9], 4, -640364487);
      d = md5_hh(d, a, b, c, x[i + 12], 11, -421815835);
      c = md5_hh(c, d, a, b, x[i + 15], 16, 530742520);
      b = md5_hh(b, c, d, a, x[i + 2], 23, -995338651);

      a = md5_ii(a, b, c, d, x[i + 0], 6, -198630844);
      d = md5_ii(d, a, b, c, x[i + 7], 10, 1126891415);
      c = md5_ii(c, d, a, b, x[i + 14], 15, -1416354905);
      b = md5_ii(b, c, d, a, x[i + 5], 21, -57434055);
      a = md5_ii(a, b, c, d, x[i + 12], 6, 1700485571);
      d = md5_ii(d, a, b, c, x[i + 3], 10, -1894986606);
      c = md5_ii(c, d, a, b, x[i + 10], 15, -1051523);
      b = md5_ii(b, c, d, a, x[i + 1], 21, -2054922799);
      a = md5_ii(a, b, c, d, x[i + 8], 6, 1873313359);
      d = md5_ii(d, a, b, c, x[i + 15], 10, -30611744);
      c = md5_ii(c, d, a, b, x[i + 6], 15, -1560198380);
      b = md5_ii(b, c, d, a, x[i + 13], 21, 1309151649);
      a = md5_ii(a, b, c, d, x[i + 4], 6, -145523070);
      d = md5_ii(d, a, b, c, x[i + 11], 10, -1120210379);
      c = md5_ii(c, d, a, b, x[i + 2], 15, 718787259);
      b = md5_ii(b, c, d, a, x[i + 9], 21, -343485551);

      a = safe_add(a, olda);
      b = safe_add(b, oldb);
      c = safe_add(c, oldc);
      d = safe_add(d, oldd);
    }
    return [a, b, c, d];
  }

  function rstr_md5(s) {
    return binl2rstr(binl_md5(rstr2binl(s), s.length * 8));
  }

  function str2rstr_utf8(input) {
    return new TextDecoder("utf-8").decode(new TextEncoder().encode(input));
  }

  return function(input) {
    if (!(input instanceof Uint8Array)) {
      input = new TextEncoder().encode(typeof input === "string" ? input : JSON.stringify(input));
    }
    var rawStr = String.fromCharCode.apply(null, input);
    return str2hex(rstr_md5(str2rstr_utf8(rawStr)));
  };
})();

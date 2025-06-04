/**
 * @name UploadFileAsHash
 * @version 0.2.0
 * @description Automatically renames uploaded files to their hash values.
 * @author Malware Shredder
 */

const { Patcher, Webpack, UI, Data } = BdApi;

const config = {
    setting: [
        {
            type: "dropdown",
            id: "algorithm",
            name: "Algorithm",
            note: "Select hashing algorithm (default = MD5)",
            value: "md5",
            options: [
                {label: "MD5", value: "md5"},
                {label: "SHA-1", value: "sha-1"},
                {label: "SHA-256", value: "sha-256"},
                {label: "SHA-384", value: "sha-384"},
                {label: "SHA-512", value: "sha-512"}
            ]
        }
    ]
}

module.exports = class UploadFileAsHash {
    constructor(meta) {
        this.meta = meta;
        this.algorithm = config.setting[0].value;
    }

    start() {
        const algorithm = Data.load(this.meta.name, "algorithm");
        if (algorithm){
            config.setting[0].value = algorithm;
            this.algorithm = algorithm;
        }
        this.startPatch();
    }

    stop() {
        Patcher.unpatchAll(this.meta.name);
    }

    showToast(msg, type="", timeout=5000){
        UI.showToast(msg, {type: type, timeout: timeout});
    }

    startPatch() {
        Patcher.instead(this.meta.name, Webpack.getByKeys("uploadFiles"), "uploadFiles", async (self, [args], original) => { // patch uploadFiles module to instead use this function
            for (const f of args.uploads) { // iterate uploads files
                const file = f.item.file; // get file instance
                if (file != null && file instanceof File){
                    let hash = await this.auto_hash(file, this.algorithm);
                    const ext = (file.name.includes(".") ? file.name.split(".").pop() : ""); // split the dot and extract extension.
                    if (hash != "null") {
                        f.filename = (ext ? `${hash}.${ext}` : hash); // rename file to hash with extension
                    }
                    else{
                        hash = await this.auto_hash(file); // try hashing using default MD5 algorithm.
                        if (hash != "null"){
                            f.filename = (ext ? `${hash}.${ext}` : hash);
                        }
                    }
                    if (f.filename != file.name){
                        this.showToast(`Successfully uploaded file as hash. Algorithm: *${this.algorithm.toUpperCase()}*`, "success");
                    }
                    else{
                        this.showToast("Failed to hash. Using original file name.", "error");
                    }
                }
            }
            original(args); // call original function with modified arguments
        });
    }

    async auto_hash(file, algorithm="md5") { // asynchronous is required to read file's contents
        try {
            const arrayBuffer = await file.arrayBuffer(); // get file's contents
            if (algorithm.toLowerCase().startsWith("sha")) {
                const hashBuffer = await window.crypto.subtle.digest(algorithm.toUpperCase(), arrayBuffer);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                return hashArray.map(b => b.toString(16).padStart(2, "0")).join(""); // convert hex to string
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

    algorithmChange(algorithm){
        config.setting[0].value = algorithm;
        this.algorithm = algorithm;
        this.showToast(`Using algorithm: *${this.algorithm.toLocaleUpperCase()}*`, "success");
        Data.save(this.meta.name, config.setting[0].id, config.setting[0].value);
    }

    getSettingsPanel() {
        return UI.buildSettingsPanel({
            settings: config.setting,
            onChange: (_, __, value) => this.algorithmChange(value),
        });
    }
};

// Thanks https://pajhome.org.uk/crypt/md5 for this awesome md5 in javascript.

var md5=function(){var n=function(n){return function(n){for(var r,t="0123456789abcdef",e="",o=0;o<n.length;o++)r=n.charCodeAt(o),e+=t.charAt(r>>>4&15)+t.charAt(15&r);return e}(function(n){for(var r="",t=0;t<32*n.length;t+=8)r+=String.fromCharCode(n[t>>5]>>>t%32&255);return r}(function(n,r){n[r>>5]|=128<<r%32,n[14+(r+64>>>9<<4)]=r;for(var i=1732584193,c=-271733879,a=-1732584194,h=271733878,g=0;g<n.length;g+=16){var v=i,d=c,l=a,A=h;c=u(c=u(c=u(c=u(c=o(c=o(c=o(c=o(c=e(c=e(c=e(c=e(c=t(c=t(c=t(c=t(c,a=t(a,h=t(h,i=t(i,c,a,h,n[g+0],7,-680876936),c,a,n[g+1],12,-389564586),i,c,n[g+2],17,606105819),h,i,n[g+3],22,-1044525330),a=t(a,h=t(h,i=t(i,c,a,h,n[g+4],7,-176418897),c,a,n[g+5],12,1200080426),i,c,n[g+6],17,-1473231341),h,i,n[g+7],22,-45705983),a=t(a,h=t(h,i=t(i,c,a,h,n[g+8],7,1770035416),c,a,n[g+9],12,-1958414417),i,c,n[g+10],17,-42063),h,i,n[g+11],22,-1990404162),a=t(a,h=t(h,i=t(i,c,a,h,n[g+12],7,1804603682),c,a,n[g+13],12,-40341101),i,c,n[g+14],17,-1502002290),h,i,n[g+15],22,1236535329),a=e(a,h=e(h,i=e(i,c,a,h,n[g+1],5,-165796510),c,a,n[g+6],9,-1069501632),i,c,n[g+11],14,643717713),h,i,n[g+0],20,-373897302),a=e(a,h=e(h,i=e(i,c,a,h,n[g+5],5,-701558691),c,a,n[g+10],9,38016083),i,c,n[g+15],14,-660478335),h,i,n[g+4],20,-405537848),a=e(a,h=e(h,i=e(i,c,a,h,n[g+9],5,568446438),c,a,n[g+14],9,-1019803690),i,c,n[g+3],14,-187363961),h,i,n[g+8],20,1163531501),a=e(a,h=e(h,i=e(i,c,a,h,n[g+13],5,-1444681467),c,a,n[g+2],9,-51403784),i,c,n[g+7],14,1735328473),h,i,n[g+12],20,-1926607734),a=o(a,h=o(h,i=o(i,c,a,h,n[g+5],4,-378558),c,a,n[g+8],11,-2022574463),i,c,n[g+11],16,1839030562),h,i,n[g+14],23,-35309556),a=o(a,h=o(h,i=o(i,c,a,h,n[g+1],4,-1530992060),c,a,n[g+4],11,1272893353),i,c,n[g+7],16,-155497632),h,i,n[g+10],23,-1094730640),a=o(a,h=o(h,i=o(i,c,a,h,n[g+13],4,681279174),c,a,n[g+0],11,-358537222),i,c,n[g+3],16,-722521979),h,i,n[g+6],23,76029189),a=o(a,h=o(h,i=o(i,c,a,h,n[g+9],4,-640364487),c,a,n[g+12],11,-421815835),i,c,n[g+15],16,530742520),h,i,n[g+2],23,-995338651),a=u(a,h=u(h,i=u(i,c,a,h,n[g+0],6,-198630844),c,a,n[g+7],10,1126891415),i,c,n[g+14],15,-1416354905),h,i,n[g+5],21,-57434055),a=u(a,h=u(h,i=u(i,c,a,h,n[g+12],6,1700485571),c,a,n[g+3],10,-1894986606),i,c,n[g+10],15,-1051523),h,i,n[g+1],21,-2054922799),a=u(a,h=u(h,i=u(i,c,a,h,n[g+8],6,1873313359),c,a,n[g+15],10,-30611744),i,c,n[g+6],15,-1560198380),h,i,n[g+13],21,1309151649),a=u(a,h=u(h,i=u(i,c,a,h,n[g+4],6,-145523070),c,a,n[g+11],10,-1120210379),i,c,n[g+2],15,718787259),h,i,n[g+9],21,-343485551),i=f(i,v),c=f(c,d),a=f(a,l),h=f(h,A)}return[i,c,a,h]}(function(n){for(var r=Array(n.length>>2),t=0;t<r.length;t++)r[t]=0;for(t=0;t<8*n.length;t+=8)r[t>>5]|=(255&n.charCodeAt(t/8))<<t%32;return r}(n),8*n.length)))};function r(n,r,t,e,o,u){return f(function(n,r){return n<<r|n>>>32-r}(f(f(r,n),f(e,u)),o),t)}function t(n,t,e,o,u,f,i){return r(t&e|~t&o,n,t,u,f,i)}function e(n,t,e,o,u,f,i){return r(t&o|e&~o,n,t,u,f,i)}function o(n,t,e,o,u,f,i){return r(t^e^o,n,t,u,f,i)}function u(n,t,e,o,u,f,i){return r(e^(t|~o),n,t,u,f,i)}function f(n,r){var t=(65535&n)+(65535&r);return(n>>16)+(r>>16)+(t>>16)<<16|65535&t}return function(r){r instanceof Uint8Array||(r=(new TextEncoder).encode("string"==typeof r?r:JSON.stringify(r)));for(var t=[],e=new Uint8Array(r),o=0,u=e.byteLength;o<u;o++)t.push(String.fromCharCode(e[o]));return n(t.join(""))}}();

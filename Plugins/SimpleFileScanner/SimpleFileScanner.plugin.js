/**
 * @name SimpleFileScanner
 * @version 0.1.0
 * @description Allow user to check files before downloading them.
 * @author Malware Shredder
 */

// Web scraping is possible but might break the rules. 
// API may be required for some website in the near future when they're added.
// I might implement scanners from Quickscope.

const { UI, Net, ContextMenu } = BdApi;

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

    startPatch() {
        this.unpatch = ContextMenu.patch("message", (retVal, props) => {
            const msg = props?.message;
            if (!msg?.attachments.length > 0){ return;}
             retVal.props.children.props.children.push(ContextMenu.buildItem({
                label: "Scan File",
                id: this.meta.name+"-scan-file",
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
        const result = {filename: file.name, size: file.size, type: file.type, scan_desc: [], checksums: {}, entropy: null}
        const algorithms = ["md5", "sha-1", "sha-256", "sha-512"];
        this.showToast("Computing hashes.", "info")
        for (const algorithm of algorithms) {
            const hash = await this.auto_hash(file, algorithm);
            result.checksums[algorithm] = hash;
        }
        this.showToast("Calculating entropy.", "info")
        const entropy = await this.entropy(file);
        result.entropy = entropy;
        if (entropy > 7.5){
            result.scan_desc.push("High entropy: file may be packed or compressed.")
        }

        return result;
    }

    async fetch_file(file){
        this.showToast("Fetching file.", "info")
        const r = await Net.fetch(file.url);
        if (r.ok){
            const arryBuffer = await r.arrayBuffer();
            const type = file.content_type;
            return new File([arryBuffer], file.filename, {type});
        }
    }

    async auto_hash(file, algorithm="md5") {
        try {
            const arrayBuffer = await file.arrayBuffer();
            if (algorithm.toLowerCase().startsWith("sha")) {
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

    async entropy(file) {
        const buf = new Uint8Array(await file.arrayBuffer());
        const size = buf.length;
        const freq = new Array(256).fill(0);

        for (let i = 0; i < size; i++) freq[buf[i]]++;
        let entropy = 0;
        for (let i = 0; i < 256; i++) {
            if (freq[i] === 0) continue;
            const p = freq[i] / size;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    display_result(result) {
        const lines = [];

        lines.push(`**File:** ${result.filename}`);
        lines.push(`**Size:** ${result.size} bytes`);
        lines.push(`**Type:** ${result.type}`);
        lines.push(`**Entropy:** ${result.entropy}`);

        if (result.scan_desc.length > 0) {
            lines.push("**Scan Descriptions:**");
            for (const desc of result.scan_desc){
                lines.push(`- ${desc}`);
            }
        }

        lines.push("**Checksum Hashes**")
        for (const [algorithm, checksum] of Object.entries(result.checksums)){
            lines.push(`- ${algorithm.toUpperCase()}: \`${checksum}\``);
        }

        UI.showConfirmationModal("Scan Result", lines.join("\n\n"), {
            confirmText: "OK",
            cancelText: null
        });
    }
};

// Thanks https://pajhome.org.uk/crypt/md5 for this awesome md5 in javascript.

var md5=function(){var n=function(n){return function(n){for(var r,t="0123456789abcdef",e="",o=0;o<n.length;o++)r=n.charCodeAt(o),e+=t.charAt(r>>>4&15)+t.charAt(15&r);return e}(function(n){for(var r="",t=0;t<32*n.length;t+=8)r+=String.fromCharCode(n[t>>5]>>>t%32&255);return r}(function(n,r){n[r>>5]|=128<<r%32,n[14+(r+64>>>9<<4)]=r;for(var i=1732584193,c=-271733879,a=-1732584194,h=271733878,g=0;g<n.length;g+=16){var v=i,d=c,l=a,A=h;c=u(c=u(c=u(c=u(c=o(c=o(c=o(c=o(c=e(c=e(c=e(c=e(c=t(c=t(c=t(c=t(c,a=t(a,h=t(h,i=t(i,c,a,h,n[g+0],7,-680876936),c,a,n[g+1],12,-389564586),i,c,n[g+2],17,606105819),h,i,n[g+3],22,-1044525330),a=t(a,h=t(h,i=t(i,c,a,h,n[g+4],7,-176418897),c,a,n[g+5],12,1200080426),i,c,n[g+6],17,-1473231341),h,i,n[g+7],22,-45705983),a=t(a,h=t(h,i=t(i,c,a,h,n[g+8],7,1770035416),c,a,n[g+9],12,-1958414417),i,c,n[g+10],17,-42063),h,i,n[g+11],22,-1990404162),a=t(a,h=t(h,i=t(i,c,a,h,n[g+12],7,1804603682),c,a,n[g+13],12,-40341101),i,c,n[g+14],17,-1502002290),h,i,n[g+15],22,1236535329),a=e(a,h=e(h,i=e(i,c,a,h,n[g+1],5,-165796510),c,a,n[g+6],9,-1069501632),i,c,n[g+11],14,643717713),h,i,n[g+0],20,-373897302),a=e(a,h=e(h,i=e(i,c,a,h,n[g+5],5,-701558691),c,a,n[g+10],9,38016083),i,c,n[g+15],14,-660478335),h,i,n[g+4],20,-405537848),a=e(a,h=e(h,i=e(i,c,a,h,n[g+9],5,568446438),c,a,n[g+14],9,-1019803690),i,c,n[g+3],14,-187363961),h,i,n[g+8],20,1163531501),a=e(a,h=e(h,i=e(i,c,a,h,n[g+13],5,-1444681467),c,a,n[g+2],9,-51403784),i,c,n[g+7],14,1735328473),h,i,n[g+12],20,-1926607734),a=o(a,h=o(h,i=o(i,c,a,h,n[g+5],4,-378558),c,a,n[g+8],11,-2022574463),i,c,n[g+11],16,1839030562),h,i,n[g+14],23,-35309556),a=o(a,h=o(h,i=o(i,c,a,h,n[g+1],4,-1530992060),c,a,n[g+4],11,1272893353),i,c,n[g+7],16,-155497632),h,i,n[g+10],23,-1094730640),a=o(a,h=o(h,i=o(i,c,a,h,n[g+13],4,681279174),c,a,n[g+0],11,-358537222),i,c,n[g+3],16,-722521979),h,i,n[g+6],23,76029189),a=o(a,h=o(h,i=o(i,c,a,h,n[g+9],4,-640364487),c,a,n[g+12],11,-421815835),i,c,n[g+15],16,530742520),h,i,n[g+2],23,-995338651),a=u(a,h=u(h,i=u(i,c,a,h,n[g+0],6,-198630844),c,a,n[g+7],10,1126891415),i,c,n[g+14],15,-1416354905),h,i,n[g+5],21,-57434055),a=u(a,h=u(h,i=u(i,c,a,h,n[g+12],6,1700485571),c,a,n[g+3],10,-1894986606),i,c,n[g+10],15,-1051523),h,i,n[g+1],21,-2054922799),a=u(a,h=u(h,i=u(i,c,a,h,n[g+8],6,1873313359),c,a,n[g+15],10,-30611744),i,c,n[g+6],15,-1560198380),h,i,n[g+13],21,1309151649),a=u(a,h=u(h,i=u(i,c,a,h,n[g+4],6,-145523070),c,a,n[g+11],10,-1120210379),i,c,n[g+2],15,718787259),h,i,n[g+9],21,-343485551),i=f(i,v),c=f(c,d),a=f(a,l),h=f(h,A)}return[i,c,a,h]}(function(n){for(var r=Array(n.length>>2),t=0;t<r.length;t++)r[t]=0;for(t=0;t<8*n.length;t+=8)r[t>>5]|=(255&n.charCodeAt(t/8))<<t%32;return r}(n),8*n.length)))};function r(n,r,t,e,o,u){return f(function(n,r){return n<<r|n>>>32-r}(f(f(r,n),f(e,u)),o),t)}function t(n,t,e,o,u,f,i){return r(t&e|~t&o,n,t,u,f,i)}function e(n,t,e,o,u,f,i){return r(t&o|e&~o,n,t,u,f,i)}function o(n,t,e,o,u,f,i){return r(t^e^o,n,t,u,f,i)}function u(n,t,e,o,u,f,i){return r(e^(t|~o),n,t,u,f,i)}function f(n,r){var t=(65535&n)+(65535&r);return(n>>16)+(r>>16)+(t>>16)<<16|65535&t}return function(r){r instanceof Uint8Array||(r=(new TextEncoder).encode("string"==typeof r?r:JSON.stringify(r)));for(var t=[],e=new Uint8Array(r),o=0,u=e.byteLength;o<u;o++)t.push(String.fromCharCode(e[o]));return n(t.join(""))}}();

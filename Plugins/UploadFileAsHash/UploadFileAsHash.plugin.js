/**
 * @name UploadFileAsHash
 * @version 0.2.0
 * @description Automatically renames uploaded files to their hash values.
 * @author Malware Shredder
 * @source https://github.com/MalwareShredder/BD_Plugins/tree/main/Plugins/UploadFileAsHash
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
        Patcher.instead(this.meta.name, Webpack.getByKeys("uploadFiles"), "uploadFiles", async (self, [args], original) => {
            for (const f of args.uploads) {
                const file = f.item.file;
                if (file != null && file instanceof File){
                    let hash = await this.auto_hash(file, this.algorithm);
                    const ext = (file.name.includes(".") ? file.name.split(".").pop() : "");
                    if (hash != "null") {
                        f.filename = (ext ? `${hash}.${ext}` : hash);
                    }
                    else{
                        this.showToast(`Unknown algorithm or failed to hash. Failed algorithm: *${this.algorithm.toLocaleUpperCase()}*. Attempting to use default algorithm: *MD5*`, "warning");
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

// minified version of md5

var md5 = (function (){
    function toHex(str){
        var hexChars = '0123456789abcdef';
        var hex = '';
        for (var i = 0; i < str.length; i++){
            var code = str.charCodeAt(i);
            hex += hexChars.charAt((code >>> 4) & 0x0F) + hexChars.charAt(code & 0x0F);
        }
        return hex;
    }

    function strToBlocks(str){
        var blocks = Array(str.length >> 2).fill(0);
        for (var i = 0; i < 8 * str.length; i += 8){
            blocks[i >> 5] |= (str.charCodeAt(i / 8) & 0xFF) << (i % 32);
        }
        return blocks;
    }

    function blocksToStr(blocks){
        var output = '';
        for (var i = 0; i < 32 * blocks.length; i += 8){
            output += String.fromCharCode((blocks[i >> 5] >>> (i % 32)) & 0xFF);
        }
        return output;
    }

    function md5Hash(blocks, len){
        blocks[len >> 5] |= 0x80 << (len % 32);
        blocks[14 + ((len + 64 >>> 9) << 4)] = len;

        var a = 1732584193,
            b = -271733879,
            c = -1732584194,
            d = 271733878;

        for (var i = 0; i < blocks.length; i += 16){
            var aa = a, bb = b, cc = c, dd = d;

            a = ff(a, b, c, d, blocks[i + 0], 7, -680876936);
            d = ff(d, a, b, c, blocks[i + 1], 12, -389564586);
            c = ff(c, d, a, b, blocks[i + 2], 17, 606105819);
            b = ff(b, c, d, a, blocks[i + 3], 22, -1044525330);
            a = ff(a, b, c, d, blocks[i + 4], 7, -176418897);
            d = ff(d, a, b, c, blocks[i + 5], 12, 1200080426);
            c = ff(c, d, a, b, blocks[i + 6], 17, -1473231341);
            b = ff(b, c, d, a, blocks[i + 7], 22, -45705983);
            a = ff(a, b, c, d, blocks[i + 8], 7, 1770035416);
            d = ff(d, a, b, c, blocks[i + 9], 12, -1958414417);
            c = ff(c, d, a, b, blocks[i + 10], 17, -42063);
            b = ff(b, c, d, a, blocks[i + 11], 22, -1990404162);
            a = ff(a, b, c, d, blocks[i + 12], 7, 1804603682);
            d = ff(d, a, b, c, blocks[i + 13], 12, -40341101);
            c = ff(c, d, a, b, blocks[i + 14], 17, -1502002290);
            b = ff(b, c, d, a, blocks[i + 15], 22, 1236535329);

            a = gg(a, b, c, d, blocks[i + 1], 5, -165796510);
            d = gg(d, a, b, c, blocks[i + 6], 9, -1069501632);
            c = gg(c, d, a, b, blocks[i + 11], 14, 643717713);
            b = gg(b, c, d, a, blocks[i + 0], 20, -373897302);
            a = gg(a, b, c, d, blocks[i + 5], 5, -701558691);
            d = gg(d, a, b, c, blocks[i + 10], 9, 38016083);
            c = gg(c, d, a, b, blocks[i + 15], 14, -660478335);
            b = gg(b, c, d, a, blocks[i + 4], 20, -405537848);
            a = gg(a, b, c, d, blocks[i + 9], 5, 568446438);
            d = gg(d, a, b, c, blocks[i + 14], 9, -1019803690);
            c = gg(c, d, a, b, blocks[i + 3], 14, -187363961);
            b = gg(b, c, d, a, blocks[i + 8], 20, 1163531501);
            a = gg(a, b, c, d, blocks[i + 13], 5, -1444681467);
            d = gg(d, a, b, c, blocks[i + 2], 9, -51403784);
            c = gg(c, d, a, b, blocks[i + 7], 14, 1735328473);
            b = gg(b, c, d, a, blocks[i + 12], 20, -1926607734);

            a = hh(a, b, c, d, blocks[i + 5], 4, -378558);
            d = hh(d, a, b, c, blocks[i + 8], 11, -2022574463);
            c = hh(c, d, a, b, blocks[i + 11], 16, 1839030562);
            b = hh(b, c, d, a, blocks[i + 14], 23, -35309556);
            a = hh(a, b, c, d, blocks[i + 1], 4, -1530992060);
            d = hh(d, a, b, c, blocks[i + 4], 11, 1272893353);
            c = hh(c, d, a, b, blocks[i + 7], 16, -155497632);
            b = hh(b, c, d, a, blocks[i + 10], 23, -1094730640);
            a = hh(a, b, c, d, blocks[i + 13], 4, 681279174);
            d = hh(d, a, b, c, blocks[i + 0], 11, -358537222);
            c = hh(c, d, a, b, blocks[i + 3], 16, -722521979);
            b = hh(b, c, d, a, blocks[i + 6], 23, 76029189);
            a = hh(a, b, c, d, blocks[i + 9], 4, -640364487);
            d = hh(d, a, b, c, blocks[i + 12], 11, -421815835);
            c = hh(c, d, a, b, blocks[i + 15], 16, 530742520);
            b = hh(b, c, d, a, blocks[i + 2], 23, -995338651);

            a = ii(a, b, c, d, blocks[i + 0], 6, -198630844);
            d = ii(d, a, b, c, blocks[i + 7], 10, 1126891415);
            c = ii(c, d, a, b, blocks[i + 14], 15, -1416354905);
            b = ii(b, c, d, a, blocks[i + 5], 21, -57434055);
            a = ii(a, b, c, d, blocks[i + 12], 6, 1700485571);
            d = ii(d, a, b, c, blocks[i + 3], 10, -1894986606);
            c = ii(c, d, a, b, blocks[i + 10], 15, -1051523);
            b = ii(b, c, d, a, blocks[i + 1], 21, -2054922799);
            a = ii(a, b, c, d, blocks[i + 8], 6, 1873313359);
            d = ii(d, a, b, c, blocks[i + 15], 10, -30611744);
            c = ii(c, d, a, b, blocks[i + 6], 15, -1560198380);
            b = ii(b, c, d, a, blocks[i + 13], 21, 1309151649);
            a = ii(a, b, c, d, blocks[i + 4], 6, -145523070);
            d = ii(d, a, b, c, blocks[i + 11], 10, -1120210379);
            c = ii(c, d, a, b, blocks[i + 2], 15, 718787259);
            b = ii(b, c, d, a, blocks[i + 9], 21, -343485551);

            a = add32(a, aa);
            b = add32(b, bb);
            c = add32(c, cc);
            d = add32(d, dd);
        }
        return [a, b, c, d];
    }

    function cmn(q, a, b, x, s, t){
        return add32(rol(add32(add32(a, q), add32(x, t)), s), b);
    }

    function ff(a, b, c, d, x, s, t){
        return cmn((b & c) | (~b & d), a, b, x, s, t);
    }

    function gg(a, b, c, d, x, s, t){
        return cmn((b & d) | (c & ~d), a, b, x, s, t);
    }

    function hh(a, b, c, d, x, s, t){
        return cmn(b ^ c ^ d, a, b, x, s, t);
    }

    function ii(a, b, c, d, x, s, t){
        return cmn(c ^ (b | ~d), a, b, x, s, t);
    }

    function rol(val, shift){
        return (val << shift) | (val >>> (32 - shift));
    }

    function add32(a, b){
        var l = (a & 0xFFFF) + (b & 0xFFFF);
        return ((a >> 16) + (b >> 16) + (l >> 16) << 16) | (l & 0xFFFF);
    }

    function computeMD5(input){
        if (!(input instanceof Uint8Array)){
            input = new TextEncoder().encode(typeof input === 'string' ? input : JSON.stringify(input));
        }
        var binary = [];
        for (var i = 0; i < input.byteLength; i++){
            binary.push(String.fromCharCode(input[i]));
        }
        var str = binary.join('');
        return toHex(blocksToStr(md5Hash(strToBlocks(str), str.length * 8)));
    }

    return computeMD5;
})();

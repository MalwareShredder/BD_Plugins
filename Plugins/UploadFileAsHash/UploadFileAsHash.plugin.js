/**
 * @name UploadFileAsHash
 * @version 0.1.1
 * @description Automatically rename uploaded files to hash values.
 * @author Malware Shredder
 */

// Comments will be added at full released.

const { Patcher, Webpack } = BdApi;

const uploadModule = Webpack.getByKeys("uploadFiles");

module.exports = class UploadFileAsHash {
    constructor(meta) {
        this.meta = meta;
        this.algorithm = "SHA-1";
    }

    start() {
        this.startPatch();
    }

    stop() {
        Patcher.unpatchAll(this.meta.name);
    }

    startPatch() {
        Patcher.instead(this.meta.name, uploadModule, "uploadFiles", async (self, [args], original) => {
            for (const f of args.uploads) {
                const file = f.item.file;
                if (file != null && file instanceof File){
                    const hash = await this.auto_hash(file);
                    if (hash != "null") {
                        const ext = (file.name.includes(".") ? file.name.split(".").pop() : "");
                        f.filename = (ext ? `${hash}.${ext}` : hash);
                    }
                }
            }
            original(args);
        });
    }

    async auto_hash(file) {
        try {
            const arrayBuffer = await file.arrayBuffer();
            if (this.algorithm.startsWith("SHA")) {
                const hashBuffer = await window.crypto.subtle.digest(this.algorithm, arrayBuffer);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
            }
            return "null";
        } catch (err) {
            return "null";
        }
    }
};

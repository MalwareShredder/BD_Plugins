/**
 * @name UploadFileAsHash
 * @version 0.1.0
 * @description Automatically rename uploaded files to hash values.
 * @author Malware Shredder
 */

const { Patcher, Webpack } = BdApi;

const uploadModule = Webpack.getByKeys("uploadFiles");
const messageModule = Webpack.getByKeys("_sendMessage");
const Dispatcher = Webpack.getByKeys("dispatch");
const userId = Webpack.getStore("UserStore").getCurrentUser().id;

module.exports = class UploadFileAsHash {
    constructor(meta) {
        this.meta = meta;
        this.algorithm = "SHA-1";
        this.correctFileNames = new Set();
    }

    start() {
        this.startPatch();
    }

    stop() {
        Patcher.unpatchAll(this.meta.name);
        Dispatcher.unsubscribe("MESSAGE_CREATE", this.msgIntercept);
        this.correctFileNames.clear();
    }

    startPatch() {
        Patcher.instead(this.meta.name, uploadModule, "uploadFiles", async (self, [args], original) => {
            for (const f of args.uploads) {
                const file = f.item?.file; // error handling
                if (file instanceof File){
                    const hash = await this.auto_hash(file);
                    if (hash != "null") {
                        const ext = (file.name.includes(".") ? file.name.split(".").pop() : "");
                        f.filename = (ext ? `${hash}.${ext}` : hash);
                        this.correctFileNames.add(f.filename);
                    }
                }
            }
            original(args);
        });
        Dispatcher.subscribe("MESSAGE_CREATE", this.msgIntercept);
    }

    deleteFromList(attachments){
        for (const a of attachments) {
            this.correctFileNames.delete(a.filename);
        }
    }

    msgIntercept = ({ message }) => {
        if (message.author.id != userId || !message.attachments || message.attachments.length == 0) return;

        let match = true;
        for (const a of message.attachments) {
            if (!this.correctFileNames.has(a.filename)) {
                console.warn("[UploadFileAsHash] File name is not matched correct file name :", a.filename);
                match = false;
            }
        }
        if (match) {
            this.deleteFromList(message.attachments);
        } else {
            messageModule.deleteMessage(message.channel_id, message.id);
        }
    };

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

rpc.exports = {
    run: function () {
        Process.enumerateRanges('r--', {
            onMatch: function (range) {
                try {
                    var bs = range.base.readByteArray(range.size);
                    var payload = { base: range.base, size: range.size, protection: range.protection };
                    if ('file' in range) {
                        payload.file = { path: range.file.path, offset: range.file.offset, size: range.file.size };
                        if (payload.file.path.startsWith('/system/') || payload.file.path.startsWith('/dev/') || payload.file.path.startsWith('/data/dalvik-cache/')) {
                            return
                        }
                    }
                    send(payload, bs);
                } catch (e) {
                    console.error(`Error when enumerateRanges: base=${range.base} size=${range.size} prot=${range.protection} e=${e}`);
                }
            },
            onComplete: function () { }
        });
    }
};

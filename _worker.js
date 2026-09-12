import { connect } from "cloudflare:sockets";

// ==================== CONFIGURATION ====================
let userID = "";
let trojanPassword = "";
let proxyIP = "cdn-b100.xn--b6gac.eu.org";
let dohURL = "https://cloudflare-dns.com/dns-query";

// Cloudflare supported ports
const CF_PORTS = [80, 8080, 8880, 2052, 2086, 2095, 443, 8443, 2053, 2096, 2087, 2083];

// ==================== UUID VALIDATION ====================
function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}



// ==================== WEBSOCKET CONSTANTS ====================
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

// ==================== MAIN EXPORT ====================
export default {
    async fetch(request, env, ctx) {
        try {
            // Load environment variables
            userID = env.UUID || env.uuid || userID;
            trojanPassword = env.TROJAN_PASS || env.TROJAN_PASSWORD || env.PASSWORD || trojanPassword;
            proxyIP = env.PROXYIP || env.proxyip || env.PROXY_IP || proxyIP;
            dohURL = env.DNS_RESOLVER_URL || env.DOH_URL || dohURL;

            const upgradeHeader = request.headers.get("Upgrade");
            const url = new URL(request.url);
            const host = request.headers.get("Host");

            // WebSocket upgrade = proxy tunnel
            if (upgradeHeader === "websocket") {
                return await proxyOverWSHandler(request);
            }

            // HTTP requests = config/subscription pages
            const path = url.pathname;

            // Config page
            if (path === `/${userID}` || path === "/config" || path === "/") {
                return new Response(getConfigPage(userID, trojanPassword, host, proxyIP), {
                    status: 200,
                    headers: {
                        "Content-Type": "text/html; charset=utf-8",
                        "Cache-Control": "no-cache"
                    }
                });
            }

            // Subscription endpoint
            if (path === "/sub" || path === "/subscribe") {
                return new Response(generateSubscription(userID, trojanPassword, host), {
                    status: 200,
                    headers: {
                        "Content-Type": "text/plain; charset=utf-8",
                        "Cache-Control": "no-cache"
                    }
                });
            }

            // Clash subscription
            if (path === "/clash") {
                return new Response(generateClashConfig(userID, trojanPassword, host), {
                    status: 200,
                    headers: {
                        "Content-Type": "text/plain; charset=utf-8",
                        "Cache-Control": "no-cache"
                    }
                });
            }

            // Fake nginx page for anti-detection
            if (path === "/nginx" || path === "/fake") {
                return new Response(getFakeNginxPage(), {
                    status: 200,
                    headers: { "Content-Type": "text/html; charset=utf-8" }
                });
            }

            // Default status page
            return new Response(getStatusPage(host, proxyIP), {
                status: 200,
                headers: { "Content-Type": "text/html; charset=utf-8" }
            });

        } catch (err) {
            console.error("Worker error:", err);
            return new Response(`Error: ${err.message}`, { status: 500 });
        }
    }
};

// ==================== WEBSOCKET PROXY HANDLER ====================
async function proxyOverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = "";
    let portWithRandomLog = "";

    const log = (info, event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };

    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWrapper = { value: null };
    let udpStreamWrite = null;
    let isDns = false;
    let protocol = "unknown";

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns && udpStreamWrite) {
                return udpStreamWrite(chunk);
            }
            if (remoteSocketWrapper.value) {
                const writer = remoteSocketWrapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            // Try VLESS first
            let result = processVlessHeader(chunk, userID);
            if (!result.hasError) {
                protocol = "vless";
            } else if (trojanPassword) {
                // Try Trojan if VLESS fails and password is set
                result = await processTrojanHeader(chunk, trojanPassword);
                if (!result.hasError) {
                    protocol = "trojan";
                }
            }

            if (result.hasError) {
                log(`Protocol error: ${result.message}`);
                // Don't throw - gracefully close to avoid crashing the pipe
                safeCloseWebSocket(webSocket);
                controller.error(new Error(result.message));
                return;
            }

            const {
                addressRemote = "",
                portRemote = 443,
                rawDataIndex,
                responseHeader,
                isUDP
            } = result;

            address = addressRemote;
            portWithRandomLog = `${portRemote} ${isUDP ? "udp" : "tcp"}`;

            if (isUDP && portRemote !== 53) {
                log("UDP proxy only enabled for DNS (port 53)");
                safeCloseWebSocket(webSocket);
                controller.error(new Error("UDP proxy only enabled for DNS (port 53)"));
                return;
            }
            if (isUDP && portRemote === 53) {
                isDns = true;
            }

            const rawClientData = chunk.slice(rawDataIndex);

            if (isDns) {
                const { write } = await handleUDPOutBound(webSocket, responseHeader, log);
                udpStreamWrite = write;
                udpStreamWrite(rawClientData);
                return;
            }

            handleTCPOutBound(remoteSocketWrapper, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log);
        },
        close() {
            log("WebSocket stream closed");
        },
        abort(reason) {
            log("WebSocket stream aborted", JSON.stringify(reason));
        }
    })).catch((err) => {
        log("WebSocket pipeTo error", err);
    });

    return new Response(null, { status: 101, webSocket: client });
}

// ==================== TCP OUTBOUND HANDLER ====================
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log) {
    async function connectAndWrite(address, port) {
        const tcpSocket = connect({ hostname: address, port });
        remoteSocket.value = tcpSocket;
        log(`Connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function retry() {
        const target = proxyIP || addressRemote;
        const tcpSocket = await connectAndWrite(target, portRemote);
        tcpSocket.closed.catch((error) => {
            console.log("Retry tcpSocket closed error", error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        });
        remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
    }

    try {
        const tcpSocket = await connectAndWrite(addressRemote, portRemote);
        remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
    } catch (error) {
        log(`Initial connection failed: ${error.message}, trying proxyIP...`);
        if (proxyIP) {
            try {
                const tcpSocket = await connectAndWrite(proxyIP, portRemote);
                remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
            } catch (proxyError) {
                log(`ProxyIP connection also failed: ${proxyError.message}`);
                safeCloseWebSocket(webSocket);
            }
        } else {
            safeCloseWebSocket(webSocket);
        }
    }
}

// ==================== READABLE WEBSOCKET STREAM ====================
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    return new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                // CRITICAL FIX: Check if stream is cancelled before enqueuing
                if (readableStreamCancel) {
                    return;
                }
                controller.enqueue(event.data);
            });

            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });

            webSocketServer.addEventListener("error", (err) => {
                log("WebSocket error");
                controller.error(err);
            });

            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },

        pull(controller) {
            // Backpressure handling placeholder
        },

        cancel(reason) {
            if (readableStreamCancel) {
                return;
            }
            log(`ReadableStream canceled: ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });
}

// ==================== VLESS HEADER PROCESSOR ====================
function processVlessHeader(vlessBuffer, userID) {
    if (vlessBuffer.byteLength < 24) {
        return { hasError: true, message: "Invalid VLESS data: too short" };
    }

    const version = new Uint8Array(vlessBuffer.slice(0, 1));
    const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
    const slicedBufferString = stringify(slicedBuffer);

    // Support multiple UUIDs
    const uuids = userID.includes(",") ? userID.split(",") : [userID];
    const isValidUser = uuids.some((userUuid) => slicedBufferString === userUuid.trim());

    if (!isValidUser) {
        return { hasError: true, message: "Invalid VLESS user" };
    }

    const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
    const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

    let isUDP = false;
    if (command === 1) {
        isUDP = false;
    } else if (command === 2) {
        isUDP = true;
    } else {
        return { hasError: true, message: `VLESS command ${command} not supported` };
    }

    const portIndex = 18 + optLength + 1;
    const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressType = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1))[0];

    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = "";

    switch (addressType) {
        case 1: // IPv4
            addressLength = 4;
            addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;
        case 2: // Domain
            addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3: // IPv6
            addressLength = 16;
            const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `Invalid VLESS address type ${addressType}` };
    }

    if (!addressValue) {
        return { hasError: true, message: "VLESS address value is empty" };
    }

    // VLESS response header: [version, 0]
    const responseHeader = new Uint8Array([version[0], 0]);
    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        responseHeader,
        isUDP
    };
}

// ==================== TROJAN HEADER PROCESSOR ====================
async function processTrojanHeader(buffer, password) {
    if (buffer.byteLength < 56) {
        return { hasError: true, message: "Invalid Trojan data: too short" };
    }

    // CRITICAL FIX: Decode hex string as TEXT, not as binary-to-hex
    const passwordHex = new TextDecoder().decode(buffer.slice(0, 56));

    // Validate hex format
    if (!/^[0-9a-f]{56}$/i.test(passwordHex)) {
        return { hasError: true, message: "Invalid Trojan password format" };
    }

    // CRITICAL FIX: Use proper SHA-224, not truncated SHA-256
    const expectedHex = await sha224(password);

    if (passwordHex.toLowerCase() !== expectedHex.toLowerCase()) {
        return { hasError: true, message: "Invalid Trojan password" };
    }

    let cursor = 56;
    const crlf1 = new Uint8Array(buffer.slice(cursor, cursor + 2));
    if (crlf1[0] !== 0x0D || crlf1[1] !== 0x0A) {
        return { hasError: true, message: "Invalid Trojan CRLF after password" };
    }
    cursor += 2;

    const addressType = new Uint8Array(buffer.slice(cursor, cursor + 1))[0];
    cursor += 1;

    let addressRemote = "";
    let addressLength = 0;

    switch (addressType) {
        case 1: // IPv4
            addressLength = 4;
            addressRemote = new Uint8Array(buffer.slice(cursor, cursor + addressLength)).join(".");
            break;
        case 3: // Domain
            addressLength = new Uint8Array(buffer.slice(cursor, cursor + 1))[0];
            cursor += 1;
            addressRemote = new TextDecoder().decode(buffer.slice(cursor, cursor + addressLength));
            break;
        case 4: // IPv6
            addressLength = 16;
            const dataView = new DataView(buffer.slice(cursor, cursor + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressRemote = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `Invalid Trojan address type ${addressType}` };
    }

    cursor += addressLength;
    const portRemote = new DataView(buffer.slice(cursor, cursor + 2)).getUint16(0);
    cursor += 2;

    // Final CRLF
    const crlf2 = new Uint8Array(buffer.slice(cursor, cursor + 2));
    if (crlf2[0] !== 0x0D || crlf2[1] !== 0x0A) {
        return { hasError: true, message: "Invalid Trojan final CRLF" };
    }
    cursor += 2;

    // Trojan has no response header (empty)
    const responseHeader = new Uint8Array(0);
    return {
        hasError: false,
        addressRemote,
        addressType,
        portRemote,
        rawDataIndex: cursor,
        responseHeader,
        isUDP: false
    };
}

// ==================== SHA-224 IMPLEMENTATION ====================
// Proper SHA-224 (not truncated SHA-256)
// Required because Web Crypto API does not support SHA-224
async function sha224(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);

    // SHA-224 initial hash values (different from SHA-256)
    let h0 = 0xc1059ed8, h1 = 0x367cd507, h2 = 0x3070dd17, h3 = 0xf70e5939;
    let h4 = 0xffc00b31, h5 = 0x68581511, h6 = 0x64f98fa7, h7 = 0xbefa4fa4;

    // SHA-256 constants
    const k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
    function shr(x, n) { return x >>> n; }
    function ch(x, y, z) { return (x & y) ^ (~x & z); }
    function maj(x, y, z) { return (x & y) ^ (x & z) ^ (y & z); }
    function ep0(x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    function ep1(x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    function sig0(x) { return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3); }
    function sig1(x) { return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10); }

    // Pre-processing
    const bitLen = data.length * 8;
    const msg = new Uint8Array(data.length + 1 + ((119 - (data.length % 64)) % 64) + 8);
    msg.set(data);
    msg[data.length] = 0x80;
    const view = new DataView(msg.buffer);
    view.setUint32(msg.length - 4, bitLen, false);

    // Process message in 512-bit chunks
    for (let i = 0; i < msg.length; i += 64) {
        const w = new Array(64);
        for (let t = 0; t < 16; t++) {
            w[t] = view.getUint32(i + t * 4, false);
        }
        for (let t = 16; t < 64; t++) {
            w[t] = (sig1(w[t - 2]) + w[t - 7] + sig0(w[t - 15]) + w[t - 16]) >>> 0;
        }

        let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

        for (let t = 0; t < 64; t++) {
            const t1 = (h + ep1(e) + ch(e, f, g) + k[t] + w[t]) >>> 0;
            const t2 = (ep0(a) + maj(a, b, c)) >>> 0;
            h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
        }

        h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }

    // SHA-224 output is first 28 bytes (7 words)
    const hash = new Uint8Array(28);
    const hashView = new DataView(hash.buffer);
    hashView.setUint32(0, h0, false);
    hashView.setUint32(4, h1, false);
    hashView.setUint32(8, h2, false);
    hashView.setUint32(12, h3, false);
    hashView.setUint32(16, h4, false);
    hashView.setUint32(20, h5, false);
    hashView.setUint32(24, h6, false);

    return Array.from(hash).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ==================== REMOTE SOCKET TO WEBSOCKET ====================
async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
    let header = responseHeader;
    let hasIncomingData = false;

    await remoteSocket.readable.pipeTo(new WritableStream({
        async write(chunk, controller) {
            hasIncomingData = true;
            if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                controller.error("WebSocket not open");
                return; // CRITICAL FIX: Return after error
            }
            if (header && header.byteLength > 0) {
                webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                header = null;
            } else {
                webSocket.send(chunk);
            }
        },
        close() {
            log(`Remote connection closed (had data: ${hasIncomingData})`);
        },
        abort(reason) {
            console.error("Remote readable abort", reason);
        }
    })).catch((error) => {
        console.error("remoteSocketToWS error", error.stack || error);
        safeCloseWebSocket(webSocket);
    });

    if (hasIncomingData === false && retry) {
        log("Retrying connection...");
        retry();
    }
}

// ==================== BASE64 TO ARRAYBUFFER ====================
function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { earlyData: null, error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
        const decode = atob(base64Str);
        const arrayBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arrayBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: null, error };
    }
}

// ==================== UUID HELPERS ====================
const byteToHex = [];
for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
    return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
        byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
        byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
        byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
        byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!isValidUUID(uuid)) {
        throw new TypeError("Stringified UUID is invalid");
    }
    return uuid;
}

// ==================== SAFE WEBSOCKET CLOSE ====================
function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error("safeCloseWebSocket error", error);
    }
}

// ==================== UDP / DNS HANDLER ====================
async function handleUDPOutBound(webSocket, responseHeader, log) {
    let isHeaderSent = false;
    const transformStream = new TransformStream({
        transform(chunk, controller) {
            for (let index = 0; index < chunk.byteLength;) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
                index = index + 2 + udpPacketLength;
                controller.enqueue(udpData);
            }
        },
        flush(controller) {}
    });

    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            const resp = await fetch(dohURL, {
                method: "POST",
                headers: { "content-type": "application/dns-message" },
                body: chunk
            });
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([udpSize >> 8 & 255, udpSize & 255]);

            if (webSocket.readyState === WS_READY_STATE_OPEN) {
                log(`DoH success, DNS message length: ${udpSize}`);
                if (isHeaderSent) {
                    webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                } else {
                    webSocket.send(await new Blob([responseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                    isHeaderSent = true;
                }
            }
        }
    })).catch((error) => {
        log("DNS UDP error: " + error);
    });

    const writer = transformStream.writable.getWriter();
    return { write: (chunk) => writer.write(chunk) };
}

// ==================== SUBSCRIPTION GENERATORS ====================
function generateSubscription(userID, trojanPassword, hostName) {
    let sub = "";

    // VLESS links for all CF ports
    for (const port of CF_PORTS) {
        const isTLS = [443, 8443, 2053, 2096, 2087, 2083].includes(port);
        const security = isTLS ? "tls" : "none";
        const vlessLink = `vless://${userID}@${hostName}:${port}?encryption=none&security=${security}&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#VLESS-${hostName}-${port}`;
        sub += vlessLink + "\n";
    }

    // Trojan links
    if (trojanPassword) {
        for (const port of CF_PORTS) {
            const isTLS = [443, 8443, 2053, 2096, 2087, 2083].includes(port);
            const security = isTLS ? "tls" : "none";
            const trojanLink = `trojan://${trojanPassword}@${hostName}:${port}?security=${security}&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#Trojan-${hostName}-${port}`;
            sub += trojanLink + "\n";
        }
    }

    return sub;
}

function generateClashConfig(userID, trojanPassword, hostName) {
    let proxies = "";
    let names = [];

    for (const port of CF_PORTS) {
        const isTLS = [443, 8443, 2053, 2096, 2087, 2083].includes(port);
        const name = `VLESS-${hostName}-${port}`;
        names.push(name);
        proxies += `  - {name: "${name}", server: ${hostName}, port: ${port}, type: vless, uuid: ${userID}, network: ws, tls: ${isTLS}, udp: false, sni: ${hostName}, client-fingerprint: chrome, ws-opts: {path: "/?ed=2048", headers: {Host: ${hostName}}}}\n`;
    }

    if (trojanPassword) {
        for (const port of CF_PORTS) {
            const isTLS = [443, 8443, 2053, 2096, 2087, 2083].includes(port);
            const name = `Trojan-${hostName}-${port}`;
            names.push(name);
            proxies += `  - {name: "${name}", server: ${hostName}, port: ${port}, type: trojan, password: ${trojanPassword}, network: ws, tls: ${isTLS}, udp: false, sni: ${hostName}, client-fingerprint: chrome, ws-opts: {path: "/?ed=2048", headers: {Host: ${hostName}}}}\n`;
        }
    }

    return `proxies:\n${proxies}proxy-groups:\n  - {name: "Auto", type: url-test, proxies: [${names.map(n => `"${n}"`).join(", ")}], url: "http://www.gstatic.com/generate_204", interval: 86400}\n  - {name: "Proxy", type: select, proxies: ["Auto", ${names.map(n => `"${n}"`).join(", ")}]}\n`;
}

// ==================== HTML PAGES ====================
function getConfigPage(userID, trojanPassword, hostName, proxyIP) {
    const vlessLink = `vless://${userID}@${hostName}:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#VLESS-${hostName}`;
    const trojanLink = trojanPassword ? `trojan://${trojanPassword}@${hostName}:443?security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#Trojan-${hostName}` : "";

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VLESS + Trojan Config</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; 
            max-width: 900px; 
            margin: 0 auto; 
            padding: 20px; 
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); 
            color: #e2e8f0; 
            min-height: 100vh;
        }
        h1 { color: #38bdf8; margin-bottom: 10px; font-size: 28px; }
        h2 { color: #818cf8; border-bottom: 1px solid #334155; padding-bottom: 8px; margin: 25px 0 15px; font-size: 20px; }
        .subtitle { color: #94a3b8; margin-bottom: 20px; font-size: 14px; }
        .status { padding: 12px 16px; border-radius: 8px; margin-bottom: 20px; font-weight: 500; }
        .status.ok { background: rgba(74, 222, 128, 0.1); color: #4ade80; border: 1px solid rgba(74, 222, 128, 0.3); }
        .status.warn { background: rgba(251, 191, 36, 0.1); color: #fbbf24; border: 1px solid rgba(251, 191, 36, 0.3); }
        pre { 
            background: #1e293b; 
            padding: 14px; 
            border-radius: 8px; 
            overflow-x: auto; 
            word-wrap: break-word; 
            white-space: pre-wrap; 
            border: 1px solid #334155;
            font-size: 13px;
            line-height: 1.5;
            position: relative;
        }
        .copy-btn {
            position: absolute;
            top: 8px;
            right: 8px;
            background: #334155;
            color: #e2e8f0;
            border: none;
            padding: 4px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            transition: background 0.2s;
        }
        .copy-btn:hover { background: #475569; }
        ul { line-height: 2; list-style: none; padding: 0; }
        li { padding: 4px 0; border-bottom: 1px solid #1e293b; }
        li:last-child { border-bottom: none; }
        code { background: #334155; padding: 2px 6px; border-radius: 4px; font-size: 13px; color: #38bdf8; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        @media (max-width: 768px) { .grid { grid-template-columns: 1fr; } }
        .card { background: rgba(30, 41, 59, 0.5); padding: 20px; border-radius: 12px; border: 1px solid #334155; }
        .ports { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
        .port { background: #334155; padding: 4px 10px; border-radius: 4px; font-size: 12px; color: #94a3b8; }
        .port.tls { background: rgba(74, 222, 128, 0.1); color: #4ade80; }
        a { color: #38bdf8; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>🚀 VLESS + Trojan Worker</h1>
    <p class="subtitle">Clean proxy implementation - All websites supported, Speedtest ready</p>

    <div class="status ${proxyIP ? 'ok' : 'warn'}">
        ${proxyIP ? "✅ ProxyIP Active: " + proxyIP : "⚠️ Direct Connection (No ProxyIP set - some sites may be blocked)"}
    </div>

    <div class="grid">
        <div class="card">
            <h2>VLESS Connection</h2>
            <pre id="vless-link">${vlessLink}<button class="copy-btn" onclick="copyToClipboard('vless-link')">Copy</button></pre>

            <h2>Manual VLESS Config</h2>
            <ul>
                <li><strong>Address:</strong> <code>${hostName}</code></li>
                <li><strong>Port:</strong> <code>443</code> (or other CF ports)</li>
                <li><strong>UUID:</strong> <code>${userID}</code></li>
                <li><strong>Security:</strong> <code>TLS</code></li>
                <li><strong>SNI:</strong> <code>${hostName}</code></li>
                <li><strong>Network:</strong> <code>WebSocket (WS)</code></li>
                <li><strong>Path:</strong> <code>/?ed=2048</code></li>
                <li><strong>Host:</strong> <code>${hostName}</code></li>
            </ul>
        </div>

        <div class="card">
            <h2>Trojan Connection</h2>
            ${trojanLink ? `<pre id="trojan-link">${trojanLink}<button class="copy-btn" onclick="copyToClipboard('trojan-link')">Copy</button></pre>` : '<p style="color:#fbbf24">Trojan password not set</p>'}

            <h2>Supported Ports</h2>
            <div class="ports">
                ${CF_PORTS.map(p => {
                    const isTLS = [443, 8443, 2053, 2096, 2087, 2083].includes(p);
                    return `<span class="port ${isTLS ? 'tls' : ''}">${p}${isTLS ? ' 🔒' : ''}</span>`;
                }).join('')}
            </div>

            <h2>Quick Links</h2>
            <ul>
                <li>📋 <a href="/sub">Subscription (All Ports)</a></li>
                <li>⚔️ <a href="/clash">Clash Config</a></li>
                <li>🌐 <a href="/nginx">Fake Nginx Page</a></li>
            </ul>
        </div>
    </div>

    <script>
        function copyToClipboard(id) {
            const el = document.getElementById(id);
            const text = el.childNodes[0].textContent.trim();
            navigator.clipboard.writeText(text).then(() => {
                const btn = el.querySelector('.copy-btn');
                btn.textContent = 'Copied!';
                setTimeout(() => btn.textContent = 'Copy', 2000);
            });
        }
    </script>
</body>
</html>`;
}

function getStatusPage(hostName, proxyIP) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Status - VLESS/Trojan Worker</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; 
            max-width: 600px; 
            margin: 50px auto; 
            text-align: center; 
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); 
            color: #e2e8f0; 
            min-height: 100vh;
            padding: 20px;
        }
        .ok { color: #4ade80; font-size: 48px; margin-bottom: 10px; }
        h1 { color: #e2e8f0; margin-bottom: 10px; }
        p { color: #94a3b8; line-height: 1.8; }
        code { background: #334155; padding: 2px 8px; border-radius: 4px; color: #38bdf8; }
        .card { background: rgba(30, 41, 59, 0.5); padding: 30px; border-radius: 16px; border: 1px solid #334155; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="ok">✅</div>
        <h1>Worker is Running</h1>
        <p>Host: <strong>${hostName}</strong></p>
        <p>ProxyIP: <strong>${proxyIP || "Direct"}</strong></p>
        <p>Visit <code>/${userID}</code> or <code>/config</code> for connection links.</p>
        <p style="margin-top: 20px; font-size: 12px; color: #64748b;">
            All systems operational. WebSocket proxy ready.<br>
            Supports VLESS + Trojan protocols.
        </p>
    </div>
</body>
</html>`;
}

function getFakeNginxPage() {
    return `<!DOCTYPE html>
<html>
<head>
    <title>Welcome to nginx!</title>
    <style>
        html { color-scheme: light dark; }
        body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
    </style>
</head>
<body>
    <h1>Welcome to nginx!</h1>
    <p>If you see this page, the nginx web server is successfully installed and
    working. Further configuration is required.</p>
    <p>For online documentation and support please refer to
    <a href="http://nginx.org/">nginx.org</a>.<br/>
    Commercial support is available at
    <a href="http://nginx.com/">nginx.com</a>.</p>
    <p><em>Thank you for using nginx.</em></p>
</body>
</html>`;
}

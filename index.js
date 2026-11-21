
import { DurableObject } from "cloudflare:workers";

const PROJECT_ID = "vyra-f251a";
const ALLOWED_ORIGIN = "https://vyra-f251a.web.app";
const INVITE_TTL = 10 * 60 * 1000;                     
let cachedKeys = null;

function randomToken(bytes = 32) {
    const data = crypto.getRandomValues(new Uint8Array(bytes));
    return btoa(String.fromCharCode(...data))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

async function hash(value) {
    const data = new TextEncoder().encode(value);
    const digest = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(digest))
        .map(x => x.toString(16).padStart(2, "0"))
        .join("");
}

async function firebaseTokenVerify(token) {
    const parts = token.split(".");
    if (parts.length !== 3) throw new Error("Geçersiz token.");

    const decode = value => {
        const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
        const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
        return JSON.parse(
            new TextDecoder().decode(
                Uint8Array.from(atob(padded), c => c.charCodeAt(0))                                                       )                                                  );                                                 };
                                                           const header = decode(parts[0]);
    const claims = decode(parts[1]);

    if (                                                       header.alg !== "RS256" ||
        !header.kid ||
        claims.aud !== PROJECT_ID ||
        claims.iss !== `https://securetoken.google.com/${PROJECT_ID}` ||                                              !claims.sub ||
        claims.sub.length > 128 ||
        claims.exp <= Math.floor(Date.now() / 1000)
    ) {
        throw new Error("Firebase kimliği geçersiz.");
    }                                                  
    if (!cachedKeys || cachedKeys.expires < Date.now()) {
        const response = await fetch(
            "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"               );
        if (!response.ok) throw new Error("Kimlik anahtarları alınamadı.");
                                                               cachedKeys = {
            keys: (await response.json()).keys,
            expires: Date.now() + 3600000                      };
    }

    const jwk = cachedKeys.keys.find(key => key.kid === header.kid);
    if (!jwk) throw new Error("İmza anahtarı bulunamadı.");

    const key = await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"]
    );

    const signature = Uint8Array.from(
        atob(parts[2].replace(/-/g, "+").replace(/_/g, "/") +
            "=".repeat((4 - parts[2].length % 4) % 4)),
        c => c.charCodeAt(0)
    );

    const valid = await crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        key,                                                   signature,
        new TextEncoder().encode(parts[0] + "." + parts[1])                                                       );

    if (!valid) throw new Error("Token imzası geçersiz.");
    return claims.sub;
}
                                                       export class CallRoom extends DurableObject {
    constructor(ctx, env) {
        super(ctx, env);                                       this.ctx = ctx;
    }

    async fetch(request) {
        if (request.method === "POST" && new URL(request.url).pathname === "/invite") {
            const uid = request.headers.get("X-Vyra-User");
            if (!uid) return new Response("Yetkisiz.", { status: 401 });                                      
            const existing = await this.ctx.storage.get("room");
            if (existing && existing.expiresAt > Date.now()) {
                return Response.json(
                    { error: "Bu oda için davet zaten oluşturulmuş." },
                    { status: 409 }
                );                                                 }

            const inviteKey = randomToken(32);
            const room = {
                ownerUid: uid,
                inviteHash: await hash(inviteKey),
                expiresAt: Date.now() + INVITE_TTL,
                guestUid: null
            };

            await this.ctx.storage.put("room", room);
                                                                   return Response.json({
                ok: true,
                inviteKey,
                expiresAt: room.expiresAt                          });
        }

        if (request.headers.get("Upgrade") !== "websocket") {
            return new Response("WebSocket gerekli.", { status: 426 });
        }
                                                               const uid = request.headers.get("X-Vyra-User");
        const inviteKey = request.headers.get("X-Vyra-Invite");

        if (!uid || !inviteKey) {
            return new Response("Yetkisiz.", { status: 401 });
        }                                              
        const room = await this.ctx.storage.get("room");
        if (!room || room.expiresAt <= Date.now()) {
            return new Response("Davet geçersiz veya süresi dolmuş.", { status: 403 });                               }

        if (await hash(inviteKey) !== room.inviteHash) {                                                                  return new Response("Davet anahtarı hatalı.", { status: 403 });                                           }

        if (uid !== room.ownerUid) {
            if (uid === room.ownerUid) {
                return new Response("Geçersiz katılımcı.", { status: 403 });
            }                                                      if (room.guestUid && room.guestUid !== uid) {                                                                     return new Response("Oda başka bir kullanıcıya ayrılmış.", { status: 409 });
            }
            room.guestUid = uid;
            await this.ctx.storage.put("room", room);          }                                              
        const connections = this.ctx.getWebSockets();                                                                 if (connections.some(socket =>
            socket.deserializeAttachment()?.uid === uid        )) {
            return new Response("Bu kullanıcı zaten bağlı.", { status: 409 });
        }
                                                               if (connections.length >= 2) {
            return new Response("Görüşme odası dolu.", { status: 409 });
        }

        if (uid !== room.ownerUid && !connections.some(socket =>                                                          socket.deserializeAttachment()?.uid === room.ownerUid
        )) {                                                       return new Response("Önce görüşmeyi başlatan kullanıcı bağlanmalı.", {
                status: 409                                        });
        }

        const pair = new WebSocketPair();
        const client = pair[0];
        const server = pair[1];

        this.ctx.acceptWebSocket(server);                      server.serializeAttachment({ uid });

        return new Response(null, {                                status: 101,
            webSocket: client,
            headers: { "Sec-WebSocket-Protocol": "vyra" }
        });
    }

    async webSocketMessage(sender, message) {
        if (typeof message !== "string" || message.length > 65536) {
            sender.close(1009, "Mesaj çok büyük.");                return;
        }

        let payload;
        try {
            payload = JSON.parse(message);
        } catch {
            sender.close(1003, "Geçersiz mesaj.");
            return;
        }

        if (
            !payload ||
            !["offer", "answer", "ice-candidate"].includes(payload.type) ||
            !payload.data ||
            typeof payload.data !== "object"
        ) {
            sender.close(1008, "Geçersiz sinyal.");
            return;
        }

        for (const socket of this.ctx.getWebSockets()) {
            if (socket !== sender && socket.readyState === 1) {
                socket.send(JSON.stringify(payload));
            }
        }
    }
                                                           async webSocketClose(socket, code, reason) {
        socket.close(code, reason);
    }                                                  
    async webSocketError(socket) {
        socket.close(1011, "Bağlantı hatası.");            }
}

export default {
    async fetch(request, env) {
        const url = new URL(request.url);              
        if (url.pathname === "/health") {                          return Response.json({
                ok: true,
                service: "vyra-webrtc",
                status: "healthy"
            });                                                }
                                                               if (url.pathname === "/invite" && request.method === "POST") {
            if (request.headers.get("Origin") !== ALLOWED_ORIGIN) {
                return new Response("Origin reddedildi.", { status: 403 });
            }

            const auth = request.headers.get("Authorization") || "";                                                      if (!auth.startsWith("Bearer ")) {
                return new Response("Kimlik doğrulama gerekli.", { status: 401 });                                        }

            try {                                                      const uid = await firebaseTokenVerify(auth.slice(7));                                                         const callId = randomToken(18);
                const id = env.CALL_ROOMS.idFromName(callId);
                const room = env.CALL_ROOMS.get(id);

                const response = await room.fetch("https://internal/invite", {
                    method: "POST",
                    headers: { "X-Vyra-User": uid }
                });                                    
                if (!response.ok) return response;

                const data = await response.json();
                return Response.json({ ...data, callId });
            } catch (error) {
                return new Response(error.message || "Yetkilendirme başarısız.", {                                                status: 403
                });
            }                                                  }

        if (!url.pathname.startsWith("/ws/")) {
            return new Response("VYRA WebRTC sunucusu", { status: 200 });
        }

        if (url.origin !== "https://" + url.host) {
            return new Response("HTTPS gerekli.", { status: 400 });
        }

        if (request.headers.get("Origin") !== ALLOWED_ORIGIN) {
            return new Response("Origin reddedildi.", { status: 403 });
        }

        if (request.headers.get("Upgrade") !== "websocket") {
            return new Response("WebSocket gerekli.", { status: 426 });
        }

        const callId = decodeURIComponent(url.pathname.slice(4));
        if (!/^[A-Za-z0-9_-]{1,150}$/.test(callId)) {
            return new Response("Geçersiz görüşme kimliği.", { status: 400 });
        }                                              
        const protocols = (request.headers.get("Sec-WebSocket-Protocol") || "")
            .split(",").map(value => value.trim());
                                                               if (protocols[0] !== "vyra" || !protocols[1] || !protocols[2]) {
            return new Response("Kimlik ve davet gerekli.", { status: 401 });
        }

        try {
            const uid = await firebaseTokenVerify(protocols[1]);
            const id = env.CALL_ROOMS.idFromName(callId);
            const room = env.CALL_ROOMS.get(id);
            const headers = new Headers(request.headers);

            headers.set("X-Vyra-User", uid);                       headers.set("X-Vyra-Invite", protocols[2]);
            headers.set("Sec-WebSocket-Protocol", "vyra");                                                    
            return await room.fetch(new Request(request, { headers }));
        } catch (error) {
            return new Response(error.message || "Yetkilendirme başarısız.", {
                status: 403
            });
        }
    }
};

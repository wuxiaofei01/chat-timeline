// 用法: node tools/build.mjs <聊天记录.txt> <密码> [输出文件=data.enc]
// 解析聊天记录 -> JSON -> gzip -> PBKDF2(SHA-256, 600k) 派生 AES-256-GCM 密钥加密
// 输出格式: magic(4) + salt(16) + iv(12) + ciphertext
import { readFileSync, writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { webcrypto, randomBytes } from 'node:crypto';

const [,, src, password, out = 'data.enc'] = process.argv;
if (!src || !password) {
  console.error('用法: node tools/build.mjs <聊天记录.txt> <密码> [输出文件]');
  process.exit(1);
}

const text = readFileSync(src, 'utf8');
const lines = text.split(/\r?\n/);

const meta = { title: '', other: '对方', range: '', note: '', exported: '' };
const days = [];
let cur = null;
const dayRe = /^──────── (\d{4}-\d{2}-\d{2}) (星期.) ────────\s*$/;
const msgRe = /^\[(\d{2}:\d{2})\] ([^：]+)：(.*)$/;

for (const line of lines) {
  if (!line.trim()) continue;
  let m;
  if ((m = dayRe.exec(line))) {
    cur = { d: m[1], w: m[2], m: [] };
    days.push(cur);
    continue;
  }
  if ((m = msgRe.exec(line)) && cur) {
    const sender = m[2];
    const self = sender === '我' ? 0 : 1;
    if (self === 1 && meta.other === '对方') meta.other = sender;
    cur.m.push([m[1], self, m[3]]);
    continue;
  }
  if (!cur) {
    if (line.startsWith('小红书聊天记录')) { meta.title = line; const t = /「(.+?)」/.exec(line); if (t) meta.other = t[1]; }
    else if (line.startsWith('时间范围：')) meta.range = line.slice('时间范围：'.length);
    else if (line.startsWith('说明：')) meta.note = line.slice('说明：'.length);
    else if (line.startsWith('导出时间：')) meta.exported = line.slice('导出时间：'.length);
    continue;
  }
  console.warn('未识别的行:', line.slice(0, 80));
}

days.sort((a, b) => a.d.localeCompare(b.d));
const total = days.reduce((n, d) => n + d.m.length, 0);
const mine = days.reduce((n, d) => n + d.m.filter(x => x[1] === 0).length, 0);
const voice = days.reduce((n, d) => n + d.m.filter(x => /^\[语音 \d+秒\]/.test(x[2])).length, 0);
const payload = { meta, stats: { total, mine, theirs: total - mine, voice, days: days.length }, days };

const json = Buffer.from(JSON.stringify(payload), 'utf8');
const gz = gzipSync(json, { level: 9 });

const salt = randomBytes(16);
const iv = randomBytes(12);
const subtle = webcrypto.subtle;
const base = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
const key = await subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
  base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = Buffer.from(await subtle.encrypt({ name: 'AES-GCM', iv }, key, gz));

writeFileSync(out, Buffer.concat([Buffer.from('XHS1'), salt, iv, ct]));
console.log(`天数 ${days.length}，消息 ${total} 条（我 ${mine} / ${meta.other} ${total - mine}），语音 ${voice} 条`);
console.log(`JSON ${(json.length/1024/1024).toFixed(2)} MB -> gzip ${(gz.length/1024/1024).toFixed(2)} MB -> 已写入 ${out}`);

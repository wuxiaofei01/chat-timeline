// 用法: node tools/update.mjs <新增聊天记录.txt> [data.enc]
// 增量更新: 用密码解密现有 data.enc，与新导出的聊天记录合并后重新加密写回。
// 密码从环境变量 CHAT_PASSWORD 读取；未设置时在终端隐藏输入（不会出现在命令历史里）。
// 合并规则: 新记录中「第一个完整的一天」及之后的日期全部以新记录为准，之前的日期保留旧数据。
import { readFileSync, writeFileSync } from 'node:fs';
import { gzipSync, gunzipSync } from 'node:zlib';
import { webcrypto, randomBytes } from 'node:crypto';

const [,, src, file = 'data.enc'] = process.argv;
if (!src) {
  console.error('用法: node tools/update.mjs <新增聊天记录.txt> [data.enc]');
  process.exit(1);
}

function askHidden(prompt) {
  return new Promise((resolve, reject) => {
    const { stdin, stderr } = process;
    if (!stdin.isTTY) return reject(new Error('请设置环境变量 CHAT_PASSWORD，或在终端中运行'));
    stderr.write(prompt);
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
    let buf = '';
    const onData = (ch) => {
      for (const c of ch) {
        if (c === '\r' || c === '\n') {
          stdin.setRawMode(false); stdin.pause(); stdin.off('data', onData);
          stderr.write('\n'); return resolve(buf);
        }
        if (c === '\u0003') { stdin.setRawMode(false); process.exit(130); }
        if (c === '\u007f' || c === '\b') buf = buf.slice(0, -1); else buf += c;
      }
    };
    stdin.on('data', onData);
  });
}

const subtle = webcrypto.subtle;
async function deriveKey(password, salt) {
  const base = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

function parse(text) {
  const meta = { title: '', other: '对方', range: '', note: '', exported: '' };
  const days = [];
  let cur = null;
  const dayRe = /^──────── (\d{4}-\d{2}-\d{2}) (星期.) ────────\s*$/;
  const msgRe = /^\[(\d{2}:\d{2})\] ([^：]+)：(.*)$/;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let m;
    if ((m = dayRe.exec(line))) { cur = { d: m[1], w: m[2], m: [] }; days.push(cur); continue; }
    if ((m = msgRe.exec(line)) && cur) {
      const self = m[2] === '我' ? 0 : 1;
      if (self === 1 && meta.other === '对方') meta.other = m[2];
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
  return { meta, days };
}

const password = process.env.CHAT_PASSWORD || await askHidden('密码: ');

// 解密现有数据
const old = readFileSync(file);
if (old.subarray(0, 4).toString() !== 'XHS1') throw new Error('data.enc 格式不对');
const key0 = await deriveKey(password, old.subarray(4, 20));
let prev;
try {
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: old.subarray(20, 32) }, key0, old.subarray(32));
  prev = JSON.parse(gunzipSync(Buffer.from(pt)).toString('utf8'));
} catch {
  console.error('解密失败：密码错误。data.enc 未改动。');
  process.exit(2);
}

// 合并
const fresh = parse(readFileSync(src, 'utf8'));
if (fresh.days.length < 2) throw new Error('新记录不足两天，无法确定完整的起始日');
const cutoff = fresh.days[1].d; // 新记录第一天可能不完整，从第二天起以新记录为准
const kept = prev.days.filter(d => d.d < cutoff);
const lastOld = prev.days.at(-1)?.d ?? '';
const prevDay = new Date(Date.parse(cutoff + 'T00:00:00Z') - 86400000).toISOString().slice(0, 10);
if (lastOld < prevDay) console.warn(`注意: 旧数据止于 ${lastOld}，新数据从 ${cutoff} 起才完整，中间可能有缺口`);
const days = [...kept, ...fresh.days.filter(d => d.d >= cutoff)];

const meta = { ...prev.meta, exported: fresh.meta.exported || prev.meta.exported };
if (days.length) meta.range = `${days[0].d} ~ ${days.at(-1).d}`;
if (meta.title) meta.title = meta.title.replace(/\d{4}-\d{2}-\d{2}\s*[~至-]\s*\d{4}-\d{2}-\d{2}/, meta.range);

const count = (f) => days.reduce((n, d) => n + d.m.filter(f).length, 0);
const total = count(() => true), mine = count(x => x[1] === 0);
const voice = count(x => /^\[语音 \d+秒\]/.test(x[2]));
const payload = { ...prev, meta, stats: { total, mine, theirs: total - mine, voice, days: days.length }, days };

// 重新加密
const gz = gzipSync(Buffer.from(JSON.stringify(payload), 'utf8'), { level: 9 });
const salt = randomBytes(16), iv = randomBytes(12);
const key = await deriveKey(password, salt);
const ct = Buffer.from(await subtle.encrypt({ name: 'AES-GCM', iv }, key, gz));
writeFileSync(file, Buffer.concat([Buffer.from('XHS1'), salt, iv, ct]));

console.log(`旧数据: ${prev.days.length} 天 / ${prev.stats?.total ?? '?'} 条，止于 ${lastOld}`);
console.log(`保留 ${cutoff} 之前的 ${kept.length} 天，写入新数据 ${days.length - kept.length} 天（${cutoff} ~ ${days.at(-1).d}）`);
console.log(`合并后: ${days.length} 天，消息 ${total} 条（我 ${mine} / ${meta.other} ${total - mine}），语音 ${voice} 条`);
console.log(`gzip ${(gz.length / 1024 / 1024).toFixed(2)} MB -> 已写入 ${file}`);

// 관리자 페이지용 GitHub 토큰을 관리자 아이디·비밀번호로 암호화해 admin-key.json 으로 저장한다.
// 사용법 (Windows):
//   1) GitHub 에서 kerygma 저장소 Contents 읽기/쓰기 권한만 가진 fine-grained 토큰을 만들고 복사
//   2) KERYGMA_ADMIN_ID / KERYGMA_ADMIN_PW 환경 변수를 넣고 실행 → 클립보드의 토큰을 읽어 암호화
//      (토큰을 직접 넘기려면 KERYGMA_TOKEN 환경 변수 사용)
// 비밀번호·토큰은 이 파일이나 저장소에 절대 적지 않는다.
import { webcrypto as crypto } from 'node:crypto';
import { execSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const REPO = 'forzamin521-a11y/kerygma';
const ITER = 600000;

const id = process.env.KERYGMA_ADMIN_ID;
const pw = process.env.KERYGMA_ADMIN_PW;
if (!id || !pw) { console.error('KERYGMA_ADMIN_ID, KERYGMA_ADMIN_PW 환경 변수가 필요합니다.'); process.exit(1); }

let token = process.env.KERYGMA_TOKEN;
if (!token) token = execSync('powershell -NoProfile -Command Get-Clipboard', { encoding: 'utf8' });
token = token.trim();
if (!/^(github_pat_|ghp_)[A-Za-z0-9_]+$/.test(token)) { console.error('클립보드에 GitHub 토큰이 없습니다.'); process.exit(1); }

// 토큰이 이 저장소에 쓸 수 있는지 확인
const res = await fetch(`https://api.github.com/repos/${REPO}`, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' } });
const repo = await res.json();
if (!res.ok || !repo.permissions?.push) { console.error('이 토큰으로 저장소에 쓸 수 없습니다:', res.status, repo.message || ''); process.exit(1); }

const enc = new TextEncoder();
const b64 = u8 => Buffer.from(u8).toString('base64');
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', enc.encode(`${id}:${pw}`.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITER }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(token)));

const out = fileURLToPath(new URL('../admin-key.json', import.meta.url));
writeFileSync(out, JSON.stringify({ v: 1, iter: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct) }, null, 2) + '\n');
console.log('admin-key.json 저장 완료 (토큰 확인됨)');

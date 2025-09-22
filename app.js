/* ছোট টোট-লজিক: Base32 decode ও TOTP না — এখানে আমরা সরল ভাবে Base32 থেকে key নেবো এবং SubtleCrypto দিয়ে TOTP করে দেখাবো */

function base32ToBytes(b32){
  if(!b32) return new Uint8Array();
  b32 = b32.replace(/=+$/,'').replace(/\s+/g,'').toUpperCase();
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0;
  const out = [];
  for(let i=0;i<b32.length;i++){
    const idx = alphabet.indexOf(b32[i]);
    if(idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if(bits >= 8){
      bits -= 8;
      out.push((value >>> bits) & 0xFF);
    }
  }
  return new Uint8Array(out);
}
function intToBytes(num){
  const bytes = new Uint8Array(8);
  for(let i=7;i>=0;i--){
    bytes[i] = num & 0xff;
    num = num >> 8;
  }
  return bytes;
}
async function hmacSha1(keyBytes, msgBytes){
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, {name:"HMAC", hash:"SHA-1"}, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, msgBytes);
  return new Uint8Array(sig);
}
async function generateTOTP(base32secret, digits=6, period=30){
  const key = base32ToBytes(base32secret);
  if(!key || key.length===0) return null;
  const now = Math.floor(Date.now()/1000);
  const counter = Math.floor(now / period);
  const counterBytes = intToBytes(counter);
  const hmac = await hmacSha1(key, counterBytes);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset+1] & 0xff) << 16) | ((hmac[offset+2] & 0xff) << 8) | (hmac[offset+3] & 0xff);
  const otp = (code % (10 ** digits)).toString().padStart(digits,'0');
  return {otp, now, counter};
}

/* LocalStorage helpers */
const STORAGE_KEY = '2fa_zone_v2_bn';
function loadAccounts(){ try{ const raw = localStorage.getItem(STORAGE_KEY); return raw ? JSON.parse(raw) : []; }catch(e){ return []; } }
function saveAccounts(list){ localStorage.setItem(STORAGE_KEY, JSON.stringify(list)); }

/* UI refs */
const labelEl = document.getElementById('label');
const secretEl = document.getElementById('secret');
const digitsEl = document.getElementById('digits');
const periodEl = document.getElementById('period');
const genNow = document.getElementById('genNow');
const saveBtn = document.getElementById('saveBtn');
const listEl = document.getElementById('list');
const acctTpl = document.getElementById('acctTpl');
const countEl = document.getElementById('count');
const refreshAll = document.getElementById('refreshAll');
const deleteAll = document.getElementById('deleteAll');
const exportBtn = document.getElementById('exportBtn');
const importBtn = document.getElementById('importBtn');
const importFile = document.getElementById('importFile');

let accounts = loadAccounts();

/* render */
function renderList(){
  listEl.innerHTML = '';
  countEl.textContent = accounts.length;
  accounts.forEach((acc, idx) => {
    const node = acctTpl.content.cloneNode(true);
    const accountEl = node.querySelector('.account');
    const avatar = node.querySelector('.avatar');
    const lbl = node.querySelector('.label');
    const secretMask = node.querySelector('.secretMask');
    const codeEl = node.querySelector('.code');
    const timeLeftEl = node.querySelector('.timeLeft');
    const barEl = node.querySelector('.bar');
    const copyBtn = node.querySelector('.copyBtn');
    const delBtn = node.querySelector('.delBtn');

    avatar.textContent = (acc.label && acc.label[0]) ? acc.label[0].toUpperCase() : 'A';
    lbl.textContent = acc.label || 'Account';
    secretMask.textContent = acc.secret ? acc.secret.replace(/.(?=.{4})/g,'*') : '—';

    // generate code and UI
    (async ()=>{
      const res = await generateTOTP(acc.secret, acc.digits || 6, acc.period || 30);
      if(res){
        codeEl.textContent = res.otp;
        // tap code to copy
        codeEl.style.cursor = 'pointer';
        codeEl.onclick = async ()=> {
          try{ await navigator.clipboard.writeText(res.otp); codeEl.textContent = 'Copied'; setTimeout(()=> codeEl.textContent = res.otp,900); }catch(e){ alert('কপি ব্যর্থ'); }
        };
        // progress & time
        const nowMs = Date.now();
        const ms = nowMs % ((acc.period||30)*1000);
        const left = Math.ceil(((acc.period||30)*1000 - ms)/1000);
        timeLeftEl.textContent = left + 's';
        barEl.style.width = (((acc.period||30)*1000 - ms) / ((acc.period||30)*1000) * 100) + '%';
      } else {
        codeEl.textContent = 'Inv';
        timeLeftEl.textContent = '-';
        barEl.style.width = '0%';
      }
    })();

    copyBtn.addEventListener('click', async ()=>{
      const res = await generateTOTP(acc.secret, acc.digits || 6, acc.period || 30);
      if(res){ try{ await navigator.clipboard.writeText(res.otp); copyBtn.textContent='Copied'; setTimeout(()=>copyBtn.textContent='Copy',900); }catch(e){ alert('Copy failed'); } } else alert('Invalid secret');
    });

    delBtn.addEventListener('click', ()=>{
      if(!confirm('Delete this account?')) return;
      accounts.splice(idx,1);
      saveAccounts(accounts);
      renderList();
    });

    listEl.appendChild(node);
  });
}

/* ticker */
let tick = null;
function startTicker(){ if(tick) clearInterval(tick); tick = setInterval(()=> renderList(), 1000); renderList(); }

/* actions */
genNow.addEventListener('click', async ()=>{
  const s = secretEl.value.trim();
  if(!s){ alert('Enter secret'); return; }
  const d = parseInt(digitsEl.value,10);
  const p = parseInt(periodEl.value,10);
  const res = await generateTOTP(s, d, p);
  if(!res){ alert('Invalid secret'); return; }
  try{ await navigator.clipboard.writeText(res.otp); alert('কোড: ' + res.otp + '\\n(কপি করা হয়েছে)'); }catch(e){ alert('কোড: ' + res.otp); }
});

saveBtn.addEventListener('click', ()=>{
  const s = secretEl.value.trim(); if(!s){ alert('Enter secret'); return; }
  const lbl = labelEl.value.trim(); const d = parseInt(digitsEl.value,10); const p = parseInt(periodEl.value,10);
  accounts.push({label: lbl, secret: s.replace(/\\s+/g,''), digits: d, period: p});
  saveAccounts(accounts); labelEl.value=''; secretEl.value=''; renderList();
});

/* clear input */
document.getElementById('clearBtn').addEventListener('click', ()=>{
  labelEl.value=''; secretEl.value=''; digitsEl.value='6'; periodEl.value='30';
});

/* refresh & delete all */
refreshAll.addEventListener('click', ()=> renderList());
deleteAll.addEventListener('click', ()=>{
  if(!confirm('সব সেভ করা অ্যাকাউন্ট মুছে ফেলতে চান?')) return;
  accounts = []; saveAccounts(accounts); renderList();
});

/* export CSV */
exportBtn.addEventListener('click', ()=>{
  if(accounts.length===0){ alert('কোনো অ্যাকাউন্ট নেই'); return; }
  const rows = [['label','secret','digits','period']].concat(accounts.map(a=>[a.label||'','"' + (a.secret||'') + '"', a.digits||6, a.period||30]));
  const csv = rows.map(r=>r.join(',')).join('\\n');
  const blob = new Blob([csv],{type:'text/csv;charset=utf-8;'});
  const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = '2fa_accounts.csv'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
});

/* import CSV */
importBtn.addEventListener('click', ()=> importFile.click());
importFile.addEventListener('change', (e)=>{
  const f = e.target.files[0]; if(!f) return;
  const reader = new FileReader();
  reader.onload = function(ev){
    const txt = ev.target.result;
    const lines = txt.split(/\\r?\\n/).map(l=>l.trim()).filter(Boolean);
    lines.forEach((ln, i)=>{
      if(i===0 && /label[,\\t]secret/i.test(ln)) return;
      const parts = ln.split(',');
      if(parts.length >= 2){
        const lbl = parts[0].replace(/^"|"$/g,'').trim();
        const sec = parts[1].replace(/^"|"$/g,'').trim();
        const digits = parts[2] ? parseInt(parts[2],10) : 6;
        const period = parts[3] ? parseInt(parts[3],10) : 30;
        accounts.push({label: lbl, secret: sec, digits, period});
      }
    });
    saveAccounts(accounts); importFile.value=''; renderList(); alert('Import সম্পন্ন হয়েছে');
  };
  reader.readAsText(f);
});

/* init */
renderList(); startTicker();
console.log('2FA Zone (বাংলা) লোড হয়েছে — লোকালি সিক্রেট সংরক্ষণ করা হবে না সার্ভারে');

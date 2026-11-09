/* Opens an AES-GCM encrypted page ({v,s,i,c}) and replaces the document with it.
   Key comes from #key=<base64url> in the link, from localStorage, or from the password form. */
const VAULT = (() => {
  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const ITEM = 'ovoz.key';
  const m = location.hash.match(/^#key=([\w-]{43})=?$/);
  const linkRaw = m ? m[1].replace(/-/g, '+').replace(/_/g, '/') + '=' : null;
  if (m) history.replaceState(null, '', location.pathname + location.search);

  const imp = raw => crypto.subtle.importKey('raw', b64(raw), 'AES-GCM', true, ['decrypt']);
  async function derive(pass, salt) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 250000, hash: 'SHA-256' }, base,
      { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  }
  const open = (k, box) => crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(box.i) }, k, b64(box.c))
    .then(buf => new TextDecoder().decode(buf));
  async function save(k) {
    try { localStorage.setItem(ITEM, btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('raw', k))))); } catch (e) {}
  }
  function show(html) { document.open(); document.write(html); document.close(); }

  function ask(box) {
    document.body.innerHTML = `<form style="position:fixed;inset:0;display:grid;place-items:center;font-family:system-ui,sans-serif">
      <div style="background:#1A1F2E;color:#F3F1EC;border:1px solid #2A3146;border-radius:20px;padding:32px;width:min(400px,calc(100vw - 32px))">
      <h2 style="margin:0 0 8px;font-size:22px">Пароль</h2>
      <p style="margin:0 0 16px;color:#A3A9B8;font-size:15px">Бу саҳифа шахсий. Паролни киритинг.</p>
      <input type="password" autocomplete="current-password" style="width:100%;box-sizing:border-box;font-size:18px;padding:12px;border-radius:12px;border:1px solid #2A3146;background:#0C0E14;color:#F3F1EC">
      <p class="e" style="color:#FF8A8A;font-size:14px;min-height:20px;margin:8px 0 0"></p>
      <button style="margin-top:6px;width:100%;font-size:17px;font-weight:700;padding:12px;border:0;border-radius:12px;background:#E9B54A;color:#1a1300;cursor:pointer">Кириш</button></div></form>`;
    const f = document.querySelector('form'), inp = f.querySelector('input');
    inp.focus();
    f.onsubmit = async e => {
      e.preventDefault();
      const k = await derive(inp.value, b64(box.s));
      try { const html = await open(k, box); await save(k); show(html); }
      catch (err) { f.querySelector('.e').textContent = 'Пароль нотўғри'; inp.select(); }
    };
  }

  return {
    async page(url) {
      const box = await (await fetch(url, { cache: 'no-cache' })).json();
      let raw = linkRaw;
      try { raw = raw || localStorage.getItem(ITEM); } catch (e) {}
      if (raw) {
        try { const k = await imp(raw); const html = await open(k, box); await save(k); return show(html); }
        catch (e) { try { localStorage.removeItem(ITEM); } catch (e2) {} }
      }
      ask(box);
    },
  };
})();

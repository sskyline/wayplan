(() => {
  "use strict";

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const values = new Map();
  let queueWrite = () => {};

  function encode64(bytes) {
    let binary = "";
    for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  const decode64 = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));

  async function initialize({ passwordMaterial, scope = location.pathname }) {
    const storageKey = `wayplan-locked-preferences-v1:${scope}`;
    const additionalData = encoder.encode(storageKey);
    let savedValues = new Map();
    let savedEnvelope;
    let salt;
    let key;
    let pending = Promise.resolve();

    function deriveKey(saltBytes) {
      return crypto.subtle.deriveKey({
        name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: 600_000
      }, passwordMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    }

    async function prepareKey() {
      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      key = await deriveKey(saltBytes);
      salt = encode64(saltBytes);
    }

    async function load(envelope) {
      if (envelope === savedEnvelope) return;
      if (!envelope) {
        savedValues = new Map();
        savedEnvelope = envelope;
        return;
      }

      const stored = JSON.parse(envelope);
      const saltBytes = decode64(stored.salt);
      const iv = decode64(stored.iv);
      if (saltBytes.length !== 16 || iv.length !== 12) throw Error("Invalid preference envelope");
      const storedKey = stored.salt === salt ? key : await deriveKey(saltBytes);
      const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData },
        storedKey, decode64(stored.ciphertext));
      savedValues = new Map(JSON.parse(decoder.decode(plaintext)));
      salt = stored.salt;
      key = storedKey;
      savedEnvelope = envelope;
    }

    let initialEnvelope;
    try {
      initialEnvelope = localStorage.getItem(storageKey);
      await load(initialEnvelope);
    } catch {
      // A corrupt envelope or a former password must not prevent the trip from opening.
      savedEnvelope = initialEnvelope;
    }
    if (!key) {
      try { await prepareKey(); } catch {}
    }
    for (const [name, value] of savedValues) values.set(name, value);

    async function save(name, value) {
      await load(localStorage.getItem(storageKey));
      if (!key) await prepareKey();

      const nextValues = new Map(savedValues);
      nextValues.set(name, value);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const plaintext = encoder.encode(JSON.stringify([...nextValues]));
      const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData }, key, plaintext);
      const envelope = JSON.stringify({ salt, iv: encode64(iv), ciphertext: encode64(ciphertext) });
      localStorage.setItem(storageKey, envelope);
      savedEnvelope = envelope;
      savedValues = nextValues;
    }

    queueWrite = (name, value) => {
      const write = () => save(name, value);
      pending = pending.then(() => navigator.locks?.request(storageKey, write) ?? write()).catch(() => {});
    };
  }

  window.WayplanEncryptedPreferences = Object.freeze({
    initialize,
    getItem: name => values.get(name) ?? null,
    setItem(name, value) {
      if (values.get(name) === value) return;
      values.set(name, value);
      queueWrite(name, value);
    }
  });
})();

;
(() => {
  "use strict";

  const form = document.getElementById("gate-form");
  const input = document.getElementById("gate-pass");
  const submit = document.getElementById("gate-submit");
  const status = document.getElementById("gate-status");
  const base = new URL("./", document.baseURI);
  const scope = base.pathname;
  const parts = [{"hash":"86f08807dd0c48bac48d7ba7a9389b5b42ecffd8127b1e287a4d3086efaf3f5b","size":262144},{"hash":"fc368e46f05e1305908fae9421981c15309f3eee02dda61e378561f43682815d","size":262144},{"hash":"18a98e3ff36e6f7ced50336a453f1b3cfc014c329f2609969b1dae7c4855895d","size":262144},{"hash":"ad75f01a238ecdda56c7601626eb20d3b2419282e90b00264daa7af9d0252498","size":262144},{"hash":"886a61b66ced261d24fe21eb05ef9169bdc1c4bff9c1678ec1caaecc8689d3a3","size":262144},{"hash":"484429d2cd456565f3bc0632ebaef24b6fb7d7e854497145bd96bbfa60b337d6","size":262144},{"hash":"d6008969b0fbae3b101e6263331261c1c0b614c13e57e48ebbff36e1c4d2c064","size":262144},{"hash":"1c124d33f9794ee4e9cbdd31c71e3c83b5ec7c4284c40658a9a30c16988c60f8","size":262144},{"hash":"b9eea0d11c91c93c583cb139c32109e3985549f8c1544464cb79df474303e544","size":262144},{"hash":"9313c32ab130919acd974b648c5d9d4494322895b4c492d31aed532c75c212f4","size":262144},{"hash":"555e0aa88dbe724cce9f8bb861529515356291c9a1a4e985130d84151f7b3137","size":262144},{"hash":"f82a284b21f7cbd3143cc2685efc4e69a66b43b8231507de4d41c9c3e1d2fb3e","size":262144},{"hash":"88d2a006680ba88c9ef598a9e879523eafcaa600bd0170b51685e630aaad2aec","size":262144},{"hash":"5c29e1242ce797870f0eb38737f485b62321690cfae9079a1008eb36aa47aed2","size":262144},{"hash":"49536bdb771637264c65a70ce47b42c802e9db5e093c649a7305977d1783f782","size":262144},{"hash":"09a5a84a924ebcdc23480b245272509123973a0fca3b2e3c34888b007aff94cb","size":262144},{"hash":"cdd5e39c979c03f7c2bdd422a1aa33651c9810a8adddfe6bbe885ef1f89df90b","size":262144},{"hash":"56db9484b27bca6860f94f52eeb3f4dcab34040a9bb9d48ae9be625e738fdda6","size":262144},{"hash":"c2c9a51f5b7882e7d0b3649e96444ba10d2ffef479eb151eb43a85c2b5dfc62d","size":262144},{"hash":"0db6d3603a11ca8ef96cc3469d5144ce4d1dd1df02c713bd997ac1afd80355e5","size":262144},{"hash":"811baa55b99bd983ab47bfb1933c10701559f93e78e7053e6a7c9b112c4c7ac9","size":262144},{"hash":"13c17ad643ef868c32130b67f70953565b4e702ec4e797933fba86a4def9117a","size":262144},{"hash":"05adb803d99abd517a485a8542fb1624596c0df29d49d7f502f19f70f3e0565e","size":262144},{"hash":"459b700ec20dda50fe470d7aeeb11936059e475cc438190797a31bf425220348","size":262144},{"hash":"7c9fc65bc4e1ebc41078e8fac44f916decff25342423ca49054e9687b022c5ec","size":262144},{"hash":"3dbb1c8e324b1313fba44c08c6e12f3894a018cee17fb430f3e43ce319e4f92e","size":262144},{"hash":"a22827cc2f686a9c7cf060401a9f14e1b48c432b412ec8db2b840d8147352852","size":262144},{"hash":"060ef3a0607f18818e38a0cbe9541362c5c943d5639a305e619f8a4443fb4d79","size":262144},{"hash":"413e71d7101f97c52e090893342dc079898cf8711c4a84388a1a9826e1c74894","size":262144},{"hash":"7c07c14049569c2cb094a936c439af0495ffaf64b5ed59cb76bf5eed541b6657","size":262144},{"hash":"4d1c84f48f90370e6d977fe7db6adbbb9dbd60ee229999eafbebe7dbeb5e4ba3","size":262144},{"hash":"ab88d46557de6154694ddce65c3fa5f1677c348ce65414dd067d50de9e4871e4","size":262144},{"hash":"3bb0f7c2e6083d4e03fb48f32d9111cf63119ba724a817699b774dd9b980bea9","size":262144},{"hash":"b4aa2f4541f211e610a9d2475a565ef7c85717a8daa53ff22814c14b475b9197","size":262144},{"hash":"e1bf86e3500239110e36ca30cc9bea732542ef68e36a592120842e25ec64c642","size":262144},{"hash":"c9f9649172443779438cabd9fde169b250c5ceb74e093660b28e767d8ba751e0","size":262144},{"hash":"448ea6d6d7933b93e4025930b868a514d90e8af214af19664071692069a3b336","size":262144},{"hash":"667bb8db17b8b9e6fb7b883f5c2d32fdbd469eceebcad874792f049cf558b531","size":262144},{"hash":"9abc6ec45e10c9fb41ba0287bbbea02d2faef92b3cd356592ff1ce0e2da91422","size":262144},{"hash":"54d2a83c52fff8ecc321c54e8f800fe41c8af0adecb179561c01b88a1cc14723","size":262144},{"hash":"4f472e9e7ca86c3e38ab59199990fefbb9f7b6ebaab07e731f0588e2f59a697b","size":262144},{"hash":"a7ae395df628e779d223231e07465b6c72a6d0bc08fadbb772279a2e3ada650a","size":262144},{"hash":"56cf8fb1c34be6cf2a896c3c9c8ad57350fe5e35ae6e5d270536e8ea4958af21","size":262144},{"hash":"8e4dadaef92c51c917258cc1e0e8ff5d39625368efe6528ff13cdf45b29da561","size":262144},{"hash":"c5fdc9b30453d0e9fe57e808d77c395b77d7c01bd38bfb3700097ab8130b759f","size":262144},{"hash":"0dd634b5ddacc3efa7769321b740aec0fc2e52953767def82a66e1777f2bb02b","size":262144},{"hash":"570eac2c9a2c3492491a35e3ad60e4ee9d4b04afac7562afce8ec8a40d0db21a","size":262144},{"hash":"68e27d5cf2e324e0811708d16903cfb50dacfe69e1d1dc22497cd9c1cf72d269","size":262144},{"hash":"2782b197c01f38d26811e7fc0e75fe87333aa8972449b0a020f62afe84f0ad40","size":262144},{"hash":"27ce1a414c6dd3fe2a30b952a8caab21f82710561db2cd1092eb15d7e4f0291e","size":262144},{"hash":"bfa8a9a2f9102142532d8f58258d5f716a7f19f14119e8da8b160e68a3bf3745","size":262144},{"hash":"283309e557a10186f9ff71c7cdfab6ad4da6cacb120c01feeb48c4e3da8b9481","size":262144},{"hash":"8e7561e619498a354bbdda7dfcd1eb17959ca93f562ed3f79b93aaeb3704c2a4","size":138454}];
  const downloaded = new Map();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const headerLength = 36;


  if (!window.isSecureContext || !window.crypto?.subtle) {
    status.textContent = "请在支持 Web Crypto 的浏览器中通过 HTTPS 打开此页面。";
    submit.disabled = true;
    return;
  }

  async function fetchPart({ hash, size }) {
    for (let attempt = 0; ; attempt++) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 45000);
      try {
        const response = await fetch(new URL(`parts/${hash}.bin`, base), {
          signal: controller.signal, cache: attempt ? "reload" : "default",
          mode: "same-origin", credentials: "omit",
        });
        if (!response.ok) throw new Error("Unavailable part");
        const bytes = new Uint8Array(await response.arrayBuffer());
        if (bytes.length !== size) throw new Error("Incomplete part");
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
        if (Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("") !== hash) {
          throw new Error("Invalid part");
        }
        return bytes;
      } catch (error) {
        if (attempt >= 2 || !navigator.onLine) throw error;
      } finally {
        clearTimeout(timeout);
      }
      await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)));
    }
  }

  async function loadBundle() {
    let next = 0;
    let failure;
    function progress() {
      status.textContent = `正在下载行程… ${Math.floor(downloaded.size / parts.length * 100)}%`;
    }
    async function download() {
      while (!failure && next < parts.length) {
        const part = parts[next++];
        if (downloaded.has(part.hash)) continue;
        try {
          downloaded.set(part.hash, await fetchPart(part));
          progress();
        } catch (error) {
          failure = error;
        }
      }
    }
    progress();
    await Promise.all([download(), download(), download()]);
    if (failure) throw failure;
    const bytes = new Uint8Array(parts.reduce((total, part) => total + part.size, 0));
    let offset = 0;
    for (const part of parts) {
      bytes.set(downloaded.get(part.hash), offset);
      offset += part.size;
    }
    if (decoder.decode(bytes.subarray(0, 8)) !== "WAYPLAN1") throw new Error("Invalid package");
    return bytes;
  }

  async function decrypt(bytes, passwordMaterial) {
    const header = bytes.subarray(0, headerLength);
    const key = await crypto.subtle.deriveKey({
      name: "PBKDF2",
      hash: "SHA-256",
      salt: header.subarray(8, 24),
      iterations: 600_000,
    }, passwordMaterial, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    return crypto.subtle.decrypt({
      name: "AES-GCM",
      iv: header.subarray(24),
      additionalData: header,
      tagLength: 128,
    }, key, bytes.subarray(headerLength));
  }

  function unpack(cleartext, createURL) {
    const view = new DataView(cleartext);
    const manifestLength = view.getUint32(0);
    let offset = 4 + manifestLength;
    const { html, sources, catalog } = JSON.parse(decoder.decode(new Uint8Array(cleartext, 4, manifestLength)));
    const photos = new Set();
    const assetURLs = catalog.map(([source, type, size]) => {
      const url = createURL(new Uint8Array(cleartext, offset, size), type);
      offset += size;
      if (source.startsWith("assets/places/") && type.startsWith("image/")) photos.add(url);
      return url;
    });
    if (offset !== cleartext.byteLength) throw new Error("Invalid bundle contents");

    function resolveAssets(text) {
      return text.replace(/@@WAYPLAN_ASSET:(\d+)@@/g, (match, index) => {
        if (!assetURLs[index]) throw new Error("Missing bundle asset");
        return assetURLs[index];
      });
    }
    const sourceURLs = new Map(Object.entries(sources).map(([name, source]) => {
      const type = name.endsWith(".css") ? "text/css" : "text/javascript";
      return [name, createURL(resolveAssets(source), `${type};charset=utf-8`)];
    }));
    return { html: resolveAssets(html), sourceURLs, photos };
  }

  function waitForResource(element) {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => finish(false), 60000);
      function finish(loaded) {
        clearTimeout(timeout);
        element.onload = element.onerror = null;
        if (loaded) resolve();
        else reject(new Error("Cannot load application resource"));
      }
      element.onload = () => finish(true);
      element.onerror = () => finish(false);
    });
  }

  async function mount({ html, sourceURLs, photos }) {
    const app = new DOMParser().parseFromString(html, "text/html");
    const root = document.documentElement;
    const gate = { head: document.head, body: document.body, lang: root.lang };
    const resolveSource = source => sourceURLs.get(source) ?? source;
    const scriptSources = [...app.querySelectorAll("script")].map(script => {
      const source = resolveSource(script.getAttribute("src"));
      script.remove();
      return source;
    });
    for (const meta of gate.head.querySelectorAll('meta[name="robots"], meta[name="referrer"]')) {
      app.head.prepend(meta.cloneNode(true));
    }
    const styles = [...app.querySelectorAll('link[rel="stylesheet"]')].map(link => {
      link.href = resolveSource(link.getAttribute("href"));
      return waitForResource(link);
    });
    window.WayplanPrivatePhotos = photos;
    try {
      root.lang = app.documentElement.lang;
      root.replaceChildren(app.head, app.body);
      await Promise.all(styles);
      for (const source of scriptSources) {
        const script = document.createElement("script");
        script.src = source;
        const loaded = waitForResource(script);
        document.body.append(script);
        await loaded;
      }
    } catch (error) {
      root.lang = gate.lang;
      root.replaceChildren(gate.head, gate.body);
      delete window.WayplanPrivatePhotos;
      throw error;
    }
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (submit.disabled) return;
    submit.disabled = true;
    status.textContent = "正在解锁…";
    const password = new TextEncoder().encode(input.value);
    input.readOnly = true;
    const objectURLs = [];
    let failure = "此浏览器无法解锁行程，请用 Safari 或 Chrome 打开。";
    try {
      const passwordMaterial = await crypto.subtle.importKey("raw", password, "PBKDF2", false, ["deriveKey"]);
      password.fill(0);
      failure = "下载中断。网络恢复后点「查看行程」可继续下载。";
      const bytes = await loadBundle();
      status.textContent = "正在验证口令…";
      input.value = "";
      failure = "口令错误，或行程文件已损坏。请核对口令后重试，或刷新页面。";
      const cleartext = await decrypt(bytes, passwordMaterial);
      failure = "暂时无法打开行程，请刷新页面后重试。";
      status.textContent = "正在打开行程…";
      let app;
      try {
        app = unpack(cleartext, (content, type) => {
          const url = URL.createObjectURL(new Blob([content], { type }));
          objectURLs.push(url);
          return url;
        });
      } finally {
        new Uint8Array(cleartext).fill(0);
      }
      await window.WayplanEncryptedPreferences.initialize({ passwordMaterial, scope });
      await mount(app);
      downloaded.clear();
      window.addEventListener("pagehide", event => {
        if (!event.persisted) objectURLs.forEach(url => URL.revokeObjectURL(url));
      }, { once: true });
      window.addEventListener("pageshow", event => {
        if (event.persisted) location.reload();
      });
    } catch {
      objectURLs.forEach(url => URL.revokeObjectURL(url));
      status.textContent = failure;
      input.focus();
    } finally {
      password.fill(0);
      input.readOnly = false;
      submit.disabled = false;
    }
  });
})();

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
  const parts = [{"hash":"aee6ce6c8c8598c3a6dcceb7459b094884764c5966b7f935271ecbd919e8046f","size":262144},{"hash":"e0b838897c4d62a8fea9df0d4bb62824d4925f4fc92632c7457f013f7a70b635","size":262144},{"hash":"3e0c0b99287b6dc0c062e0ca2b75f1aaa1e77cd2673f7c6de43c35da26d54e82","size":262144},{"hash":"681717fa4feda5ff77230417457f42246fcb6a44dda43838aef8e6f002e4445f","size":262144},{"hash":"9481eea41320907e76aabe730a308184c0aeb1f15abb3a4503511c0ea47274a7","size":262144},{"hash":"48641bbabc4373380de1e07219c22ab30749ae96e8166ec27525d4ce19f1032b","size":262144},{"hash":"d71c1a3a94df895864dcc1de45f2b190d55ec91ec8e140c7eff5f800475bb9c4","size":262144},{"hash":"013b03f5209080679f4966b8666bafcb75c3eddd5f952c3ce04172d07d435ee7","size":262144},{"hash":"76da064fa749d82ffb8a67b17dce0a6bec99f49a87e14ff034c13acdc355264b","size":262144},{"hash":"40106cea70a144e7878fcd7cb9d3449a667d30c492d9fc9c4547afe88b41fc28","size":262144},{"hash":"cce14ee46a8f5b95fd10a2b06351b51433d2556e30fe16eb4dc3dad4ddebae33","size":262144},{"hash":"58d59d5c71e91aa222f8cc18cbfe9fdbe2b871543f6d0294b86ef4547d92123f","size":262144},{"hash":"5875dbc18b0ee2a0f525b8d435a000bcab2bd398e718c5377d00fe5a8ddbcbe9","size":262144},{"hash":"7491816c3c01cb8348af98b37d8e29d378f192a77fca31d1048af5c39c6c5859","size":262144},{"hash":"af042d84b1537a220db19c5ac5b3e75dde7c5a8dfbc4c581e02a5dfb7d65bad7","size":262144},{"hash":"dc29843d8f9594b57708057f0da7c644c53cb561c486dc673e46d2e181b5ba24","size":262144},{"hash":"75c6ae484fe3ad2fbfdf9a34e5e91a81121ba67f8b10463a57a132c3dc4254ae","size":262144},{"hash":"844287f3f730fcf7b1b5c8ea759f3c9df81fe4cc412f1eec488fde4a0bca78c6","size":262144},{"hash":"6904054b6676380e21987f2965cd5aa7d792e448b9d273761fbf30a1b0280cd9","size":262144},{"hash":"2d3e88df2afd08ae97e7d9d1ba276b0c2e55641648c9af864c673c0d99763ac6","size":262144},{"hash":"fbac4b6ef833bc1c7b5240252b0eaf3ff73622bb3f762fa764673693501b25cc","size":262144},{"hash":"2a80426b65c3b5bee4e9bdead1c3915c5c43161d640b85501afff650d9c72816","size":262144},{"hash":"e60899ed6e1ac762b248bcefcb9ac2c35db5c8d63e22b0367923e2bcae16faa8","size":262144},{"hash":"81cf3ea8f8a63f96cdfe692024e7f4c6d6c79fa0a94d7b542b8e44051e811450","size":262144},{"hash":"5c62c191869b7b1f2b07591c3be6f2676c44e3c4f5f859bb3e018581a3d1f71b","size":262144},{"hash":"56e1fbad97a935bd14d28699ee9352ceff952b43c6ec494499d757b23a4c343a","size":262144},{"hash":"44da12230389eab5f0f7f1f8a917c56fcffc1a8b5a01dc372191ab8e4aea834a","size":262144},{"hash":"c1ddbad0c46001400d42e713a049700432997da16d1198f3fe6b1552cc14ebef","size":262144},{"hash":"8f9f27427ed6ad21e2e73d382e0cf226b3f4e3ab1a8c6c79a1d522fb2b05d14c","size":262144},{"hash":"8ec5a273fa0a321fe81931fcaef15d7c55b7cd432a3a3ba16266292edd6e9ae0","size":262144},{"hash":"06b7348f9db3121e47ed3fbc45d00517ac53471b3cb7f87953d9dea445556dc9","size":262144},{"hash":"c8109d44b8f7d0ed416ff73029ea48c1007bdfdd84fc35911294e0c21d201e6a","size":262144},{"hash":"1eea6668998882dbd27343a815281d4a293c101a39bcb2495af8d81b68a92cf7","size":262144},{"hash":"513d1e3ab91a3afe515c15e12cfc1cf305ef7a9fd9fb1a037d499ae0d7b2333e","size":262144},{"hash":"c5ee7977b663e47b784c511c8e55ef3a575aea3999a866489eb57c5463b6c2a5","size":262144},{"hash":"3c81b221482c8e8fda44058855828514bf09ff1df8a20333482422ac4546d334","size":262144},{"hash":"0cc5bad54cb90d87ae02146a2c50adad0b181ea3aaca6045e1c2f6151d524053","size":262144},{"hash":"96822323e5a66473379ef1803cc793d4b5ee911696fe39670bc0fade6b2fcec1","size":262144},{"hash":"ec6ae9d887c2cb774e990e5d51fb8c0dc73214ffcb5b136b99a6aec166b50952","size":262144},{"hash":"a8853454a9fbc71cbb29e11697d8a6f242661206303fc54f8b678861381d63fe","size":262144},{"hash":"29e5d6a8a79926bb7993eb3f3bca8cca24c7108a25f8cd2dcc56118ff209ad39","size":262144},{"hash":"d0eb74e95192d4c506317f122ca3434596a5202ad7a355d0bfcc64fa1751b012","size":262144},{"hash":"786660fa5aa9e4c1741d7d356cfbc3f8e7677ddeaf189f670eaa1ede02dc1b2d","size":262144},{"hash":"8ccc30eaaea49ad567d4a3bf4c2557ef73b56860612fdc13e2c581e05f19b544","size":262144},{"hash":"56a632d386ee09b42ec02ed29506e100af747c93ce37b93a6c08a8c7b3620fd0","size":262144},{"hash":"e3ac2f0cce8f731835461178e1bb641aa1835e97f709d70de3c2cb6f740f1482","size":262144},{"hash":"6ba7542549e00941911e19728e2080cce9dd2bca51390f3e2b39fd4b0e51cf95","size":262144},{"hash":"74d9b5555fa9658bb38d3340656ee6dade28bdd66ab318f50698cc2af6bbc014","size":262144},{"hash":"8686f2b9af6976edb4e1b58b97eaa644c19d3bce518d824b834ced54bc2f7063","size":262144},{"hash":"6717e6efbfb9ba6495883d1203312e017f84a7338df10c623deedf13d24657e4","size":262144},{"hash":"befb0f6708addd69f8aede41628a576f27734a2b2f802cf8fbdb16d8cb1e3b07","size":262144},{"hash":"c25d76aaaa1ff8fb827a2edb62181925cc9cca6b57d0956918002dc1a26974f3","size":262144},{"hash":"3561020d83e81792ca77aa7ee1c4f65ca8c7ddb662a68baf7fc7ded994630d27","size":131335}];
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

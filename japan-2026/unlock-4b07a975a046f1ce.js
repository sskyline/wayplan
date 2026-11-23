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
  const parts = [{"hash":"726c7e920d072b48cabc0fbd3c12f7ad7b84f0b789baf0b8ef9d4bbefffd56f3","size":262144},{"hash":"73ded9e439e72588cba174bb6afc18d38282f366d9af8514ffc008a98d11a580","size":262144},{"hash":"fb55de3fbca04ebba9c301f1e74b5ad8a3e69308b4710449d3d0ac12e14db775","size":262144},{"hash":"2b48b595f0e6d72439731e39d27f208ae88cf70397a30a68c94789d13c46997d","size":262144},{"hash":"bbf733b86b69b24f341e6edcd4eca9840bcf75331001783bd69cc7466d0d558d","size":262144},{"hash":"54937077430f96ada0aed06ed12a58a5234f552998e6396a53f99133e623fc36","size":262144},{"hash":"8d060431b26b3498ff8375b4d00ae2015e80fc30a57e5be1d52460f94daf86cf","size":262144},{"hash":"aedf62a0f3e9c1e11af09a0d423096f4ce6f6c44fadf6da95e961be4d2390317","size":262144},{"hash":"ec31e9619dbfa143bf7194fb0366ef377faaef5b9795c18f60791f9e9667e004","size":262144},{"hash":"b780e904378122d207be61268f5d7d07fb6d946a5cae1d355856fe03edb0e135","size":262144},{"hash":"f45257b9507062a020a2b6c0291170e2c0d5ab1f0b79d23deb58889c6edf3417","size":262144},{"hash":"cb8e1adf580ae9506df4d1bba715cf478a91688f9a37fc2a074cf4c999c32e8a","size":262144},{"hash":"511c9016d43baa274d15fff6f10ade78464ee8497e000b543930bcbd3e78621e","size":262144},{"hash":"0567059d59b78bd772de046adc4ca064af3e8ede617dfab9a2be3db1612231f4","size":262144},{"hash":"15a1e6dba21c915d156e4d7e0a6a5e5be7d63c03bdf3aa7aa79619be0fe29604","size":262144},{"hash":"e0b6adc457e29fe0df84cdf979631dc12d4a63433c0e1f5c315f9948d67aaff2","size":262144},{"hash":"8935e0065dfba7c1606f1f12f2d256eb65d9e55fe7fd31fb850b0e47e5dd7257","size":262144},{"hash":"d82c6303a0c92bfb8411446edd96e30a35454e32eb9cfec43234e8daa6bbf4ca","size":262144},{"hash":"4c812d27df6a83a34d8b60b9f80a77869942dfe06c9042cd93e059846b98c39b","size":262144},{"hash":"1059ed01c14c6ffe95cfe304a00e04f6c3f1de64250278e02524a4e1595e0b49","size":262144},{"hash":"68539acdf1ceb8ffa9cf8ea6b6e04f4a403f5df095b1f49779fee4c09cfca77e","size":262144},{"hash":"26e041f244381fab91360c678a3c3a753d883392acb6d0dfd266e155850e21aa","size":262144},{"hash":"45ed78bcb98ae7ecc3a86c9609b6c026237d7568f572860b194986e16b9c83c1","size":262144},{"hash":"048e1382710fb755c949b88fac1a976eda7b280cd513ec97ebf5f09065d2d509","size":262144},{"hash":"02d5bfb2a4e7f73ed340227106bf55b1017c355dc0c4a8f980fcff091393bd5d","size":262144},{"hash":"48dd0553f6d89dcc4054737959c71074f22a2045455280ba3d694a32407c489e","size":262144},{"hash":"b8aa2546b8a6b8627867cd1c81691a5afc2feeb59e123ffe591abcd700706279","size":262144},{"hash":"c5a1cac991250d0d52dcc258fa00bd331172482da9dbe6b0df0af39843feee06","size":262144},{"hash":"d680fe7d676147cd5769d8fe9712f986935e484d7e29804564b38b281ccb02f5","size":262144},{"hash":"b30ce16d9c03e4eaab334435f8c5623d6b52ce9489af0f0424d93074c18702d2","size":262144},{"hash":"69a0a2150d1e3a8a6786f74c111fe471da569b07521ba1613ab23a8e89a228df","size":262144},{"hash":"d60c436ab563497556a3b9c97ffac17854ce7b23926fd9b08ed7976a09da2552","size":262144},{"hash":"c248722a251c25fcf46c4abb66915b4bcebdb2c649b990623f5286b4f0615cc1","size":262144},{"hash":"fed894b064ce6ce735848747e48b234658ef4a02c89a2ee6f3b95f25dce933bb","size":262144},{"hash":"7000fd5fa967de2bfe24bcd9a640bd23733cc9944cf3dc91aad4b98fe9fb3845","size":262144},{"hash":"84c47be98458f47c9005229a8be8bcb6041c7d119fa31c8d10608b08098c2a10","size":262144},{"hash":"72db64f494819adb6aa4be89a161a555de35cbe4a797bdf5fa70b7f45f9e363f","size":262144},{"hash":"82e34605a7c01bf603e15cc4842f4f542489e9717ffe0f9a8e448421ad736815","size":262144},{"hash":"41eb645ff696f9d3ac57465b0f72664140fc4eeaedc87b5337082119070cd1a6","size":262144},{"hash":"c5e178a6a4653fa4fcbef4fb248cb63674752adfa3356044613f720b7b971037","size":262144},{"hash":"b38355d4909e5b0e7f52382e36cf5facb9587f4fe067075c8ef65636574dadae","size":262144},{"hash":"a2f5cdb65b2818163f537cc6daf25cf114398a90ab317bf86fd3ee0b8eb8e293","size":262144},{"hash":"57992cd6b5d74e16b6396b87daf7f7bc13a445ab3e17c8e77008c84ac96f0276","size":262144},{"hash":"1c03ac22448ef6f501e278caf344e75c6c0669c49dde9e9fd23478a4beea84f3","size":262144},{"hash":"a87f6173a2dde2f91d3b51f1fbb9609259a703f1ff3d4c57630a32887bea1733","size":262144},{"hash":"280eaff5caa00689d9c09913c610962e1758a59f2552a2969e4377e9cf60006a","size":262144},{"hash":"4a07b6f0ab3e542f8fcdd33785c7c666161880c3ece389e4158fb520fe3577ec","size":262144},{"hash":"959d715b9caf6ed0cb58cedc4962afd3f9d4121a2b37c8d1f78023ad63b0ed08","size":262144},{"hash":"b879f693b76a2b03859b66805ebf67ab9a89bb58bb4789a185630b1f380dcffe","size":262144},{"hash":"d9f4372c014351055c85a6d35903ea561c85ea95cf51c738e133e40c758dcbd8","size":262144},{"hash":"b347711fc3e4fbcc804bddaa9af16183da457ef65760e39a6501c60751e58072","size":262144},{"hash":"b25274bbfdc25d58cbfae546a76048abb47ebecf5b2451361bb81c9076710863","size":262144},{"hash":"86f8b1be825cb994503af055d635ccce916188bb2fecbb3c5e31db24e4b0561e","size":114095}];
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

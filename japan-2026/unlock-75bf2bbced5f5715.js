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
  const parts = [{"hash":"cfd90326e51ff9f695c7819fccd7a0015fbb0acf003538353e7afe69a8f51ae4","size":262144},{"hash":"cc4262906488945c3d4b45f8b661325ab5ac1b534265709eb1298f118ae2e522","size":262144},{"hash":"aa793ab5b46e522eca88a6ab0fd41ff7be661e1bdd686e2cb0247324487770eb","size":262144},{"hash":"bea5b4a8682791afd84a374aafedd46014921aeecfdd4a8d857951d15baf0efd","size":262144},{"hash":"94b874a84e9bfdb584181ac0d88d6bd05621c0090463470a09e15b56eae051a6","size":262144},{"hash":"f2f956fc1b2367b3472a299cedb21fdb2154d4d537304e18079d78324b6345dc","size":262144},{"hash":"bf99e803b5d8055aa14c0c1b89da96adca37c9155a7b9d3aa13deee0f0574ff3","size":262144},{"hash":"f49c14ea71c60ff6b6d62b12a172084b54270fbc5f38ba0401a5504ece365ab4","size":262144},{"hash":"5e9a4f9ed444280751a196e67d821a232fbfcde5293fcdc9e0f82bcfdd8441a3","size":262144},{"hash":"8b66246c4dffb6004adf8dea26c37a952bdeddf0febdaf5c6527f39d23a8d57b","size":262144},{"hash":"85d3ea25046090d73744dca185df4da364fa79e3b5fbaa42aab24f47d2d09eec","size":262144},{"hash":"86925ef061b44c1d593abb9d1e2098c1f87ac4c280e598345e8deb6ca1ce3930","size":262144},{"hash":"c5e42707fff0273fdc2e5be6f35f09c443184ee9e972d840386e74c05746b865","size":262144},{"hash":"698e070ddf0e664d491b84bd5fd800bef8dd74375da774348609148db4a7773d","size":262144},{"hash":"7dc7c57c20a35c9a6994c75b781b27ea435c43eb77150fffa7d890495d370694","size":262144},{"hash":"320057b1c027b9736a3f8a18fd13f6b4fd0bb699b4cf4e823c939eeaae480f39","size":262144},{"hash":"1e3f91ba16ba1129d516459d7a9510d3aae43eba45d06335b7f96ffa4c4cef87","size":262144},{"hash":"13dcfc0f03258f3cf0b3e70abcfa9a2eb22a2e808e234257b8e7d5cd50326478","size":262144},{"hash":"0ebda68dddcec495631450c21ce3a4bcc9e0988e81bcd6a905ef53d177a30dc2","size":262144},{"hash":"8c934db26dc88b123407b1cfda83f730d29ee85d61e373d86d24e066398dac43","size":262144},{"hash":"8be5f1ec77d53af586447f63e37ba847e31e0e7d36c4a4eee5abbc1308e2245b","size":262144},{"hash":"baa9aee0bee20becce62905232afc1ba9fc16b869db301584dd920cb6c34d341","size":262144},{"hash":"3af30c286f654e75d4873df1cb08fff2ed99e6d9a267811161461b4e3dba4426","size":262144},{"hash":"9089f074e5ea88f3a59f7a601ace1d8f16bd1f68b39ed897ba4865fc216b7138","size":262144},{"hash":"9cda0468ab98a4269c0e4247d6e206cbe6a0df4bcabcd5b10335b13714db20dd","size":262144},{"hash":"f90284f6391d3eab7a50fa488183d732b0ab5d13382f7524845a46e80b35d0b3","size":262144},{"hash":"a0683363a62a22e0372568b39d9f3ace4979a69da10df750d8723ae1ee150b4a","size":262144},{"hash":"6b7025eb6ca0d5485841d212fe1b1ee0b7050564b23b3efb856caec126178681","size":262144},{"hash":"63276c6f2e95d4d8f6e12560a4e9008b097a6ee7518a3a36e9db62b53ef19067","size":262144},{"hash":"3a1efdfa1c6839e33b58a8f70b8d28aea69f4fadf7090c69cb950d0293c34431","size":262144},{"hash":"feb0e1fdcad8b1526c5b92ba5bc9d09f6f0b5ef9a8198d46412ce8d7ba2d099a","size":262144},{"hash":"b23beb0b13c29597dc820e741d52e2c6789fb00be3fcbb74b95af9ac0862ba2f","size":262144},{"hash":"35a1635c22cbf08b5fd1a5d391fbc5fc01324139806eb76f688309a3dc6d3f8d","size":262144},{"hash":"5c1998247b5ac822e12c75ce41a452ad68f62131e408af3259889c63ba6abb4a","size":262144},{"hash":"b0c23dfaf6d136dfca682e774f85fffc923981957f4863a5be9b0d0a13527f8b","size":262144},{"hash":"86a7f14ab66613959e29099b56c885536f37b8b800dd89d3de01da7c839920d4","size":262144},{"hash":"32b96fe7a39962a558997487d3007a6c39ac36cebe0b42ca2a3d4fa958f9a69b","size":262144},{"hash":"425540010e7184c455052952cacb6a7f55842fe69e2133116b8e79158beb58fc","size":262144},{"hash":"50fc7c642d9c7199e1350f9b62c288e7588e651e7dd48b221586e69987486bcc","size":262144},{"hash":"08baf3ddf7f81c601c59b23b4fc3823c574663503903d874b4a91762328cff3d","size":262144},{"hash":"9e864132c996cb8fc0b6e3df231639d304c9cf548c620c0e6089055a3bfca4ab","size":262144},{"hash":"fd0852a68451086026edd2c2ed4a78ad5633280e9959528787f9cc57a4fba4e3","size":262144},{"hash":"9e051ac5684cb229a8a4bb4f73711c9d9737e465d25c8fe232bf55723b045246","size":225766}];
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

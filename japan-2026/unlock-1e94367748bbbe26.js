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
  const parts = [{"hash":"26e0e6e172a8c02ab57d2ed028c20cf6f833bce958e296aaea9b632c76bbdbe5","size":262144},{"hash":"7d45543994eee9247b5054889acecb2abc043f1c54767ff7bbc427c77a11013b","size":262144},{"hash":"8fc2b4d79d164fab65055d8b013189522d74e3f302005689e2e3a0d87932ecbd","size":262144},{"hash":"1ccecb8924743865e71e5af863ab62c5bc8aa512f8af36c97cad84d64e48b7a1","size":262144},{"hash":"a5634e2b1e5fa3fac1856a603fcde6e3fe9e2338207b4e81e78353569c0375e5","size":262144},{"hash":"54bed5307c6dc9030ca62f4de7fad00fd1262bb46dccdae2ae28d3320c383963","size":262144},{"hash":"4b4fef5f73c47fa502b091a770bf8005901ce1082c8e29b130dd2d424afeea7d","size":262144},{"hash":"f0c2e878cae49ed9ef24974555949eb8c8c304eaf7599b0f19d4a10f6fcbea8e","size":262144},{"hash":"67553583513098e3cdf3e154f84e1093a98c0196095ff673288f61323312f57e","size":262144},{"hash":"d6970c4eea511a620977653ac96b813ab569ce875745f8a59bbf64c21cd91afc","size":262144},{"hash":"76b48bb115b85f916e6a01a560e710c0121cafd1242ac897b2fbc380e76618f7","size":262144},{"hash":"57a5b020a1cb4b61255ff02d66d7d0ff3f8e51a45b66127285ffa64f01298588","size":262144},{"hash":"aeee6a91f6c805061a724002649b78f9d70962ffd0f0a7e16b818739b4ddf975","size":262144},{"hash":"c404e3d20de477af521b5fb7fabe2f69e9598d975d3bb2926278b45badeaf5c2","size":262144},{"hash":"2c975939c0bad7bfa8bd932cedcb9bd752d81d8d5bd4bdef36547a6f36bd7666","size":262144},{"hash":"d95d2a9022025d3ec7fdf4412d790d8240f9d2b08704038f0a512ffb12a2765e","size":262144},{"hash":"3f50f4be254989e7dabe3e3b778cdc0c1a3286e4529fae48249ef18440049041","size":262144},{"hash":"9741dc08fd8fe2712aac2da7e0dd35795a4a4fc3a73ebbe805aa2845630d3893","size":262144},{"hash":"686a74e7d7760bb85ae0f788c29893744856fb905220f7198f9a6cc406e45647","size":262144},{"hash":"f4df834bf77746ae9d524434a4450099e781d6a8f6bf6f9afa93db80a60f4ab4","size":262144},{"hash":"d7a07f9d1ab2a549e4813cdcbeb44f670bf5cbca3d40de9bd13c0b17eef664a7","size":262144},{"hash":"ce6550ea8dd98fa4d82325e6c825ea01c4a9b9ea53ac921bd971be119cc81569","size":262144},{"hash":"bab2dd854748e321ff53ccd1f016580d5c9607d47240311c31d7fcbcc2cd1305","size":262144},{"hash":"070bf417e0a48c2b32a541cb9e38bd74d04f04d64599cb50f970c7a01f6b41d0","size":262144},{"hash":"4ae102f6598c48f05dcfb2a5ce41d4ef8a76a357c81e89cc13b5348510b02b45","size":262144},{"hash":"6c1adc1c9adf24b6f0fe9b9afa09c9adf92cf135574e9b7f9b65cd2765a8c919","size":262144},{"hash":"1cf033b1e800cfe7d2daff6d147cccdcf7fb187e26989f5285850f2075cd234a","size":262144},{"hash":"8498d28b8fe32338681ee1d325d2d72bd862331a24b5ef9a29342a3ecfd7665b","size":262144},{"hash":"b17600318f36a26affdd3aeb772f5a8b26d76653e6bec2f83a38f7b76268a476","size":262144},{"hash":"31bccf07d5f7c6805bc1d0c44d5242357e72f3de52c88ae28197c08226f922dc","size":262144},{"hash":"e957043ae5332319c3b6448a52341a4206d6f083a285f9309552dc78cafa1217","size":262144},{"hash":"d83803e9a6124a7fb688a029841a971a547b46d5fde4e5a37312b1918c2af20c","size":262144},{"hash":"a620c7dd42d95a436bbca2b9517c035cdc1cef767a39f51bb29d3ae8fde4f8aa","size":262144},{"hash":"696039285c0503fb8962fedee0f471c896e07bbd2c141feba6f4a17d05ae51a6","size":262144},{"hash":"89602de6635e9bcc3267a41b4d88b525d08fb663f2a6e51a082fdcc0404f750c","size":262144},{"hash":"f64e14dce902fd6b4dc4684ffe53391bba2db4e47c0e0c5a22e5d7228bd1d633","size":262144},{"hash":"1a1f8010520af308f3eab97d76445cc891c4e5e4993805bdde422cf6bae21777","size":262144},{"hash":"d766ad6dec7fd4de983bb2aff9b10a73bac367966923626b61a7d3008b6e7e41","size":262144},{"hash":"5d035b2816022f587607f344e89f66984dbb237b74c16f283321818547479eb3","size":262144},{"hash":"fc504b9b3122d8e422690b82e1947eea2bf27688d94de325e21073f602536d21","size":262144},{"hash":"31c052d7b1d0f2b75cb86d660ee559b9ef249f1e0b6581a2ef93217e33c607f2","size":262144},{"hash":"7f96b0ae6247a2236d36ebe5bff2fb452b7c35ca2fedabf20de9f7fb14058ae6","size":262144},{"hash":"564754b92b7dc250db046acbc7a1c02cb3fe58519fa410ed497a3e0743cb8cfc","size":262144},{"hash":"631ca9e29fe9feb9f4a6812af8aae29329a3cb710f04db3fa487d1f9ba6d81e5","size":262144},{"hash":"f04b75c1fd492441194f745937bb55fc842b071de15d07889fc8a5c5265723ce","size":262144},{"hash":"9be838f09150aff094dab16ed764b0dbd53cee4d6203de74ed041a3673803a6f","size":262144},{"hash":"7b84f417d68f88ba38d7e5012c54255598c3603ed3cbcd2c3e3cbe1b59c5ef5d","size":262144},{"hash":"5224d576c116fd797b6979d788ce2b292d9aff2c2659d849d251bc787a8c1a68","size":262144},{"hash":"311883f66bd1557de9bb908c035b9fe16a380280ebebda81e8d3f0fd2417e12e","size":262144},{"hash":"3460d434ae2cc2e070832300d3a9a255f197ab8273690341344e7e40268d8b8f","size":262144},{"hash":"fc3cf33193c589b129055710b5f3f33d8fe74cdbb0bd312757498d80e64a4b8e","size":262144},{"hash":"ef6992d3b8c667b0fa9ddb281fa046e5da52afa65ef94248a0e185b5b81955ff","size":262144},{"hash":"41ef7c7a29bc62527820d532bb928e576ebfffeb0597e68070ceb17c5e8ef62c","size":143039}];
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

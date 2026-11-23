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
  const parts = [{"hash":"623e03ab68f7907fec0e30f3c7c3445e442b7a5db13d9b054c70541e150a27f0","size":262144},{"hash":"fa24faf822622eaf1a7bd42b5e87e31b6ddf95cbf5df9c5cc2566b4794c16ae4","size":262144},{"hash":"fa3c4f15976036c1c65c095ca54a84b9a625189d47598cb786be013e2494cead","size":262144},{"hash":"f48f05bebff1b7d66d9f107a31dee7c0967199b513c1b05db60f448d2a1998ca","size":262144},{"hash":"038375d4d94f261ec2d4274a3de28f75e0fe12b098714594388f23912574c61f","size":262144},{"hash":"9531168bed344b1e3add4bab8ff4c0e43705b5b41a29d66246dc269e6de8f941","size":262144},{"hash":"212755a5471c25a7ed422f34b3d23789bffbf5021eed571dc466f20dd724a84a","size":262144},{"hash":"b696830c15770542d5cd5ea8ad791faa4ab187dcdd7f64d7dfae8e83b0d5977d","size":262144},{"hash":"71283ffaf4933f7bcaf81e1919aeb05a1844d4281de549b6db63a081e254ea6b","size":262144},{"hash":"58e66969b7356982ed0c31515a81bf3b5379ebf21a63b16857c7df841722ddc1","size":262144},{"hash":"fbbc17f655dafb7baa40a2b8ac38de862e13dda8d7cdb049c6045f927894669a","size":262144},{"hash":"f78a65fda63858c3545d158df090e21c69257ae3a8fe7a22ab0e150cb3c854fe","size":262144},{"hash":"67c789b2847cd9b83631a20029478d2262ecd369d0082df1c966b940b2c4339b","size":262144},{"hash":"a83e2e5d3d92cd85e30f3bc281fd14667ee83d16fc5c6be906552498bbdcf71f","size":262144},{"hash":"1cfdfb3ae7739343efae5e0fdce46d51ec2e8c83060f836c4eaa44407428cdd5","size":262144},{"hash":"1c3e0bccc9882e113f0dcfaa6f786a28d94775156a9976eb601a33b390500367","size":262144},{"hash":"ebeb52425d691917a2249e8e67aafe877682d50ed17d2191259038ede4d03faa","size":262144},{"hash":"89c1304cb03b5696b12e0db5c70e52ca2e5004406f8effb8c4cf555c5ad0a5f7","size":262144},{"hash":"c9907ae2abdbb561f9d37ad389e3d728cad50822d1975efbf01ffcf3d4961da9","size":262144},{"hash":"59d3f3d3f6bddbf8a1988d8dcadb3a2e5ec984b27dfffd7793477479bb726259","size":262144},{"hash":"dcb0d42b579c9697bc7c226702d5a0e43403523823031d025efb08a6e6faeabf","size":262144},{"hash":"783f0cde1f8893c8e3d92ec41d7fac4b426fe68c0cd59c997b3a4ee54789e930","size":262144},{"hash":"3f7e1466785c74beb6597b120470c004285b02814b48813f972bc6d3efbd7038","size":262144},{"hash":"e85eb4a80699ddf94f674b1ffc3d07a7ee364dca979c65b6ba5b1a515b24d3df","size":262144},{"hash":"64f60e65730f56f383a601e0062a3fe634c9700a6e91aedc9b6d51fd28dfc045","size":262144},{"hash":"5232cb4a2127acf403eafd623a0f89d8009d2cb8cab912c758e72a902eb75cc9","size":262144},{"hash":"63bc7b40ce536de9065c3d530f90fa93bf79cd1db68ba9af1ee2634eb1dd649b","size":262144},{"hash":"2a8776bc2b102b494c802320c88300c2f42429231ca4385e2b79955954687233","size":262144},{"hash":"6a31050045229a3066f32a6a00228e76cb46003f42d4c1b46b5cc6808f3c95b3","size":262144},{"hash":"f31f64538a11a1f3398e7c7b39e275ea166b8eed7f25757d7c4c688ff296a9e9","size":262144},{"hash":"216665e83082a05fd8a8c5032f6af98657871d42d21ab8b2e2178a2f26eb40dd","size":262144},{"hash":"802e3d6837030c25fb137686d939bbbe25351116b97de18113e66e880e0b1b08","size":262144},{"hash":"30c7e15c89b7236773e1fc5897b65feff2aa3cc5783cd1d53aa421680f829171","size":262144},{"hash":"b28d4b6cf0216a50754785fa71bfd26b64103033bb18f22ba075d770747d31ae","size":262144},{"hash":"0183e99246fbe0b7d51dd7a6a3fb467b661c0164297f5e75f85179db7141debd","size":262144},{"hash":"3df63224d0756d1ab75c5a364505d67f89e2bb5e4bc1c605d792b326cc8193bd","size":262144},{"hash":"6d35703e6b9f63ce37e82b672dbb1ce80aaa7d42ed72e4f260462173fc85050f","size":262144},{"hash":"294f5f4408697a3b725d6d86811a728d3288a6cba44f323c788d743f5e903ceb","size":262144},{"hash":"58bdd081732664ae117f59840146aded3550a790d9acedadcfbee57f67f7d586","size":262144},{"hash":"db3bda684405ec9bb9ced58b10b55269e2dd2143459e6c79968018e2ac834a82","size":262144},{"hash":"b7b26e8e13ae605f1ef75531f6f68cf1bf61d8f50aa75e69f644f464e1e44723","size":262144},{"hash":"f52e5f0d971794eb53ab926d67fe03b259c7510a16d0bafbbe29355344ba46d6","size":262144},{"hash":"676a20625669cefc071db02ea27fbeb19fb73627f44f165f48b868124dbdbc56","size":262144},{"hash":"7b0c59d00932923f7f8a88cd68b453850960bd935fe33948ffb8c958c9fbbb4b","size":262144},{"hash":"4ebe00eb7630ef9162479ee7451807273e66d56ab7ff6e865054be31a900c557","size":262144},{"hash":"ea042e27ef5ad1edd31ba1963fb259b74d5939ebcefc92e03254c06b5bbab0cf","size":262144},{"hash":"c05b37b7e39994a019623c1f41f4a873b5424384637bb8d08cd8cc1a44b07b6f","size":262144},{"hash":"51560a5404475d031ee87f3c44d922bd382fdc261752aa061ffd0ce58f3f762b","size":262144},{"hash":"e5f94fd82712b609a1af0db4d4e483b946ea113fc24c1b52e015214f7f70839f","size":262144},{"hash":"2351a0bc89a9fdf49581d092c321fd44347c20e6b397d2301bf048ed90b01b24","size":262144},{"hash":"e568e2a8be2f64b726d06545be16c4ced673bf979e0764e5ef77e4a0c4c2b24c","size":262144},{"hash":"1f820ddf38868449cac6d646a3438f8565e7590f46dd8480c72dc02c86229baf","size":262144},{"hash":"6fde25898d26bc56c41f4591ead7dc121e4d8963e2680b93acf9e9b59577da7e","size":131337}];
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

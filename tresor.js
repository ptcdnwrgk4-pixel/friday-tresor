"use strict";
// Der Tresor — ein Schließfach, dessen Inhalt der Server nie lesen kann.
//
// Max, 07.10.2026: „vertrauliche Daten, die dadurch mehrfach gesichert
// sind, auch wenn Friday gehackt wird." Spec: Friday – Tresor (2026-10-07).
//
// ALLES HIER PASSIERT IM BROWSER. Das Codewort verlässt das Gerät nie; der
// Tresorschlüssel lebt nur in dieser Datei, nur solange der Tresor offen
// ist, nur im Arbeitsspeicher. Kein localStorage, kein sessionStorage,
// kein IndexedDB — ein Wächter liest diese Datei darauf.
//
// Die Schlüssel (Spec § 4):
//   Tresorschlüssel   32 Byte Zufall. Verschlüsselt alle Inhalte.
//   Codewortschlüssel PBKDF2-SHA-256, 600 000 Runden, aus dem Codewort.
//   Papierschlüssel   32 Byte Zufall + 2 Byte Prüfsumme, als Base32-Gruppen.
//   Schlüsselzettel   der Tresorschlüssel, je einmal eingepackt (AES-GCM)
//                     mit Codewort- und mit Papierschlüssel. Liegt beim Server.
//   je Eintrag        HKDF(Tresorschlüssel, Kennung) → AES-GCM; Stück n hat
//                     Nonce n. Kein Nonce doppelt, weil kein Unterschlüssel
//                     doppelt.
//   Geräteschlüssel   (Runde 2) HKDF(Codewort-Bits ‖ Chip-Geheimnis). Das
//                     Chip-Geheimnis kommt per WebAuthn PRF aus dem
//                     Sicherheitschip, freigegeben mit Face ID / Touch ID,
//                     und verlässt das Gerät nie. Je Gerät ein Päckchen;
//                     sobald eines gebunden ist, gibt der Server das reine
//                     Codewort-Päckchen nicht mehr heraus.
//
// Ehrlich zur Bindung: Apple synchronisiert Passkeys über den Schlüsselbund.
// Die Bindung gilt dann für alle Geräte dieser Apple-ID — jedes mit Face ID
// oder Touch ID. Es ist eine Bindung an Schlüsselbund und Gesicht, nicht an
// ein Stück Metall.
//
// RUNDE 3 (09.10.2026): Diese Datei kommt NICHT mehr von Fridays Server.
// Sie liegt in einem eigenen Repo und wird von GitHub Pages ausgeliefert.
// Wer Fridays Server steuert, kann den Code, der ver- und entschlüsselt,
// nicht mehr tauschen — er sieht weiter nur Chiffre-Stücke. Dafür zählt
// jetzt, wer das Repo beherrscht: ein Konto, das Friday nie bekommt.
//
// Was bleibt: Der Browser ist Vertrauensbasis. Mehr hält Web-Technik nicht,
// und diese Datei behauptet nicht mehr.
//
// Der Kern (Bytes, Schlüssel, Base32) läuft auch in Node — tests/tresor_probe.js
// fährt ihn dort wirklich, statt ihn zu lesen. Die Vektoren sind dieselben wie
// in Runde 1 und 2: Ein Päckchen von gestern öffnet diese Seite von heute.

(function () {
  const subtle = globalThis.crypto.subtle;
  const te = new TextEncoder();
  const td = new TextDecoder();

  const KDF = "PBKDF2-SHA-256";
  const RUNDEN = 600000;
  const STUECK = 4 * 1024 * 1024;              // Klartext je Stück; der Server kennt den Wert
  const SPERRE_NACH_MS = 5 * 60 * 1000;         // ohne Bedienung
  const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  // ------------------------------------------------------------ Bytes
  function concat(...teile) {
    const n = teile.reduce((s, t) => s + t.byteLength, 0);
    const aus = new Uint8Array(n);
    let o = 0;
    for (const t of teile) { aus.set(new Uint8Array(t.buffer ? t.buffer.slice(t.byteOffset, t.byteOffset + t.byteLength) : t), o); o += t.byteLength; }
    return aus;
  }
  function b64(bytes) {
    let s = "";
    const u = new Uint8Array(bytes);
    for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function unb64(text) {
    const s = atob(text);
    const u = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
    return u;
  }
  // 12 Byte: 4 Byte Null, dann der Zähler als 64-Bit-Zahl, big-endian.
  function nonce(n) {
    const u = new Uint8Array(12);
    const dv = new DataView(u.buffer);
    dv.setUint32(4, Math.floor(n / 0x100000000));
    dv.setUint32(8, n >>> 0);
    return u;
  }
  function gleich(a, b) {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }

  // ------------------------------------------------------------ Base32 (Papierschlüssel)
  function base32(bytes) {
    let bits = 0, wert = 0, aus = "";
    for (const b of bytes) {
      wert = (wert << 8) | b; bits += 8;
      while (bits >= 5) { aus += B32[(wert >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) aus += B32[(wert << (5 - bits)) & 31];
    return aus;
  }
  function unbase32(text) {
    const sauber = text.toUpperCase().replace(/[^A-Z2-7]/g, "");
    let bits = 0, wert = 0;
    const aus = [];
    for (const z of sauber) {
      const i = B32.indexOf(z);
      if (i < 0) throw new Error("Kein Papierschlüssel: unerlaubtes Zeichen.");
      wert = (wert << 5) | i; bits += 5;
      if (bits >= 8) { aus.push((wert >>> (bits - 8)) & 255); bits -= 8; }
    }
    return new Uint8Array(aus);
  }
  async function pruefsumme(bytes) {
    return new Uint8Array(await subtle.digest("SHA-256", bytes)).slice(0, 2);
  }
  // 32 Byte Schlüssel + 2 Byte Prüfsumme = 34 Byte = 55 Zeichen = 11 Gruppen.
  // Die Prüfsumme fängt den Tippfehler beim Abschreiben, bevor er zählt.
  async function papierErzeugen() {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const text = base32(concat(key, await pruefsumme(key)));
    return { key, text: text.match(/.{1,5}/g).join("-") };
  }
  async function papierLesen(text) {
    const bytes = unbase32(text || "");
    if (bytes.length < 34) throw new Error("Der Papierschlüssel ist unvollständig.");
    const key = bytes.slice(0, 32), ps = bytes.slice(32, 34);
    if (!gleich(ps, await pruefsumme(key))) throw new Error("Der Papierschlüssel stimmt nicht — ein Zeichen ist falsch.");
    return key;
  }

  // ------------------------------------------------------------ Schlüssel
  async function kekAusCodewort(codewort, salz, runden) {
    const basis = await subtle.importKey("raw", te.encode(codewort.normalize("NFKC")), "PBKDF2", false, ["deriveKey"]);
    return subtle.deriveKey({ name: "PBKDF2", salt: salz, iterations: runden, hash: "SHA-256" }, basis,
      { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  function kekAusPapier(key) {
    return subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }
  // Runde 2: dieselbe Ableitung wie kekAusCodewort, aber als Bytes — sie
  // werden mit dem Chip-Geheimnis zusammengeführt, nicht direkt benutzt.
  async function codewortBits(codewort, salz, runden) {
    const basis = await subtle.importKey("raw", te.encode(codewort.normalize("NFKC")), "PBKDF2", false, ["deriveBits"]);
    return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", salt: salz, iterations: runden, hash: "SHA-256" }, basis, 256));
  }
  // Geräteschlüssel = HKDF(Codewort-Bits ‖ Chip-Geheimnis, Salz). Fehlt eines
  // von beiden, kommt ein anderer Schlüssel heraus — und das Päckchen bleibt zu.
  async function kekAusGeraet(cwBits, chip, salz) {
    const ikm = concat(cwBits, chip);
    const basis = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
    ikm.fill(0);
    return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: salz, info: te.encode("tresor:geraet:v1") },
      basis, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  // Päckchen = 12 Byte Nonce || Chiffre+Siegel.
  async function einpacken(kek, tmk) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: "AES-GCM", iv }, kek, tmk);
    return concat(iv, new Uint8Array(ct));
  }
  async function auspacken(kek, paeckchen) {
    const p = new Uint8Array(paeckchen);
    if (p.length < 12 + 16) throw new Error("Das Päckchen ist beschädigt.");
    const klar = await subtle.decrypt({ name: "AES-GCM", iv: p.slice(0, 12) }, kek, p.slice(12));
    return new Uint8Array(klar);
  }
  async function eintragSchluessel(tmk, kennung, zweck) {
    const basis = await subtle.importKey("raw", tmk, "HKDF", false, ["deriveKey"]);
    return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: te.encode(`${zweck}:${kennung}`) },
      basis, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function stueckVerschluesseln(key, n, klar) {
    return new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce(n) }, key, klar));
  }
  async function stueckEntschluesseln(key, n, chiffre) {
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce(n) }, key, chiffre));
  }
  async function kopfPacken(tmk, kennung, kopf) {
    const key = await eintragSchluessel(tmk, kennung, "kopf");
    return stueckVerschluesseln(key, 0, te.encode(JSON.stringify(kopf)));
  }
  async function kopfLesen(tmk, kennung, chiffre) {
    const key = await eintragSchluessel(tmk, kennung, "kopf");
    return JSON.parse(td.decode(await stueckEntschluesseln(key, 0, chiffre)));
  }

  // ------------------------------------------------------------ Logins (Browser Schritt 3b)
  // Ein Login gehört zu genau EINEM Ursprung — Schema, Host, Port, wie
  // location.origin. „shop.example" ist nicht „shop-example.evil" und nicht
  // „shop.example.evil". Ohne Schema gilt https.
  function ursprungVon(text) {
    let t = String(text || "").trim();
    if (!t) return null;
    // Ein Schema ist „etwas:" gefolgt von „//" oder von etwas, das keine
    // Ziffer ist (javascript:, data:). „shop.example:8443" ist ein Name mit
    // Port, kein Schema (Codex an #4).
    if (!/^[a-z][a-z0-9+.-]*:(?:\/\/|(?!\d))/i.test(t)) t = "https://" + t;
    try {
      const u = new URL(t);
      if (u.protocol !== "https:" && u.protocol !== "http:") return null;
      if (!u.hostname || u.username || u.password) return null;
      return u.origin;
    } catch { return null; }
  }
  // Passt dieser Eintrag zu dieser Anfrage? Nur bei GENAU gleichem Ursprung.
  function loginPasst(kopf, anfrage) {
    return !!(kopf && anfrage && kopf.art === "login" && typeof kopf.ursprung === "string"
              && kopf.ursprung === anfrage.ursprung && ursprungVon(kopf.ursprung) === kopf.ursprung);
  }

  // Zahlungskarten (Browser Schritt 3c): Nummer mit Prüfsumme (Luhn), Ablauf
  // MM/JJ, Prüfziffer 3 oder 4 Ziffern. Gibt die Karte zurück oder null.
  function karteLesen(nummer, ablauf, pruefziffer) {
    const ziffern = String(nummer || "").replace(/[\s-]/g, "");
    if (!/^\d{12,19}$/.test(ziffern)) return null;
    let summe = 0;
    for (let i = 0; i < ziffern.length; i++) {
      let n = Number(ziffern[ziffern.length - 1 - i]) * (i % 2 ? 2 : 1);
      summe += n > 9 ? n - 9 : n;
    }
    if (summe % 10) return null;
    const m = /^\s*(\d{1,2})\s*\/\s*(\d{2}|\d{4})\s*$/.exec(String(ablauf || ""));
    if (!m || Number(m[1]) < 1 || Number(m[1]) > 12) return null;
    const pz = String(pruefziffer || "");
    if (pz && !/^\d{3,4}$/.test(pz)) return null;
    return { nummer: ziffern, ablauf: `${m[1].padStart(2, "0")}/${m[2].slice(-2)}`, pruefziffer: pz };
  }

  const intern = { concat, b64, unb64, nonce, base32, unbase32, papierErzeugen, papierLesen,
    kekAusCodewort, kekAusPapier, codewortBits, kekAusGeraet, einpacken, auspacken, eintragSchluessel,
    stueckVerschluesseln, stueckEntschluesseln, kopfPacken, kopfLesen, ursprungVon, loginPasst, karteLesen,
    KDF, RUNDEN, STUECK };

  // Ab hier nur Browser.
  if (typeof document === "undefined") {
    if (typeof module === "object" && module.exports) module.exports = intern;
    return;
  }

  // ------------------------------------------------------------ Zustand
  let tmk = null;                 // Uint8Array, nur solange offen
  let zettel = null;              // der Schlüsselzettel vom Server
  let eintraege = [];
  let platz = { belegt: 0, frei: null };
  let sperrUhr = null;
  let beschaeftigt = false;
  let bindung = null;             // das Gerät, mit dem gerade geöffnet wurde (Runde 2)
  let neuesPrfSalz = null;        // bis der Server eines kennt
  let anfrage = null;             // Browser Schritt 3b: Friday bittet um einen Login
  let anfrageKarte = "";          // die Kennung der Anmeldekarte, aus dem Fragment

  // ------------------------------------------------------------ WebAuthn (Runde 2)
  // Der Server ist an der Zeremonie nicht beteiligt: Er prüft keine
  // Signatur. Der Chip ist hier nur eine Quelle für ein Geheimnis, das es
  // nur mit Gesicht gibt — deshalb genügt eine zufällige Challenge aus
  // dieser Seite, und die Antwort bleibt hier.
  const webauthn = () => typeof PublicKeyCredential !== "undefined" && !!(navigator.credentials && navigator.credentials.create);
  const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
  function prfSalz() {
    if (zettel && zettel.prf_salz) return unb64(zettel.prf_salz);
    if (!neuesPrfSalz) neuesPrfSalz = rnd(32);
    return neuesPrfSalz;
  }
  async function geraetRegistrieren() {
    const salz = prfSalz();
    const cred = await navigator.credentials.create({ publicKey: {
      rp: { id: location.hostname, name: "Friday" },
      user: { id: rnd(16), name: "tresor", displayName: "Friday Tresor" },
      challenge: rnd(32),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "required", userVerification: "required" },
      extensions: { prf: { eval: { first: salz } } } } });
    const ext = cred.getClientExtensionResults();
    if (!ext.prf || ext.prf.enabled === false) throw new Error("Dieses Gerät kann keine Gerätebindung (kein PRF im Sicherheitschip).");
    const id = new Uint8Array(cred.rawId);
    let chip = ext.prf.results && ext.prf.results.first ? new Uint8Array(ext.prf.results.first) : null;
    if (!chip) chip = (await geraetAbfragen([id], salz)).chip;      // manche Browser liefern es erst beim Abfragen
    return { id, chip, salz };
  }
  async function geraetAbfragen(ids, salz) {
    const a = await navigator.credentials.get({ publicKey: {
      challenge: rnd(32), rpId: location.hostname,
      allowCredentials: ids.map((id) => ({ type: "public-key", id })), userVerification: "required",
      extensions: { prf: { eval: { first: salz } } } } });
    const r = a.getClientExtensionResults().prf;
    if (!r || !r.results || !r.results.first) throw new Error("Das Gerät hat kein Chip-Geheimnis geliefert.");
    return { id: new Uint8Array(a.rawId), chip: new Uint8Array(r.results.first) };
  }
  const webauthnFehler = (e) => e && e.name === "NotAllowedError" ? "abgebrochen oder nicht erlaubt" : (e && e.message) || String(e);
  const geraetName = () => /iPhone/.test(navigator.userAgent) ? "iPhone" : /iPad/.test(navigator.userAgent) ? "iPad" : /Macintosh/.test(navigator.userAgent) ? "Mac" : "Gerät";
  const wann = (iso) => iso ? new Date(iso).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" }) : "";

  // Fridays Adresse steht in index.html, nicht hier: ein Betrieb ist eine
  // Konfiguration, kein Code (Spec Mandant § 2).
  const API = (document.querySelector('meta[name="friday-api"]') || {}).content || "";
  // Die Sitzung lebt nur im Arbeitsspeicher — wie der Tresorschlüssel.
  let sitzung = null;

  const box = () => document.getElementById("tresor");
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const mb = (n) => n == null ? "–" : n < 1024 * 1024 ? `${Math.round(n / 1024)} KB` : n < 1024 ** 3 ? `${(n / 1024 ** 2).toFixed(1)} MB` : `${(n / 1024 ** 3).toFixed(2)} GB`;

  async function api(pfad, { method = "GET", json = null, roh = null } = {}) {
    // Kein Cookie: Die Seite liegt auf einer anderen Adresse als Friday, und
    // ein Cookie für die ganze Domain wäre eine Verbreiterung, die niemand
    // will (Spec Runde 3 § 4). Stattdessen der Sitzungsschlüssel aus dem
    // Ticket — im Arbeitsspeicher, nie gespeichert.
    const init = { method, cache: "no-store", headers: {} };
    if (sitzung) init.headers["Authorization"] = `Bearer ${sitzung}`;
    if (json) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(json); }
    if (roh) { init.headers["Content-Type"] = "application/octet-stream"; init.body = roh; }
    const r = await fetch(API + pfad, init);
    if (r.status === 401) { sitzung = null; throw new Error("unauthorized"); }
    if (r.headers.get("content-type")?.includes("application/octet-stream")) {
      if (!r.ok) throw new Error(`Server: ${r.status}`);
      return new Uint8Array(await r.arrayBuffer());
    }
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.message || `Server: ${r.status}`);
    return d;
  }

  // Ein Versuch, der nicht aufging — gemeldet, nicht gezaehlt: Zaehlen kann
  // nur der Server, erfahren kann er es nur hier. Das Codewort wird in
  // dieser Datei geprueft; ohne diese Meldung merkte niemand, wenn es jemand
  // oft versucht (Migration 041).
  //
  // GESPERRT WIRD NICHTS. Wer wirklich angreift, hat das Paeckchen kopiert
  // und probiert offline. Die Meldung ist ein Hinweis fuer Max, keine Tuer,
  // die zufaellt — und sie darf nichts aufhalten: Klemmt sie, klemmt sie
  // still, und der naechste Versuch geht trotzdem.
  function fehlversuch(art) {
    api("/api/tresor/fehlversuch", { method: "POST", json: { art } }).catch(() => {});
  }

  function sperren() {
    if (tmk) tmk.fill(0);
    tmk = null;
    bindung = null;
    if (sperrUhr) { clearTimeout(sperrUhr); sperrUhr = null; }
    for (const u of document.querySelectorAll("#tresor a[data-blob]")) URL.revokeObjectURL(u.href);
    const b = box();
    if (b) b.innerHTML = "";
    if (zettel) gesperrtZeigen();
  }
  function wach() {
    if (!tmk) return;
    if (sperrUhr) clearTimeout(sperrUhr);
    sperrUhr = setTimeout(() => { sperren(); hinweis("Tresor geschlossen – fünf Minuten ohne Bedienung."); }, SPERRE_NACH_MS);
  }
  document.addEventListener("visibilitychange", () => { if (document.hidden && tmk) sperren(); });
  window.addEventListener("pagehide", () => { if (tmk) sperren(); });

  // ------------------------------------------------------------ Anzeige
  function karte(html) { return `<div class="karte">${html}</div>`; }
  function hinweis(text, fehler = false) {
    const h = document.getElementById("tresor-hinweis");
    if (h) { h.textContent = text; h.className = "leer" + (fehler ? " fehler" : ""); }
  }
  function meter() {
    const frei = platz.frei == null ? "" : ` · noch ${mb(platz.frei)} frei`;
    return `<div class="tresor-meter">${eintraege.length} ${eintraege.length === 1 ? "Eintrag" : "Einträge"} · ${mb(platz.belegt)} belegt${frei}</div>`;
  }

  async function zeigen() {
    const b = box();
    if (!b) return;
    b.innerHTML = '<p class="leer">Tresor wird geholt …</p>';
    try {
      const d = await api("/api/tresor");
      platz = { belegt: d.belegt, frei: d.frei };
      eintraege = d.eintraege || [];
      if (!d.eingerichtet) { zettel = null; einrichtenZeigen(); return; }
      zettel = await api("/api/tresor/schluessel");
      if (tmk) offenZeigen(); else gesperrtZeigen();
    } catch (e) {
      if (String(e.message) === "unauthorized") return;
      b.innerHTML = `<p class="leer fehler">Tresor nicht erreichbar – ${esc(e.message)}</p>`;
    }
  }

  // --- Einrichten: Codewort → Papierschlüssel zeigen → abschreiben lassen → erst dann speichern.
  function einrichtenZeigen() {
    box().innerHTML = karte(`
      <div class="art"><span>Einrichten · Schritt 1 von 2</span></div>
      <div class="satz">Ein Codewort, das nur du kennst.</div>
      <div class="quelle">Es verlässt dieses Gerät nie. Mindestens 10 Zeichen – ein Satz ist leichter zu merken als ein Wort und schwerer zu raten.</div>
      <input id="tr-cw1" type="password" autocomplete="new-password" placeholder="Codewort">
      <input id="tr-cw2" type="password" autocomplete="new-password" placeholder="Codewort noch einmal">
      <div class="knoepfe"><button class="ja" id="tr-weiter">Weiter</button></div>
      <p class="leer" id="tresor-hinweis"></p>`);
    document.getElementById("tr-weiter").addEventListener("click", async () => {
      const a = document.getElementById("tr-cw1").value, c = document.getElementById("tr-cw2").value;
      if (a.length < 10) return hinweis("Mindestens 10 Zeichen.", true);
      if (a !== c) return hinweis("Die beiden Codewörter sind nicht gleich.", true);
      await papierZeigen(a);
    });
  }
  async function papierZeigen(codewort) {
    const neu = crypto.getRandomValues(new Uint8Array(32));
    const papier = await papierErzeugen();
    box().innerHTML = karte(`
      <div class="art"><span>Einrichten · Schritt 2 von 2</span></div>
      <div class="satz">Dein Papierschlüssel. Er wird <em>genau einmal</em> angezeigt.</div>
      <div class="tresor-papier" id="tr-papier">${esc(papier.text)}</div>
      <div class="quelle">Schreib ihn auf Papier und leg ihn an einen Ort, an den du in fünf Jahren noch denkst. Er öffnet den Tresor, wenn Codewort oder Gerät weg sind. <b>Nicht in den Vault, nicht ins Handy, nicht in eine Mail.</b> Der Server kennt ihn nie.</div>
      <div class="quelle">Zur Sicherheit tippst du ihn jetzt einmal ab – so merken wir beide, ob er richtig auf dem Zettel steht.</div>
      <input id="tr-papier-probe" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="Papierschlüssel abtippen">
      <div class="knoepfe"><button class="ja" id="tr-fertig">Aufgeschrieben und abgetippt</button></div>
      <p class="leer" id="tresor-hinweis"></p>`);
    document.getElementById("tr-fertig").addEventListener("click", async () => {
      let probe;
      try { probe = await papierLesen(document.getElementById("tr-papier-probe").value); }
      catch (e) { return hinweis(e.message, true); }
      if (!gleich(probe, papier.key)) return hinweis("Das ist nicht der Schlüssel, der oben steht. Zeichen für Zeichen vergleichen.", true);
      hinweis("Schlüsselzettel wird gerechnet …");
      try {
        const salz = crypto.getRandomValues(new Uint8Array(16));
        const kekC = await kekAusCodewort(codewort, salz, RUNDEN);
        const kekP = await kekAusPapier(papier.key);
        zettel = await api("/api/tresor/schluessel", { method: "PUT", json: {
          kdf: KDF, runden: RUNDEN, salz: b64(salz),
          paeckchen_codewort: b64(await einpacken(kekC, neu)),
          paeckchen_papier: b64(await einpacken(kekP, neu)) } });
        tmk = neu;
        papier.key.fill(0);
        offenZeigen(); wach();
      } catch (e) { hinweis("Nicht gespeichert – " + e.message, true); }
    });
  }

  // --- Gesperrt: Codewort (+ Face ID, sobald ein Gerät gebunden ist), oder der Weg über Papier.
  function gesperrtZeigen() {
    const geraete = zettel.geraete || [];
    const mitGeraet = geraete.length > 0 && webauthn();
    const mitCodewort = !!zettel.paeckchen_codewort;
    let knoepfe = "";
    if (mitGeraet) knoepfe += '<button class="ja" id="tr-auf-geraet">Mit Face ID öffnen</button>';
    if (mitCodewort) knoepfe += `<button class="${mitGeraet ? "leise" : "ja"}" id="tr-auf">${mitGeraet ? "Nur mit Codewort" : "Öffnen"}</button>`;
    knoepfe += '<button class="leise" id="tr-papier-weg">Mit Papierschlüssel</button>';
    let lage = "";
    if (geraete.length) {
      lage = `<div class="quelle">Gebunden an: ${geraete.map((g) => esc(g.name)).join(", ")}. `;
      lage += mitGeraet ? "Codewort und Face ID öffnen." : "Dieser Browser kann keine Gerätebindung — hier geht es nur mit dem Papierschlüssel.";
      if (mitCodewort) lage += ` Bis ${wann(zettel.codewort_bis)} geht es auch mit dem Codewort allein (Gerät hinzufügen).`;
      lage += "</div>";
    }
    box().innerHTML = anfrageHinweis() + karte(`
      <div class="art"><span>Geschlossen</span></div>
      <div class="satz">Codewort</div>
      <input id="tr-cw" type="password" autocomplete="current-password" placeholder="Codewort">
      ${lage}
      <div class="knoepfe">${knoepfe}</div>
      <p class="leer" id="tresor-hinweis"></p>`) + meter();
    const auf = async () => {
      const cw = document.getElementById("tr-cw").value;
      if (!cw) return;
      hinweis("Schlüssel wird gerechnet …");
      try {
        const kek = await kekAusCodewort(cw, unb64(zettel.salz), zettel.runden);
        tmk = await auspacken(kek, unb64(zettel.paeckchen_codewort));
        bindung = null;
        offenZeigen(); wach();
      } catch { fehlversuch("codewort"); hinweis("Falsches Codewort.", true); }
    };
    const aufGeraet = async () => {
      const cw = document.getElementById("tr-cw").value;
      if (!cw) return hinweis("Erst das Codewort, dann Face ID.", true);
      hinweis("Face ID …");
      let antwort;
      try { antwort = await geraetAbfragen(geraete.map((g) => unb64(g.credential_id)), unb64(zettel.prf_salz)); }
      catch (e) { return hinweis("Nicht geöffnet – " + webauthnFehler(e), true); }
      const g = geraete.find((x) => gleich(unb64(x.credential_id), antwort.id));
      if (!g) { antwort.chip.fill(0); return hinweis("Dieses Gerät ist nicht gebunden.", true); }
      hinweis("Schlüssel wird gerechnet …");
      const zurueck = g.fassung < zettel.codewort_fassung;
      try {
        const bits = await codewortBits(cw, unb64(g.cw_salz), g.runden);
        const kek = await kekAusGeraet(bits, antwort.chip, unb64(g.kdf_salz));
        bits.fill(0);
        tmk = await auspacken(kek, unb64(g.paeckchen));
        bindung = g;
        if (zurueck) await nachziehen(g, antwort.chip);
        antwort.chip.fill(0);
        offenZeigen(); wach();
      } catch {
        antwort.chip.fill(0);
        fehlversuch("geraet");
        hinweis(zurueck
          ? `Falsches Codewort. Es wurde ${wann(zettel.codewort_geaendert_at)} auf „${zettel.codewort_geaendert_auf}" geändert – hier gilt noch das alte; danach übernimmt dieses Gerät das neue.`
          : "Falsches Codewort.", true);
      }
    };
    if (mitCodewort) document.getElementById("tr-auf").addEventListener("click", auf);
    if (mitGeraet) document.getElementById("tr-auf-geraet").addEventListener("click", aufGeraet);
    document.getElementById("tr-cw").addEventListener("keydown", (e) => { if (e.key === "Enter") (mitGeraet ? aufGeraet : mitCodewort ? auf : () => {})(); });
    document.getElementById("tr-papier-weg").addEventListener("click", papierWegZeigen);
  }
  // Das Codewort wurde auf einem anderen Gerät geändert: Dieses Gerät ist
  // mit dem alten geöffnet — jetzt das neue, und das Päckchen hier wird neu
  // gepackt. Die Fassung bleibt; nur dieses Gerät zieht nach.
  async function nachziehen(g, chip) {
    const neu = prompt(`Das Codewort wurde ${wann(zettel.codewort_geaendert_at)} auf „${zettel.codewort_geaendert_auf}" geändert. Gib das NEUE Codewort ein, damit dieses Gerät es übernimmt (Abbrechen: später):`) || "";
    if (neu.length < 10) return;
    const cwSalz = rnd(16), kdfSalz = rnd(16);
    const bits = await codewortBits(neu, cwSalz, RUNDEN);
    const kek = await kekAusGeraet(bits, chip, kdfSalz); bits.fill(0);
    zettel = await api(`/api/tresor/geraete/${encodeURIComponent(g.id)}/codewort`, { method: "PUT", json: {
      kdf: KDF, runden: RUNDEN, cw_salz: b64(cwSalz), kdf_salz: b64(kdfSalz), paeckchen: b64(await einpacken(kek, tmk)), nachziehen: true } });
    bindung = (zettel.geraete || []).find((x) => x.id === g.id) || null;
  }
  function papierWegZeigen() {
    const geraete = zettel.geraete || [];
    const danach = !geraete.length ? "Danach wählst du ein neues – der Papierschlüssel bleibt, wie er ist."
      : webauthn() ? "Danach wählst du ein neues Codewort und bindest dieses Gerät neu (Face ID). Die anderen Bindungen tragen das alte Codewort – heb sie auf, wenn du es nicht mehr weißt."
      : "Dieser Browser kann keine Gerätebindung. Danach werden alle Bindungen aufgehoben und das neue Codewort gilt allein – bis du auf einem Gerät mit Face ID wieder bindest.";
    box().innerHTML = karte(`
      <div class="art"><span>Mit Papierschlüssel öffnen</span></div>
      <div class="quelle">Der Weg, wenn das Codewort weg ist. ${danach}</div>
      <input id="tr-papier-ein" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="Papierschlüssel">
      <input id="tr-cw-neu1" type="password" autocomplete="new-password" placeholder="Neues Codewort (mind. 10 Zeichen)">
      <input id="tr-cw-neu2" type="password" autocomplete="new-password" placeholder="Neues Codewort noch einmal">
      <div class="knoepfe"><button class="ja" id="tr-papier-auf">Öffnen und Codewort setzen</button><button class="leise" id="tr-zurueck">Zurück</button></div>
      <p class="leer" id="tresor-hinweis"></p>`);
    document.getElementById("tr-zurueck").addEventListener("click", gesperrtZeigen);
    document.getElementById("tr-papier-auf").addEventListener("click", async () => {
      const a = document.getElementById("tr-cw-neu1").value, c = document.getElementById("tr-cw-neu2").value;
      if (a.length < 10) return hinweis("Mindestens 10 Zeichen.", true);
      if (a !== c) return hinweis("Die beiden Codewörter sind nicht gleich.", true);
      try {
        const key = await papierLesen(document.getElementById("tr-papier-ein").value);
        hinweis("Tresor wird geöffnet …");
        const geheim = await auspacken(await kekAusPapier(key), unb64(zettel.paeckchen_papier));
        key.fill(0);
        tmk = geheim; bindung = null;
        if (!geraete.length) {
          zettel = await api("/api/tresor/schluessel/codewort", { method: "PUT", json: await codewortPaeckchen(a) });
          offenZeigen(); wach();
        } else if (webauthn()) {
          await geraetBinden({ codewort: a, neuesCodewort: true });
          wach();
        } else {
          await bindungenAufheben(a);
          offenZeigen(); wach();
        }
      } catch (e) {
        // Nur der Papierschluessel selbst zaehlt als Fehlversuch — nicht ein
        // Serverfehler danach, sonst meldete der Zaehler Stoerungen statt
        // Versuchen.
        if (e.message !== "unauthorized" && !tmk) fehlversuch("papier");
        hinweis(e.message === "unauthorized" ? e.message : (e.message || "Der Papierschlüssel passt nicht."), true);
      }
    });
  }
  async function codewortPaeckchen(codewort, extra = {}) {
    const salz = rnd(16);
    const kek = await kekAusCodewort(codewort, salz, RUNDEN);
    return { kdf: KDF, runden: RUNDEN, salz: b64(salz), paeckchen_codewort: b64(await einpacken(kek, tmk)), ...extra };
  }

  // --- Offen: Liste, Ablegen, Öffnen, Löschen, Schließen.
  async function offenZeigen() {
    const b = box();
    const zeilen = [];
    const koepfe = {};
    for (const e of eintraege) {
      let kopf;
      try { kopf = await kopfLesen(tmk, e.id, unb64(e.kopf)); } catch { kopf = { name: "(nicht lesbar)", typ: "", groesse: 0 }; }
      koepfe[e.id] = kopf;
      const art = kopf.art === "login" ? `Login · ${kopf.ursprung || "?"}` : kopf.art === "karte" ? `Zahlungskarte · •••• ${kopf.endung || ""}`
        : kopf.art === "text" ? "Text" : (kopf.typ || "Datei");
      const geheim = kopf.art === "login" || kopf.art === "karte";
      zeilen.push(`<div class="zeile knopf" data-id="${esc(e.id)}"><span class="l">${esc(kopf.name)}<small>${esc(art)}${geheim ? "" : " · " + mb(kopf.groesse)}</small></span><span class="w">›</span></div>`);
    }
    b.innerHTML = anfrageKarteHtml(koepfe) + karte(`
      <div class="art"><span>Offen</span><button class="leise tresor-klein" id="tr-zu">Schließen</button></div>
      <div class="liste" id="tr-liste">${zeilen.join("") || '<p class="leer">Noch leer.</p>'}</div>`) + meter() + karte(`
      <div class="art"><span>Ablegen</span></div>
      <input id="tr-name" placeholder="Name (nur du siehst ihn)">
      <textarea id="tr-text" rows="3" placeholder="Text – oder unten eine Datei wählen"></textarea>
      <input id="tr-datei" type="file">
      <div class="tresor-balken" id="tr-balken" hidden><span></span></div>
      <div class="knoepfe"><button class="ja" id="tr-ablegen">In den Tresor</button></div>
      <p class="leer" id="tresor-hinweis"></p>
      <div id="tr-ansicht"></div>`) + karte(`
      <div class="art"><span>Login ablegen</span></div>
      <div class="quelle">Für Friday im Browser: Will eine Seite eine Anmeldung, wählst du hier den Login, und er geht nur an genau diese Seite. Friday selbst sieht ihn nie.</div>
      <input id="tr-login-seite" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="Seite, z. B. shop.example">
      <input id="tr-login-name" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="Benutzername oder E-Mail">
      <input id="tr-login-pw" type="password" autocomplete="new-password" placeholder="Passwort">
      <div class="knoepfe"><button class="ja" id="tr-login-ablegen">Login in den Tresor</button></div>`) + karte(`
      <div class="art"><span>Zahlungskarte ablegen</span></div>
      <div class="quelle">Für Friday im Browser: Will eine Kasse eine Karte, wählst du sie hier, und der Browser füllt sie nur ein. Bestellt wird erst mit einer Kaufkarte und Face ID.</div>
      <input id="tr-karte-name" autocomplete="off" placeholder="Name, z. B. Visa privat">
      <input id="tr-karte-nummer" autocomplete="off" inputmode="numeric" placeholder="Kartennummer">
      <input id="tr-karte-ablauf" autocomplete="off" inputmode="numeric" placeholder="Ablauf MM/JJ">
      <input id="tr-karte-pz" type="password" autocomplete="off" inputmode="numeric" placeholder="Prüfziffer">
      <input id="tr-karte-inhaber" autocomplete="off" placeholder="Name auf der Karte">
      <div class="knoepfe"><button class="ja" id="tr-karte-ablegen">Karte in den Tresor</button></div>`) + geraeteKarte();
    b.addEventListener("pointerdown", wach); b.addEventListener("keydown", wach);
    document.getElementById("tr-zu").addEventListener("click", () => { sperren(); });
    document.getElementById("tr-ablegen").addEventListener("click", ablegen);
    document.getElementById("tr-login-ablegen").addEventListener("click", loginAblegen);
    document.getElementById("tr-karte-ablegen").addEventListener("click", karteAblegen);
    for (const k of b.querySelectorAll("[data-login-mit]")) k.addEventListener("click", () => mitLoginAnmelden(k.dataset.loginMit, koepfe[k.dataset.loginMit]));
    for (const k of b.querySelectorAll("[data-karte-mit]")) k.addEventListener("click", () => mitKarteFuellen(k.dataset.karteMit, koepfe[k.dataset.karteMit]));
    const nein = document.getElementById("tr-anfrage-weg");
    if (nein) nein.addEventListener("click", () => { anfrage = null; anfrageKarte = ""; offenZeigen(); });
    document.getElementById("tr-cw-wechsel").addEventListener("click", codewortWechseln);
    document.getElementById("tr-papier-neu").addEventListener("click", papierErneuernZeigen);
    const binden = document.getElementById("tr-binden");
    if (binden) binden.addEventListener("click", () => geraetBinden({}));
    const dazu = document.getElementById("tr-dazu");
    if (dazu) dazu.addEventListener("click", geraetHinzufuegen);
    for (const k of b.querySelectorAll("[data-aufheben]")) k.addEventListener("click", () => bindungAufheben(k.dataset.aufheben));
    for (const z of b.querySelectorAll("#tr-liste .zeile")) z.addEventListener("click", () => oeffnen(z.dataset.id));
  }

  // --- Schlüssel: Geräte, Codewort, Papier (Runde 2).
  function geraeteKarte() {
    const geraete = zettel.geraete || [];
    const zeilen = geraete.map((g) => {
      const alt = g.fassung < zettel.codewort_fassung ? " · altes Codewort" : "";
      const hier = bindung && bindung.id === g.id ? " · dieses Gerät" : "";
      return `<div class="zeile"><span class="l">${esc(g.name)}<small>seit ${wann(g.erstellt_at)}${alt}${hier}</small></span><button class="leise tresor-klein" data-aufheben="${esc(g.id)}">Aufheben</button></div>`;
    });
    const lage = geraete.length
      ? "Codewort allein öffnet den Tresor nicht mehr – es braucht ein gebundenes Gerät oder den Papierschlüssel."
      : (webauthn() ? "Noch kein Gerät gebunden: Das Codewort allein öffnet den Tresor. Mit Face ID wird daraus Codewort <em>und</em> Gerät."
                    : "Noch kein Gerät gebunden. Dieser Browser kann keine Gerätebindung – binde auf dem iPhone.");
    return karte(`
      <div class="art"><span>Schlüssel</span></div>
      <div class="quelle">${lage}</div>
      <div class="liste">${zeilen.join("")}</div>
      <div class="knoepfe">${webauthn() ? '<button class="ja" id="tr-binden">Dieses Gerät binden</button>' : ""}${geraete.length ? '<button class="leise" id="tr-dazu">Anderes Gerät hinzufügen</button>' : ""}<button class="leise" id="tr-cw-wechsel">Codewort ändern</button><button class="leise" id="tr-papier-neu">Papierschlüssel erneuern</button></div>`);
  }

  async function geraetBinden({ codewort = null, neuesCodewort = false }) {
    if (!tmk || !webauthn()) return;
    let cw = codewort;
    if (cw == null) {
      cw = prompt("Dein Codewort – es wird mit diesem Gerät verbunden:") || "";
      if (cw.length < 10) return hinweis("Mindestens 10 Zeichen – nichts gebunden.", true);
    }
    const name = (prompt("Name für dieses Gerät:", geraetName()) || "").trim();
    if (!name) return hinweis("Ohne Namen keine Bindung.", true);
    hinweis("Face ID …");
    try {
      const reg = await geraetRegistrieren();
      const cwSalz = rnd(16), kdfSalz = rnd(16);
      const bits = await codewortBits(cw, cwSalz, RUNDEN);
      const kek = await kekAusGeraet(bits, reg.chip, kdfSalz); bits.fill(0); reg.chip.fill(0);
      const kennung = neueKennung();
      zettel = await api("/api/tresor/geraete", { method: "POST", json: {
        id: kennung, name, credential_id: b64(reg.id), prf_salz: b64(reg.salz),
        kdf: KDF, runden: RUNDEN, cw_salz: b64(cwSalz), kdf_salz: b64(kdfSalz),
        paeckchen: b64(await einpacken(kek, tmk)), neues_codewort: neuesCodewort } });
      neuesPrfSalz = null;
      bindung = (zettel.geraete || []).find((g) => g.id === kennung) || null;
      await offenZeigen();
      hinweis(`„${name}" ist gebunden. Codewort allein öffnet den Tresor jetzt nicht mehr.`);
    } catch (e) { hinweis("Nicht gebunden – " + webauthnFehler(e), true); }
  }

  // Zehn Minuten Codewort allein — damit ein anderes Gerät hineinkommt und
  // sich dort bindet. Danach ist das Päckchen wieder weg.
  async function geraetHinzufuegen() {
    if (!tmk) return;
    const cw = prompt("Dein Codewort – zehn Minuten lang öffnet es den Tresor auch auf einem anderen Gerät:") || "";
    if (cw.length < 10) return hinweis("Mindestens 10 Zeichen – nichts geändert.", true);
    try {
      zettel = await api("/api/tresor/schluessel/codewort", { method: "PUT", json: await codewortPaeckchen(cw, { minuten: 10 }) });
      hinweis(`Zehn Minuten: Auf dem anderen Gerät mit dem Codewort öffnen, dann dort „Dieses Gerät binden".`);
    } catch (e) { hinweis("Nicht möglich – " + e.message, true); }
  }

  async function bindungAufheben(kennung) {
    if (!tmk) return;
    const geraete = zettel.geraete || [];
    const g = geraete.find((x) => x.id === kennung);
    if (!g) return;
    const letzte = geraete.length === 1;
    if (!confirm(`Bindung „${g.name}" aufheben?${letzte ? " Es ist die letzte – danach öffnet das Codewort allein wieder." : ""}`)) return;
    let json = {};
    if (letzte) {
      const cw = prompt("Dein Codewort – damit es den Tresor danach allein öffnet:") || "";
      if (cw.length < 10) return hinweis("Mindestens 10 Zeichen – nichts aufgehoben.", true);
      json = await codewortPaeckchen(cw);
    }
    try {
      zettel = await api(`/api/tresor/geraete/${encodeURIComponent(kennung)}`, { method: "DELETE", json });
      if (bindung && bindung.id === kennung) bindung = null;
      await offenZeigen();
      hinweis(`Bindung „${g.name}" aufgehoben.`);
    } catch (e) { hinweis("Nicht aufgehoben – " + e.message, true); }
  }
  async function bindungenAufheben(codewort) {
    for (const g of [...(zettel.geraete || [])].reverse()) {
      const letzte = (zettel.geraete || []).length === 1;
      zettel = await api(`/api/tresor/geraete/${encodeURIComponent(g.id)}`, { method: "DELETE", json: letzte ? await codewortPaeckchen(codewort) : {} });
    }
    bindung = null;
  }

  async function papierErneuernZeigen() {
    if (!tmk) return;
    const papier = await papierErzeugen();
    box().innerHTML = karte(`
      <div class="art"><span>Papierschlüssel erneuern</span></div>
      <div class="satz">Dein neuer Papierschlüssel. Er wird <em>genau einmal</em> angezeigt.</div>
      <div class="tresor-papier">${esc(papier.text)}</div>
      <div class="quelle">Der alte Zettel ist danach wertlos – vernichte ihn. Schreib den neuen auf Papier, <b>nicht in den Vault, nicht ins Handy, nicht in eine Mail.</b></div>
      <input id="tr-papier-probe" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="Neuen Papierschlüssel abtippen">
      <div class="knoepfe"><button class="ja" id="tr-fertig">Aufgeschrieben und abgetippt</button><button class="leise" id="tr-zurueck">Abbrechen</button></div>
      <p class="leer" id="tresor-hinweis"></p>`);
    document.getElementById("tr-zurueck").addEventListener("click", () => { papier.key.fill(0); offenZeigen(); });
    document.getElementById("tr-fertig").addEventListener("click", async () => {
      let probe;
      try { probe = await papierLesen(document.getElementById("tr-papier-probe").value); }
      catch (e) { return hinweis(e.message, true); }
      if (!gleich(probe, papier.key)) return hinweis("Das ist nicht der Schlüssel, der oben steht. Zeichen für Zeichen vergleichen.", true);
      try {
        zettel = await api("/api/tresor/schluessel/papier", { method: "PUT", json: { paeckchen_papier: b64(await einpacken(await kekAusPapier(papier.key), tmk)) } });
        papier.key.fill(0);
        await offenZeigen();
        hinweis("Papierschlüssel erneuert. Der alte gilt nicht mehr.");
      } catch (e) { hinweis("Nicht erneuert – " + e.message, true); }
    });
    wach();
  }

  function balken(anteil) {
    const el = document.getElementById("tr-balken");
    if (!el) return;
    el.hidden = anteil == null;
    if (anteil != null) el.firstElementChild.style.width = `${Math.round(anteil * 100)}%`;
  }

  async function ablegen() {
    if (!tmk || beschaeftigt) return;
    const name = document.getElementById("tr-name").value.trim();
    const text = document.getElementById("tr-text").value;
    const datei = document.getElementById("tr-datei").files[0];
    let quelle, kopf;
    if (datei) { quelle = datei; kopf = { art: "datei", name: name || datei.name, typ: datei.type || "application/octet-stream", groesse: datei.size }; }
    else if (text.trim()) { const bytes = te.encode(text); quelle = new Blob([bytes]); kopf = { art: "text", name: name || text.trim().slice(0, 40), typ: "text/plain", groesse: bytes.length }; }
    else return hinweis("Nichts zum Ablegen – Text eingeben oder Datei wählen.", true);
    if (quelle.size === 0) return hinweis("Die Datei ist leer.", true);
    if (await eintragAblegen(kopf, quelle)) {
      document.getElementById("tr-name").value = "";
      document.getElementById("tr-text").value = "";
      document.getElementById("tr-datei").value = "";
      await zeigen();
    }
  }

  // Ein Login ist ein Eintrag wie jeder andere: Kopf (Name, Art, Ursprung)
  // und ein Stück mit Benutzername und Passwort, beides verschlüsselt. Der
  // Server sieht davon nichts, auch nicht, für welche Seite er ist.
  async function loginAblegen() {
    if (!tmk || beschaeftigt) return;
    const ursprung = ursprungVon(document.getElementById("tr-login-seite").value);
    const benutzer = document.getElementById("tr-login-name").value.trim();
    const passwort = document.getElementById("tr-login-pw").value;
    if (!ursprung) return hinweis("Welche Seite? Eine Adresse wie shop.example.", true);
    if (!passwort) return hinweis("Ohne Passwort kein Login.", true);
    const bytes = te.encode(JSON.stringify({ benutzer, passwort }));
    const kopf = { art: "login", name: `${new URL(ursprung).hostname}${benutzer ? " · " + benutzer : ""}`, ursprung,
                   typ: "application/json", groesse: bytes.length };
    if (await eintragAblegen(kopf, new Blob([bytes]))) {
      for (const id of ["tr-login-seite", "tr-login-name", "tr-login-pw"]) document.getElementById(id).value = "";
      await zeigen();
    }
  }

  // Eine Zahlungskarte: Nummer, Ablauf, Prüfziffer, Name — verschlüsselt wie
  // jeder Eintrag. Im Kopf nur die letzten vier Ziffern, für die Liste.
  async function karteAblegen() {
    if (!tmk || beschaeftigt) return;
    const wert = (id) => document.getElementById(id).value;
    const k = karteLesen(wert("tr-karte-nummer"), wert("tr-karte-ablauf"), wert("tr-karte-pz"));
    if (!k) return hinweis("Die Karte stimmt nicht: Nummer, Ablauf (MM/JJ) und Prüfziffer prüfen.", true);
    const inhaber = wert("tr-karte-inhaber").trim();
    const bytes = te.encode(JSON.stringify({ ...k, inhaber }));
    const endung = k.nummer.slice(-4);
    const kopf = { art: "karte", name: wert("tr-karte-name").trim() || `Karte •••• ${endung}`, endung,
                   typ: "application/json", groesse: bytes.length };
    if (await eintragAblegen(kopf, new Blob([bytes]))) {
      for (const id of ["tr-karte-name", "tr-karte-nummer", "tr-karte-ablauf", "tr-karte-pz", "tr-karte-inhaber"]) document.getElementById(id).value = "";
      await zeigen();
    }
  }

  async function eintragAblegen(kopf, quelle) {
    const stuecke = Math.ceil(quelle.size / STUECK);
    beschaeftigt = true; balken(0); hinweis("Wird verschlüsselt …");
    try {
      // Die Kennung entsteht HIER, nicht beim Server: Der Kopf ist mit einem
      // Schlüssel aus der Kennung verschlüsselt, also muss sie feststehen,
      // bevor der Server irgendetwas sieht. Er prüft nur Muster und
      // Eindeutigkeit.
      const kennung = neueKennung();
      const kopfChiffre = await kopfPacken(tmk, kennung, kopf);
      await api("/api/tresor/eintraege", { method: "POST", json: { id: kennung, kopf: b64(kopfChiffre), stuecke } });
      const key = await eintragSchluessel(tmk, kennung, "inhalt");
      for (let n = 0; n < stuecke; n++) {
        const klar = new Uint8Array(await quelle.slice(n * STUECK, (n + 1) * STUECK).arrayBuffer());
        const chiffre = await stueckVerschluesseln(key, n, klar);
        await api(`/api/tresor/eintraege/${encodeURIComponent(kennung)}/stuecke/${n}`, { method: "PUT", roh: chiffre });
        balken((n + 1) / stuecke);
      }
      await api(`/api/tresor/eintraege/${encodeURIComponent(kennung)}/fertig`, { method: "POST" });
      beschaeftigt = false; balken(null);
      return true;
    } catch (e) {
      beschaeftigt = false; balken(null);
      hinweis("Nicht abgelegt – " + e.message, true);
      return false;
    }
  }

  async function eintragLesen(e) {
    const key = await eintragSchluessel(tmk, e.id, "inhalt");
    const teile = [];
    for (let n = 0; n < e.stuecke; n++) {
      const chiffre = await api(`/api/tresor/eintraege/${encodeURIComponent(e.id)}/stuecke/${n}`);
      teile.push(await stueckEntschluesseln(key, n, chiffre));
    }
    return concat(...teile);
  }

  // --- Die Anfrage: Friday bittet um eine Anmeldung (Browser Schritt 3b) --
  // Was die Karte will, fragt diese Seite mit IHRER Sitzung beim Server ab;
  // angeboten werden nur Logins mit GENAU diesem Ursprung. Der gewählte wird
  // hier entschlüsselt und geht an genau diese Karte — der Server füllt ihn
  // nur in eine Seite dieses Ursprungs und behält ihn nicht.
  function anfrageHinweis() {
    if (!anfrage) return "";
    const was = anfrage.art === "zahlung" ? "eine Zahlungskarte" : "einen Login";
    return karte(`<div class="art"><span>${anfrage.art === "zahlung" ? "Zahlungskarte erbeten" : "Anmeldung erbeten"}</span></div>
      <div class="satz">Friday bittet um ${was} für <b>${esc(anfrage.ursprung)}</b>.</div>
      <div class="quelle">Öffne den Tresor, dann wählst du aus.</div>`);
  }
  function anfrageKarteHtml(koepfe) {
    if (!anfrage) return "";
    if (anfrage.art === "zahlung") return zahlungKarteHtml(koepfe);
    const passend = Object.entries(koepfe).filter(([, k]) => loginPasst(k, anfrage));
    const geraete = (zettel && zettel.geraete) || [];
    const ohneGeraet = geraete.length > 0 && !bindung;
    const knoepfe = ohneGeraet ? ""
      : passend.map(([id, k]) => `<button class="ja" data-login-mit="${esc(id)}">Anmelden als ${esc(k.name)}</button>`).join("");
    const lage = ohneGeraet
      ? '<div class="quelle fehler">Dieser Tresor ist an ein Gerät gebunden. Logins gibt er nur heraus, wenn er mit Face ID geöffnet wurde.</div>'
      : passend.length ? ""
      : `<div class="quelle">Kein Login für genau diese Seite im Tresor. Leg ihn unten ab oder tippe ihn auf der Karte in der HUD.</div>`;
    return karte(`<div class="art"><span>Anmeldung erbeten</span></div>
      <div class="satz">Friday bittet um einen Login für <b>${esc(anfrage.ursprung)}</b>.</div>
      <div class="quelle">auf ${esc(String(anfrage.adresse || "").slice(0, 120))}</div>
      ${anfrage.ziel_ursprung && anfrage.ziel_ursprung !== anfrage.ursprung ? `<div class="quelle fehler">Das Formular sendet an ${esc(anfrage.ziel_ursprung)}.</div>` : ""}
      ${lage}
      <div class="knoepfe">${knoepfe}<button class="leise" id="tr-anfrage-weg">Nicht jetzt</button></div>
      <p class="leer" id="tr-anfrage-ergebnis"></p>`);
  }
  // Die Zahlungskarte (Browser Schritt 3c): angeboten werden alle Karten; sie
  // geht an genau diese Kasse, und der Browser füllt sie nur ein.
  function zahlungKarteHtml(koepfe) {
    const karten = Object.entries(koepfe).filter(([, k]) => k && k.art === "karte");
    const ohneGeraet = ((zettel && zettel.geraete) || []).length > 0 && !bindung;
    const knoepfe = ohneGeraet ? ""
      : karten.map(([id, k]) => `<button class="ja" data-karte-mit="${esc(id)}">${esc(k.name)} einfüllen</button>`).join("");
    const lage = ohneGeraet
      ? '<div class="quelle fehler">Dieser Tresor ist an ein Gerät gebunden. Karten gibt er nur heraus, wenn er mit Face ID geöffnet wurde.</div>'
      : karten.length ? "" : '<div class="quelle">Noch keine Zahlungskarte im Tresor. Leg sie unten ab oder tippe sie auf der Karte in der HUD.</div>';
    return karte(`<div class="art"><span>Zahlungskarte erbeten</span></div>
      <div class="satz">Friday bittet um eine Zahlungskarte für <b>${esc(anfrage.ursprung)}</b>.</div>
      <div class="quelle">auf ${esc(String(anfrage.adresse || "").slice(0, 120))}</div>
      ${anfrage.ziel_ursprung && anfrage.ziel_ursprung !== anfrage.ursprung ? `<div class="quelle fehler">Die Kartenfelder liegen bei ${esc(anfrage.ziel_ursprung)}.</div>` : ""}
      <div class="quelle">Der Browser füllt die Karte nur ein. Bestellt wird erst mit einer Kaufkarte und Face ID in der HUD.</div>
      ${lage}
      <div class="knoepfe">${knoepfe}<button class="leise" id="tr-anfrage-weg">Nicht jetzt</button></div>
      <p class="leer" id="tr-anfrage-ergebnis"></p>`);
  }
  async function mitKarteFuellen(kennung, kopf) {
    const e = eintraege.find((x) => x.id === kennung);
    const aus = document.getElementById("tr-anfrage-ergebnis");
    if (!tmk || !e || !anfrage || anfrage.art !== "zahlung" || !kopf || kopf.art !== "karte" || beschaeftigt) return;
    if ((zettel.geraete || []).length && !bindung) return;
    beschaeftigt = true;
    for (const k of document.querySelectorAll("[data-karte-mit]")) k.disabled = true;
    if (aus) { aus.className = "leer"; aus.textContent = "Wird eingefüllt …"; }
    try {
      const k = JSON.parse(td.decode(await eintragLesen(e)));
      const d = await api(`/api/tresor/browser/${encodeURIComponent(anfrageKarte)}/zahlungskarte`, { method: "POST",
        json: { ursprung: anfrage.ursprung, nummer: k.nummer || "", ablauf: k.ablauf || "", pruefziffer: k.pruefziffer || "",
                inhaber: k.inhaber || "" } });
      const ursprung = anfrage.ursprung;
      anfrage = null; anfrageKarte = "";
      if (aus) aus.textContent = d.ok ? `Eingefüllt auf ${ursprung}. Zurück zur HUD: Friday klickt auf Bestellen, und das wird eine Kaufkarte mit Face ID.`
        : "Nicht eingefüllt – " + (d.blockiert || "blockiert");
    } catch (err) {
      if (aus) { aus.className = "leer fehler"; aus.textContent = "Nicht eingefüllt – " + err.message; }
      for (const k of document.querySelectorAll("[data-karte-mit]")) k.disabled = false;
    }
    beschaeftigt = false;
    wach();
  }
  async function mitLoginAnmelden(kennung, kopf) {
    const e = eintraege.find((x) => x.id === kennung);
    const aus = document.getElementById("tr-anfrage-ergebnis");
    if (!tmk || !e || !anfrage || !loginPasst(kopf, anfrage) || beschaeftigt) return;
    if ((zettel.geraete || []).length && !bindung) return;
    beschaeftigt = true;
    for (const k of document.querySelectorAll("[data-login-mit]")) k.disabled = true;
    if (aus) { aus.className = "leer"; aus.textContent = "Wird angemeldet …"; }
    try {
      const login = JSON.parse(td.decode(await eintragLesen(e)));
      const d = await api(`/api/tresor/browser/${encodeURIComponent(anfrageKarte)}/anmelden`, { method: "POST",
        json: { ursprung: kopf.ursprung, benutzer: login.benutzer || "", passwort: login.passwort || "" } });
      anfrage = null; anfrageKarte = "";
      if (aus) aus.textContent = d.angemeldet ? `Angemeldet bei ${kopf.ursprung}.${d.passwortfeld_noch_da ? " Das Passwortfeld ist noch da – in der HUD nachsehen." : ""} Zurück zur HUD.`
        : "Nicht angemeldet – " + (d.blockiert || "blockiert");
    } catch (err) {
      if (aus) { aus.className = "leer fehler"; aus.textContent = "Nicht angemeldet – " + err.message; }
      for (const k of document.querySelectorAll("[data-login-mit]")) k.disabled = false;
    }
    beschaeftigt = false;
    wach();
  }
  // 18 Byte Zufall als Base64-URL: 24 Zeichen aus [A-Za-z0-9_-] — dasselbe
  // Muster, das der Server prüft (tresor.py _ID_RE).
  function neueKennung() {
    return b64(crypto.getRandomValues(new Uint8Array(18))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function oeffnen(kennung) {
    if (!tmk || beschaeftigt) return;
    const e = eintraege.find((x) => x.id === kennung);
    if (!e) return;
    beschaeftigt = true; balken(0); hinweis("Wird geholt …");
    try {
      const kopf = await kopfLesen(tmk, e.id, unb64(e.kopf));
      const key = await eintragSchluessel(tmk, e.id, "inhalt");
      const teile = [];
      for (let n = 0; n < e.stuecke; n++) {
        const chiffre = await api(`/api/tresor/eintraege/${encodeURIComponent(e.id)}/stuecke/${n}`);
        teile.push(await stueckEntschluesseln(key, n, chiffre));
        balken((n + 1) / e.stuecke);
      }
      const ansicht = document.getElementById("tr-ansicht");
      for (const u of ansicht.querySelectorAll("a[data-blob]")) URL.revokeObjectURL(u.href);
      if (kopf.art === "karte") {
        const k = JSON.parse(td.decode(concat(...teile)));
        ansicht.innerHTML = karte(`<div class="art"><span>${esc(kopf.name)}</span><button class="leise tresor-klein" data-weg="${esc(e.id)}">Löschen</button></div>
          <div class="quelle">Zahlungskarte · Ablauf ${esc(k.ablauf || "")}</div><div class="satz">${esc(k.inhaber || "(ohne Name)")}</div>
          <div class="wortlaut" id="tr-nr">•••• ${esc(kopf.endung || "")}</div><div class="knoepfe"><button class="leise" id="tr-nr-zeigen">Nummer zeigen</button></div>`);
        document.getElementById("tr-nr-zeigen").addEventListener("click", () => {
          const f = document.getElementById("tr-nr");
          f.textContent = f.textContent.startsWith("••••") ? `${k.nummer} · ${k.pruefziffer || ""}` : `•••• ${kopf.endung || ""}`;
        });
      } else if (kopf.art === "login") {
        // Das Passwort steht nicht im HTML, bis du es sehen willst.
        const login = JSON.parse(td.decode(concat(...teile)));
        ansicht.innerHTML = karte(`<div class="art"><span>${esc(kopf.name)}</span><button class="leise tresor-klein" data-weg="${esc(e.id)}">Löschen</button></div>
          <div class="quelle">Login für ${esc(kopf.ursprung)}</div><div class="satz">${esc(login.benutzer || "(ohne Benutzername)")}</div>
          <div class="wortlaut" id="tr-pw">••••••••</div><div class="knoepfe"><button class="leise" id="tr-pw-zeigen">Passwort zeigen</button></div>`);
        document.getElementById("tr-pw-zeigen").addEventListener("click", () => {
          const f = document.getElementById("tr-pw");
          f.textContent = f.textContent === "••••••••" ? login.passwort : "••••••••";
        });
      } else if (kopf.art === "text") {
        ansicht.innerHTML = karte(`<div class="art"><span>${esc(kopf.name)}</span><button class="leise tresor-klein" data-weg="${esc(e.id)}">Löschen</button></div><div class="wortlaut">${esc(td.decode(concat(...teile)))}</div>`);
      } else {
        const blob = new Blob(teile, { type: kopf.typ || "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const vorschau = /^image\//.test(kopf.typ) ? `<img src="${url}" alt="">` : /^video\//.test(kopf.typ) ? `<video src="${url}" controls playsinline></video>` : "";
        ansicht.innerHTML = karte(`<div class="art"><span>${esc(kopf.name)}</span><button class="leise tresor-klein" data-weg="${esc(e.id)}">Löschen</button></div>${vorschau}<div class="knoepfe"><a class="knopf-link" data-blob="1" href="${url}" download="${esc(kopf.name)}">Auf diesem Gerät sichern</a></div>`);
      }
      ansicht.querySelector("[data-weg]").addEventListener("click", () => loeschen(e.id, kopf.name));
      hinweis("");
    } catch (err) { hinweis("Nicht lesbar – " + err.message, true); }
    beschaeftigt = false; balken(null);
  }

  async function loeschen(kennung, name) {
    if (!confirm(`„${name}" endgültig aus dem Tresor löschen? Es gibt keinen Papierkorb.`)) return;
    try { await api(`/api/tresor/eintraege/${encodeURIComponent(kennung)}`, { method: "DELETE" }); await zeigen(); }
    catch (e) { hinweis("Nicht gelöscht – " + e.message, true); }
  }

  async function codewortWechseln() {
    if (!tmk) return;
    const geraete = zettel.geraete || [];
    if (geraete.length && !bindung) return hinweis("Mit gebundenen Geräten änderst du das Codewort auf einem gebundenen Gerät – dort mit Face ID öffnen.", true);
    const a = prompt("Neues Codewort (mindestens 10 Zeichen):") || "";
    if (a.length < 10) return hinweis("Mindestens 10 Zeichen – nichts geändert.", true);
    const c = prompt("Neues Codewort noch einmal:") || "";
    if (a !== c) return hinweis("Nicht gleich – nichts geändert.", true);
    try {
      if (!geraete.length) {
        zettel = await api("/api/tresor/schluessel/codewort", { method: "PUT", json: await codewortPaeckchen(a) });
        hinweis("Codewort geändert. Der Papierschlüssel gilt weiter.");
        return;
      }
      // Das Päckchen DIESES Geräts neu — dafür noch einmal Face ID. Die
      // anderen Geräte tragen danach das alte Codewort und ziehen beim
      // nächsten Öffnen nach.
      hinweis("Face ID …");
      const antwort = await geraetAbfragen([unb64(bindung.credential_id)], unb64(zettel.prf_salz));
      const cwSalz = rnd(16), kdfSalz = rnd(16);
      const bits = await codewortBits(a, cwSalz, RUNDEN);
      const kek = await kekAusGeraet(bits, antwort.chip, kdfSalz); bits.fill(0); antwort.chip.fill(0);
      zettel = await api(`/api/tresor/geraete/${encodeURIComponent(bindung.id)}/codewort`, { method: "PUT", json: {
        kdf: KDF, runden: RUNDEN, cw_salz: b64(cwSalz), kdf_salz: b64(kdfSalz), paeckchen: b64(await einpacken(kek, tmk)), nachziehen: false } });
      bindung = (zettel.geraete || []).find((g) => g.id === bindung.id) || null;
      await offenZeigen();
      hinweis(geraete.length > 1
        ? "Codewort geändert. Die anderen Geräte übernehmen es beim nächsten Öffnen: dort erst das alte, dann das neue Codewort."
        : "Codewort geändert. Der Papierschlüssel gilt weiter.");
    } catch (e) { hinweis("Nicht geändert – " + webauthnFehler(e), true); }
  }

  // ------------------------------------------------------------ Eintritt
  // Ein Weg, nicht zwei: Diese Seite hat kein eigenes Anmeldefeld. Die HUD
  // holt ein Ticket (60 Sekunden, einmal einlösbar) und öffnet diese Seite
  // damit. Das Ticket steht im Fragment — das verlässt den Browser nie,
  // steht in keinem Log und in keinem Referer.
  function tuerZu(text) {
    const b = box();
    if (b) b.innerHTML = karte(`<div class="art"><span>Tresor</span></div>
      <p class="satz">${esc(text)}</p>
      <p class="leer">Öffne den Tresor über Fridays Oberfläche. Diese Seite hat
      absichtlich keine eigene Anmeldung: ein Weg, nicht zwei.</p>
      <p class="leer" id="tresor-hinweis"></p>`);
  }

  async function eintreten() {
    const b = box();
    if (!b) return;
    // In einem fremden Rahmen gar nicht erst anfangen. Die Regel dafuer
    // (frame-ancestors) gilt nur als Kopfzeile, und GitHub Pages setzt
    // keine — also haelt der Code sie selbst. Ein Tresor, der sich in einer
    // fremden Seite oeffnen laesst, oeffnet sich unter fremder Aufsicht.
    if (window.top !== window.self) return tuerZu("Der Tresor laeuft nicht in einem fremden Rahmen.");
    if (!API) return tuerZu("Diese Seite kennt Fridays Adresse nicht.");
    const treffer = /(?:^|[#&])t=([A-Za-z0-9_-]+)/.exec(location.hash || "");
    if (!treffer) return tuerZu("Über die HUD öffnen.");
    // Browser Schritt 3b: Kommt die Seite von einer Anmeldekarte, steht deren
    // Kennung mit im Fragment. Sie ist kein Geheimnis, nur ein Verweis.
    const login = /(?:^|[#&])login=([A-Za-z0-9_-]{8,64})(?:&|$)/.exec(location.hash || "");
    // Sofort aus der Adresszeile — bevor irgendetwas anderes passiert.
    history.replaceState(null, "", location.pathname + location.search);
    b.innerHTML = '<p class="leer">Tresor wird geöffnet …</p>';
    try {
      const d = await api("/api/tresor/sitzung", { method: "POST", json: { ticket: treffer[1] } });
      sitzung = d.sitzung;
      if (!sitzung) throw new Error("Der Server hat keine Sitzung ausgestellt.");
      if (login) {
        try {
          const a = await api(`/api/tresor/browser/${encodeURIComponent(login[1])}`);
          if (ursprungVon(a.ursprung) === a.ursprung) { anfrage = a; anfrageKarte = login[1]; }
        } catch { /* die Karte ist weg oder abgelaufen: dann eben der Tresor, ohne Anfrage */ }
      }
      await zeigen();
    } catch (e) {
      tuerZu(e.message === "unauthorized"
        ? "Das Ticket gilt nicht mehr — es lebt eine Minute und nur einmal."
        : "Kein Eintritt – " + e.message);
    }
  }

  globalThis.Tresor = { zeigen, sperren, eintreten, _intern: intern };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", eintreten);
  else eintreten();
})();

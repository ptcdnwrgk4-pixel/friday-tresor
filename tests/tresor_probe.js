// Fährt den Kern von tresor.js in Node — dieselben Funktionen, die der
// Browser benutzt, nicht ein Nachbau. Ein Wächter, der mit derselben Annahme
// rechnet wie der Code, prüft nichts; deshalb stehen unten FESTE VEKTOREN aus
// Runde 1 und 2 (08.10.2026, erzeugt mit dem Code, der damals live war).
//
// Das ist die Zusage dieser Runde in einer Datei: Ein Päckchen von gestern
// muss die Seite von heute öffnen. Geht hier etwas kaputt, ist ein Tresor
// nicht mehr aufzubekommen — und zwar bevor jemand ihn füllt.
//
// Lauf: node tests/tresor_probe.js   (Rückgabe 0 = alles gut)
"use strict";
const path = require("path");
const intern = require(path.join(__dirname, "..", "tresor.js"));

// --- Feste Vektoren aus Runde 1 und 2 -------------------------------------
const hex = (s) => new Uint8Array(Buffer.from(s, "hex"));
const FEST = {
  tmk: hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
  salz: hex("0102030405060708090a0b0c0d0e0f10"),
  kdf_salz: hex("1112131415161718191a1b1c1d1e1f20"),
  chip: hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"),
  papier: hex("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"),
  codewort: "ein ganzer satz als codewort",
  runden: 1000,
  eintrag: "abcdefghijklmnopqrstuvwx",
  cw_paeckchen: "lGoidfpd4RhSc+tE5Azz+EBR9AcnpPbrHF+ryqT5w2F2Vsbi1zgHkPVu95iPBOEdgN3PIp6WhVwfJKBN",
  papier_paeckchen: "Ujqq+SnijGd/BNtRN0PI4jeJO7mN8LZRAOuOj7OOBj7wpFKfsB0lVJpQ8S3rgYCq0pZnBzp9tMI3GbMw",
  geraet_paeckchen: "z2+564mihjKkulRJVVzP4CsQWhOrTth4xWHf/XS7UMXkCPToLaQ4SBHbsudjwkuVbeq+No2mijT03yIj",
  stueck0: "zdd2KIcXbx0UcPx2sE+AqRZpYnSrMRBdjH2t",
  papiertext: "77XN3-TF3VK-MYQ53-GKVCD-GIQRA-D765X-OMXOV-JTCDX-MZKUI-MZCCE-AF35A",
};

async function alteTresoreGehenAuf(b) {
  const gleich = (a, c) => Buffer.from(a).equals(Buffer.from(c));
  // Jeder Vektor einzeln: Ein kaputtes Päckchen wirft, und ein Wächter, der
  // dabei abbricht, sagt nicht, WELCHER Tresor nicht mehr aufginge.
  const vektor = async (name, f) => { try { b[name] = await f(); } catch (e) { b[name] = false; } };
  // Codewort-Päckchen von Runde 1.
  await vektor("fest_codewort", async () => {
    const kek = await intern.kekAusCodewort(FEST.codewort, FEST.salz, FEST.runden);
    return gleich(await intern.auspacken(kek, intern.unb64(FEST.cw_paeckchen)), FEST.tmk);
  });
  // Papier-Päckchen von Runde 1 — und der abgeschriebene Zettel selbst.
  await vektor("fest_papier", async () => {
    const kekP = await intern.kekAusPapier(FEST.papier);
    return gleich(await intern.auspacken(kekP, intern.unb64(FEST.papier_paeckchen)), FEST.tmk);
  });
  await vektor("fest_papiertext", async () => gleich(await intern.papierLesen(FEST.papiertext), FEST.papier));
  // Geräte-Päckchen von Runde 2.
  await vektor("fest_geraet", async () => {
    const bits = await intern.codewortBits(FEST.codewort, FEST.salz, FEST.runden);
    const kekG = await intern.kekAusGeraet(bits, FEST.chip, FEST.kdf_salz);
    return gleich(await intern.auspacken(kekG, intern.unb64(FEST.geraet_paeckchen)), FEST.tmk);
  });
  // Ein Stück Inhalt von Runde 1.
  await vektor("fest_stueck", async () => {
    const ek = await intern.eintragSchluessel(FEST.tmk, FEST.eintrag, "inhalt");
    return Buffer.from(await intern.stueckEntschluesseln(ek, 0, intern.unb64(FEST.stueck0)))
      .toString("utf8") === "Stück null";
  });
}

async function main() {
  const b = {};
  const te = new TextEncoder();

  // Papierschlüssel: Roundtrip, Tippfehler, Format.
  const p = await intern.papierErzeugen();
  b.papier_format = /^([A-Z2-7]{5}-){10}[A-Z2-7]{5}$/.test(p.text);
  const gelesen = await intern.papierLesen(p.text.toLowerCase().replace(/-/g, " "));
  b.papier_roundtrip = Buffer.from(gelesen).equals(Buffer.from(p.key));
  const kaputt = p.text.replace(/^./, (c) => (c === "A" ? "B" : "A"));
  b.papier_tippfehler_faellt_auf = await intern.papierLesen(kaputt).then(() => false, () => true);

  // Codewort: einpacken, auspacken, falsches Codewort scheitert.
  const tmk = crypto.getRandomValues(new Uint8Array(32));
  const salz = crypto.getRandomValues(new Uint8Array(16));
  const kek = await intern.kekAusCodewort("ein ganzer satz als codewort", salz, 1000);
  const paeckchen = await intern.einpacken(kek, tmk);
  b.paeckchen_laenge = paeckchen.length;                        // 12 + 32 + 16
  b.codewort_roundtrip = Buffer.from(await intern.auspacken(kek, paeckchen)).equals(Buffer.from(tmk));
  const falsch = await intern.kekAusCodewort("ein ganzer satz als codewort!", salz, 1000);
  b.falsches_codewort_scheitert = await intern.auspacken(falsch, paeckchen).then(() => false, () => true);
  // NFKC: "é" als ein Zeichen und als e + Akzent sind dasselbe Codewort.
  const k1 = await intern.kekAusCodewort("café am abend", salz, 1000);
  const k2 = await intern.kekAusCodewort("café am abend", salz, 1000);
  b.codewort_normalisiert = await intern.auspacken(k2, await intern.einpacken(k1, tmk)).then(() => true, () => false);

  // Papier packt denselben Schlüssel, unabhängig vom Codewort.
  const kekP = await intern.kekAusPapier(p.key);
  b.papier_packt_denselben_schluessel = Buffer.from(await intern.auspacken(kekP, await intern.einpacken(kekP, tmk))).equals(Buffer.from(tmk));

  // Stücke: Roundtrip, Nonce je Stück verschieden, falsches Stück scheitert.
  const key = await intern.eintragSchluessel(tmk, "abcdefghijklmnopqrstuvwx", "inhalt");
  const klar0 = te.encode("Stück null"), klar1 = te.encode("Stück eins");
  const c0 = await intern.stueckVerschluesseln(key, 0, klar0);
  const c1 = await intern.stueckVerschluesseln(key, 1, klar1);
  b.stueck_roundtrip = Buffer.from(await intern.stueckEntschluesseln(key, 0, c0)).equals(Buffer.from(klar0));
  b.stueck_vertauscht_scheitert = await intern.stueckEntschluesseln(key, 1, c0).then(() => false, () => true);
  b.nonces_verschieden = !Buffer.from(intern.nonce(0)).equals(Buffer.from(intern.nonce(1)))
    && !Buffer.from(intern.nonce(1)).equals(Buffer.from(intern.nonce(0x100000000)));
  b.nonce_laenge = intern.nonce(7).length;

  // Zwei Einträge, derselbe Zähler: verschiedene Schlüssel → verschiedene Chiffre.
  const key2 = await intern.eintragSchluessel(tmk, "zyxwvutsrqponmlkjihgfedc", "inhalt");
  b.eintraege_trennen = !Buffer.from(c0).equals(Buffer.from(await intern.stueckVerschluesseln(key2, 0, klar0)));
  b.anderer_eintrag_scheitert = await intern.stueckEntschluesseln(key2, 0, c0).then(() => false, () => true);

  // Kopf: Roundtrip; und der Kopf-Schlüssel ist nicht der Inhalts-Schlüssel.
  const kopf = { art: "datei", name: "Ausweis.jpg", typ: "image/jpeg", groesse: 123456 };
  const kc = await intern.kopfPacken(tmk, "abcdefghijklmnopqrstuvwx", kopf);
  b.kopf_roundtrip = JSON.stringify(await intern.kopfLesen(tmk, "abcdefghijklmnopqrstuvwx", kc)) === JSON.stringify(kopf);
  b.kopf_nicht_mit_inhaltsschluessel = await intern.stueckEntschluesseln(key, 0, kc).then(() => false, () => true);

  // Base64 für große Blöcke (über 32 KiB — die Grenze von String.fromCharCode.apply).
  // getRandomValues nimmt hoechstens 65 536 Byte je Aufruf (Browser wie Node).
  const gross = new Uint8Array(100000);
  for (let o = 0; o < gross.length; o += 65536) crypto.getRandomValues(gross.subarray(o, Math.min(o + 65536, gross.length)));
  b.b64_gross = Buffer.from(intern.unb64(intern.b64(gross))).equals(Buffer.from(gross));

  // Runde 2: Geräteschlüssel aus Codewort-Bits UND Chip-Geheimnis. Fehlt
  // eines, bleibt das Päckchen zu; gleiche Eingaben geben denselben Schlüssel.
  const cwSalz = crypto.getRandomValues(new Uint8Array(16)), kdfSalz = crypto.getRandomValues(new Uint8Array(16));
  const chip = crypto.getRandomValues(new Uint8Array(32));
  const bits = await intern.codewortBits("ein ganzer satz als codewort", cwSalz, 1000);
  b.codewort_bits_laenge = bits.length;
  const kekG = await intern.kekAusGeraet(bits, chip, kdfSalz);
  const pG = await intern.einpacken(kekG, tmk);
  b.geraet_roundtrip = Buffer.from(await intern.auspacken(await intern.kekAusGeraet(
    await intern.codewortBits("ein ganzer satz als codewort", cwSalz, 1000), chip, kdfSalz), pG)).equals(Buffer.from(tmk));
  const andererChip = crypto.getRandomValues(new Uint8Array(32));
  b.geraet_ohne_chip_scheitert = await intern.auspacken(await intern.kekAusGeraet(bits, andererChip, kdfSalz), pG).then(() => false, () => true);
  const falscheBits = await intern.codewortBits("ein ganzer satz als codewort!", cwSalz, 1000);
  b.geraet_ohne_codewort_scheitert = await intern.auspacken(await intern.kekAusGeraet(falscheBits, chip, kdfSalz), pG).then(() => false, () => true);
  // Der Geräteschlüssel ist nicht der Codewortschlüssel: Das Codewort-Päckchen
  // geht mit ihm nicht auf — und umgekehrt.
  b.geraet_ist_nicht_codewort = await intern.auspacken(kekG, paeckchen).then(() => false, () => true)
    && await intern.auspacken(kek, pG).then(() => false, () => true);

  await alteTresoreGehenAuf(b);

  // Die Parameter selbst. Alte Tresore tragen ihre Runden im Zettel und
  // gingen auch mit anderen Zahlen auf — ein stilles Herabsetzen träfe nur
  // NEUE Tresore, und genau das fiele sonst niemandem auf (Spec § 4).
  b.kdf_name = intern.KDF === "PBKDF2-SHA-256";
  b.runden_600k = intern.RUNDEN === 600000;
  b.stueck_4mib = intern.STUECK === 4 * 1024 * 1024;

  // Der Befund ist erst ein Wächter, wenn er bei Rot auch laut wird.
  const schlecht = Object.entries(b).filter(([k, v]) => v === false).map(([k]) => k);
  if (b.paeckchen_laenge !== 60) schlecht.push("paeckchen_laenge");
  if (b.nonce_laenge !== 12) schlecht.push("nonce_laenge");
  if (b.codewort_bits_laenge !== 32) schlecht.push("codewort_bits_laenge");
  console.log(JSON.stringify(b, null, 1));
  if (schlecht.length) {
    console.error("\nFEHLGESCHLAGEN: " + schlecht.join(", "));
    process.exit(1);
  }
  console.error("\n" + Object.keys(b).length + " Befunde, alle gut.");
}
main().catch((e) => { console.error(String((e && e.stack) || e)); process.exit(1); });

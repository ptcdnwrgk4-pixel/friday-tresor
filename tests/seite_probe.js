// Was die Seite NICHT tut. Die Krypto-Probe nebenan prüft das Rechnen; hier
// steht das Versprechen über die Seite selbst, als Regel statt als Satz:
// nichts von außen, nichts gespeichert, und die Adresse des Regals an genau
// einer Stelle.
//
// Lauf: node tests/seite_probe.js   (Rückgabe 0 = alles gut)
"use strict";
const fs = require("fs");
const path = require("path");
const wurzel = path.join(__dirname, "..");
const lies = (n) => fs.readFileSync(path.join(wurzel, n), "utf8");

// Kommentare sind Herkunft, keine Verdrahtung — derselbe Satz wie beim
// Mandanten-Wächter in friday-mcp. Ein Kommentar, der „kein localStorage"
// sagt, darf den Wächter nicht auslösen, der genau das prüft.
const nurCode = (text) => text
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .split("\n").filter((z) => !/^\s*\/\//.test(z)).join("\n");

const html = lies("index.html");
const js = nurCode(lies("tresor.js"));
const css = nurCode(lies("tresor.css"));
const befunde = {};
const sage = (name, wahr) => { befunde[name] = !!wahr; };

// --- Nichts von außen ------------------------------------------------------
// Die CSP ist die eigentliche Sicherung; dieser Wächter hält, dass sie da ist
// und dass die Seite sie nicht nebenbei untergräbt.
sage("csp_vorhanden", /http-equiv=["']Content-Security-Policy["']/i.test(html));
sage("csp_default_none", /default-src\s+'none'/.test(html));
sage("csp_script_self", /script-src\s+'self'/.test(html));
sage("csp_kein_unsafe", !/unsafe-inline|unsafe-eval/.test(html));
sage("kein_fremdes_skript", ![...html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)]
  .some((m) => /^(https?:)?\/\//.test(m[1])));
sage("kein_inline_skript", !/<script\b(?![^>]*\bsrc=)[^>]*>[\s\S]*?\S[\s\S]*?<\/script>/i.test(html));
sage("kein_fremdes_stylesheet", ![...html.matchAll(/<link\b[^>]*\bhref=["']([^"']+)["']/gi)]
  .some((m) => /^(https?:)?\/\//.test(m[1])));
sage("keine_fremde_schrift", !/@import|fonts\.(googleapis|gstatic)/.test(css));

// --- Nichts gespeichert ----------------------------------------------------
// Der Tresorschlüssel lebt im Arbeitsspeicher, sonst nirgends (Spec § 7).
sage("kein_speicher", !/localStorage|sessionStorage|indexedDB|document\.cookie/.test(js));
sage("kein_eval", !/\beval\s*\(|new\s+Function\s*\(/.test(js));
// Das Ticket darf nicht in der Adresszeile stehenbleiben.
sage("ticket_wird_entfernt", /history\.replaceState/.test(js));
// Kein fremder Rahmen. frame-ancestors waere die Regel dafuer, gilt aber nur
// als Kopfzeile — GitHub Pages setzt keine. Also haelt der Code sie selbst,
// und dieser Waechter haelt den Code.
sage("kein_fremder_rahmen", /window\.top\s*!==\s*window\.self/.test(js));
sage("frame_ancestors_nicht_vorgetaeuscht", !/frame-ancestors/.test(
  html.replace(/<!--[\s\S]*?-->/g, "")));
// Kein eigenes Anmeldefeld: ein Weg, nicht zwei (Spec Runde 3 § 4).
sage("keine_zweite_anmeldung", !/type=["']password["']/.test(html));

// --- Die Adresse des Regals ------------------------------------------------
// Genau eine Stelle nennt sie, und der Code selbst keine (Spec Mandant § 2).
sage("adresse_in_html", /<meta\s+name=["']friday-api["']\s+content=["']https:\/\/[^"']+["']/.test(html));
sage("adresse_nicht_im_code", !/https?:\/\/(?!schemas\.|www\.w3\.org)[a-z0-9.-]+/i.test(js));
const ziel = (/content=["'](https:\/\/[^"']+)["']/.exec(html) || [])[1] || "";
sage("csp_erlaubt_nur_dieses_ziel", ziel && new RegExp("connect-src\\s+" + ziel.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\s*;").test(html));

// --- Die Haustür -----------------------------------------------------------
sage("cname_gesetzt", /^[a-z0-9.-]+\.[a-z]{2,}$/.test(lies("CNAME").trim()));

const schlecht = Object.entries(befunde).filter(([, v]) => !v).map(([k]) => k);
console.log(JSON.stringify(befunde, null, 1));
if (schlecht.length) {
  console.error("\nFEHLGESCHLAGEN: " + schlecht.join(", "));
  process.exit(1);
}
console.error("\n" + Object.keys(befunde).length + " Befunde, alle gut.");

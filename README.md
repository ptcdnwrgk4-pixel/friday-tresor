# friday-tresor

Die Tresor-Seite von [Friday](https://friday.kosmyra.de) — und der Grund, warum
sie hier liegt und nicht dort.

## Worum es geht

Der Tresor ist ein Schließfach für vertrauliche Dateien. Alles wird **in diesem
Browser** ver- und entschlüsselt; Fridays Server bewahrt nur Chiffre-Stücke auf
und kann nichts davon öffnen. Nicht einmal die Titel.

Bis zum 09.10.2026 lieferte Fridays Server auch den Code aus, der das tut. Das
war die ehrliche Grenze: *Wer den Server steuert, kann diesen Code tauschen und
beim nächsten Öffnen das Codewort abgreifen.* Eine Webseite kann sich nicht
gegen ihren eigenen Server verteidigen — auch kein Cache hilft, denn der
Service Worker, der ihn hielte, käme vom selben Server.

Darum diese Trennung:

| | |
|---|---|
| **Dieses Repo** | der Code, der ver- und entschlüsselt. Ausgeliefert über GitHub Pages |
| **Fridays Server** | das Regal: nimmt Bytes an, gibt Bytes zurück, prüft Größen — nie Inhalte |

Wer den Server beherrscht, sieht weiter nur Chiffre. Wer den Code ändern will,
braucht dieses Repo — und dorthin kommt Friday nicht: Das Bot-Konto
`kosmyra-friday-bot` ist hier kein Mitarbeiter, `main` nur über Pull Request.

## Was hier **nicht** liegt

Keine Schlüssel. Nirgends, auch nicht verschlüsselt.

* Das **Codewort** ist im Kopf des Besitzers.
* Der **Papierschlüssel** liegt auf Papier, außerhalb jedes Rechners.
* Das **Gerätegeheimnis** steckt im Sicherheitschip des Geräts (WebAuthn PRF)
  und verlässt es nie.
* Die **verschlüsselten Inhalte** liegen auf Fridays Server.

Deshalb darf dieses Repo öffentlich sein. Seine Sicherheit kommt nicht daher,
dass niemand den Code *lesen* kann, sondern daher, dass niemand außer dem
Besitzer ihn *ändern* kann. Dass jeder nachlesen kann, was die Seite tut und was
sie nicht tut, ist der Vorteil, nicht das Risiko.

## Dateien

| | |
|---|---|
| `index.html` | die Seite. Trägt die Content-Security-Policy und **die einzige Stelle, die Fridays Adresse nennt** (`<meta name="friday-api">`) |
| `tresor.js` | Schlüssel, Päckchen, Stücke, Gerätebindung, Oberfläche |
| `tresor.css` | eigenständig; keine Schrift, kein Framework von außen |
| `tests/tresor_probe.js` | fährt den Kern in Node, gegen **feste Vektoren aus Runde 1 und 2** |
| `tests/seite_probe.js` | was die Seite nicht tut: nichts von außen, nichts gespeichert |
| `CNAME` | `tresor.kosmyra.de` |

```
node tests/tresor_probe.js && node tests/seite_probe.js
```

Beides läuft bei jedem Pull Request (`.github/workflows/probe.yml`).

Die festen Vektoren sind die Zusage in einer Datei: **Ein Päckchen von gestern
muss die Seite von heute öffnen.** Ein Wächter, der mit derselben Annahme
rechnet wie der Code, prüft nichts — deshalb stehen dort Zahlen von damals und
keine, die der Code sich gerade selbst ausrechnet.

## Der Eintritt

Diese Seite hat **kein eigenes Anmeldefeld**: ein Weg, nicht zwei. Fridays
Oberfläche holt ein Ticket — eine Minute gültig, einmal einlösbar — und öffnet
die Seite damit. Das Ticket steht im Fragment der Adresse, das den Browser nie
verlässt, und wird sofort aus der Adresszeile entfernt. Die Seite tauscht es
gegen einen Sitzungsschlüssel, der nur im Arbeitsspeicher lebt und mit dem
Schließen verfällt. Direkt aufgerufen sagt die Seite: *Über die HUD öffnen.*

## Was das nicht löst

* Wer dieses **GitHub-Konto** beherrscht, beherrscht den Code. Dagegen hilft
  Zwei-Faktor-Anmeldung und der Branch-Schutz, sonst nichts.
* Der **Browser** bleibt Vertrauensbasis. Mehr hält Web-Technik nicht, und diese
  Datei behauptet nicht mehr.

Spec: *Friday – Tresor (2026-10-07)* und *Friday – Tresor Runde 3 (2026-10-09)*.

# CampClimate OTA Publisher

Kleines lokales Python-Tool, das eine Firmware-`.bin` aus dem `drop`-Ordner nimmt und danach:

- ein Central-Produktionsimage vor jeder weiteren Hashbildung mit dem privaten
  RSA-3072-Schluessel fuer ESP32-S3 Secure Boot V2 signiert und sofort verifiziert
- SHA256 berechnet
- im Signatur-Pflichtmodus ein kanonisches Release-Manifest mit ECDSA P-256 signiert
- die erzeugte Signatur sofort mit dem oeffentlichen Schluessel gegenprueft
- die Datei unter einem SHA256-basierten, unveraenderlichen Storage-Pfad hochlaedt
- bestehende Storage-Objekte niemals ueberschreibt
- das vollstaendige BIN aus Supabase zurueckliest und erneut auf Groesse und SHA256 prueft
- einen neuen Eintrag in `public.firmware_releases` zunaechst mit `published=false` anlegt
- den Datenbankeintrag zurueckliest und erst danach auf `published=true` schaltet
- die hochgeladene Datei in `archive` verschiebt
- eine lokale `.release.json`-Akte neben dem archivierten BIN ablegt

## Einrichtung

1. `.env.example` nach `env` kopieren
2. `SUPABASE_SERVICE_ROLE_KEY` eintragen
3. fuer Central `CENTRAL_SECURE_BOOT_PRIVATE_KEY` als echten absoluten Pfad
   ausserhalb aller Git-Repositories eintragen und die Datei auf Modus `0600`
   setzen
4. Sicherstellen, dass das Supabase-Schema einschliesslich
   `firmware_release_signing_phase1.sql` eingespielt wurde

Der Signaturvertrag ist in
[`docs/ota_release_signing_v1.md`](docs/ota_release_signing_v1.md)
vollstaendig beschrieben. Der Produktionsbetrieb verwendet:

```text
OTA_SIGNING_MODE=required
```

Central, Basic, App und beide Factory-Installer pruefen den gemeinsamen
Signaturvertrag.

Central besitzt zusaetzlich eine zweite, getrennte Signaturschicht: Das
ESP32-S3-Anwendungsimage wird mit RSA-3072 im Secure-Boot-V2-Format signiert.
Erst das vollstaendige, RSA-signierte BIN wird gehasht und durch das
ECDSA-P-256-Release-Manifest gebunden. Der RSA-Schluessel ist nicht der
P-256-Manifestschluessel. `OTA_SIGNING_MODE=disabled` deaktiviert nur die
alte Manifestebene; ein Central-Produktionsimage wird trotzdem niemals ohne
verifizierte RSA-3072-Signatur vorbereitet.

Wenn Python auf macOS mit einem SSL-Zertifikatsfehler scheitert, kannst du fuer den lokalen Test voruebergehend setzen:

```text
SUPABASE_INSECURE_SSL=1
```

Das sollte nur lokal und bewusst als Fallback genutzt werden. Der sichere
Standard ist `SUPABASE_INSECURE_SSL=0`. Auf macOS nutzt der Publisher, sofern
installiert, das aktuelle `certifi`-CA-Bundle:

```bash
/usr/local/bin/python3 -m pip install --user certifi
```

Der Service-Role-Key darf nicht mit deaktivierter Zertifikatspruefung fuer
Produktionsuploads verwendet werden.

## Nutzung

### GUI

Fuer den einfachen Release-Alltag gibt es jetzt auch eine GUI:

```bash
/usr/local/bin/python3 "/Users/bastian-gt/Documents/PlatformIO/Projects/CampClimate OTA Publisher/publisher_gui.py"
```

Oder per Doppelklick:

`CampClimate OTA Publisher.command`

Die GUI kann:

- `Basic` oder `Central` als OTA-Target waehlen
- eine `Release-Art` setzen
- Version, Bezeichnung / Notes und `mandatory` pflegen
- eine vorhandene `.bin` verwenden
- oder die aktuelle Produktions-Firmware frisch aus den Sources bauen
  - `Basic V2.0` via `basic-v2`
  - `Central 2.0` via `central-production`
- danach den vorhandenen Upload-Prozess nach Supabase ausfuehren

Im Signatur-Pflichtmodus gilt:

- `Release-Sequenz` ist Pflicht
- die Sequenz muss groesser als die hoechste bereits vorhandene signierte
  Sequenz desselben Targets sein
- Produktionsreleases werden standardmaessig nur aus einem frischen Build signiert
- vorhandene beliebige BIN-Dateien werden abgelehnt
- vor dem Upload werden Datei, Hash und Signatur erneut geprueft
- der Build erhaelt `CAMPCLIMATE_RELEASE_SEQUENCE`
- Basic muss genau eine `CCFWSEQ1`-Marke mit demselben 64-Bit-Sequenzwert
  enthalten; Central verwendet den festen, RSA-verifizierten `CCIMG001`-Deskriptor

Fuer Central gilt unabhaengig vom Manifestmodus zusaetzlich:

- `Release-Sequenz` ist Pflicht
- das eingebettete Image muss Typ `production`, Hardware `2.0` und denselben
  Sequenzwert tragen
- der Publisher ruft das versionierte `image_tool.py` aus dem Central-Projekt auf
- ein frischer Build muss unsigniert eintreffen und wird genau einmal signiert
- vor dem Upload wird die RSA-3072-Signatur erneut kryptografisch verifiziert
- Fehlerausgaben enthalten weder den privaten Schluessel noch seinen Pfad
- das signierte Zwischenartefakt liegt in einem privaten `0700`-Verzeichnis,
  besitzt Modus `0600` und wird bei Erfolg, Abbruch oder Fehler bereinigt
- `OTA_ALLOW_EXISTING_SIGNED_BIN=1` akzeptiert bei Central nur ein bereits mit
  dem konfigurierten RSA-Schluessel verifiziertes Produktionsimage; ein
  beliebiges vorhandenes BIN wird nicht nachsigniert

### Terminal

1. Firmware-`.bin` in `drop/` legen
2. Im Terminal in diesen Ordner wechseln
3. Tool starten:

```bash
python3 publisher.py
```

Das Tool fragt dich dann nach:

- Datei
- Target
- Version
- Bezeichnung / Notes
- `mandatory`
- fuer Central sowie bei aktivierter Manifestsignatur die monotone `Release-Sequenz`

## Signaturschluessel vorbereiten

Es werden zwei voneinander getrennte Produktionsschluessel verwendet:

- ECDSA P-256 signiert das Release-Manifest.
- RSA-3072 signiert ausschliesslich das Central-BIN fuer ESP32-S3 Secure Boot V2.

Der echte Produktionsschluessel wird ausserhalb aller Git-Repositories erzeugt:

```bash
python3 signing_key_tool.py generate --purpose production
```

Das Werkzeug:

- erzeugt einen verschluesselten P-256-Privatschluessel
- leitet den oeffentlichen Schluessel ab
- bildet Key-ID und SHA256-Fingerprint
- fuehrt eine Signatur-Gegenprobe aus
- verweigert Zielordner innerhalb dieses Repositories

Anschliessend wird die Passphrase interaktiv im macOS-Schluesselbund abgelegt:

```bash
python3 signing_key_tool.py store-passphrase \
  --key-id "<ausgegebene-key-id>" \
  --private-key "<ausgegebener-privater-pfad>" \
  --public-key "<ausgegebener-oeffentlicher-pfad>"
```

Die Passphrase wird dabei nicht als Klartextargument auf der Kommandozeile
uebergeben. Das Werkzeug prueft anschliessend durch eine echte Testsignatur,
dass die gespeicherte Passphrase zum privaten Schluessel passt. Privater
Schluessel und Passphrase gehoeren zusaetzlich in zwei verschluesselte,
getrennt gelagerte Offline-Backups.

Der RSA-3072-Schluessel wird ebenfalls ausserhalb aller Repositories und mit
Dateimodus `0600` gehalten. Weil `espsecure.py` ihn nicht ueber den bestehenden
Manifest-Keychain-Dialog entsperrt, darf sein lokaler Einsatzpfad nur auf dem
geschuetzten Release-Rechner liegen; die gesicherten Offline-Kopien bleiben
verschluesselt und getrennt gelagert. Der Publisher schreibt oder protokolliert
den Pfad nicht in Release-Akten.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Die Tests erzeugen nur temporaere Testschluessel und pruefen unter anderem:

- stabilen kanonischen Manifesttext
- gueltige Signatur und Gegenpruefung
- Ablehnung manipulierter Manifestfelder
- Ablehnung nachtraeglich veraenderter Firmware
- Ablehnung einer fehlenden, mehrfachen oder abweichenden BIN-Sequenz
- Central-RSA-Signierung vor der ECDSA-Manifest-Hashbildung
- erneute RSA-Verifikation direkt vor jedem Upload
- strikte Trennung: Der unveraenderte Basic-Pfad ruft kein Central-Signierwerkzeug auf
- Fail-closed bei fehlendem, relativem oder zu offen berechtigtem RSA-Schluessel
- Bereinigung privater Central-Zwischenartefakte auch auf Fehlerpfaden
- Sperre beliebiger vorhandener BINs im Signatur-Pflichtmodus
- content-addressed Storage-Pfade ohne Upsert
- Readback-Pflicht auch bei bereits vorhandenen Storage-Objekten
- Ablehnung eines abweichenden Supabase-Readbacks
- monotone Release-Sequenzen
- Freigabe eines Releases erst nach unveroeffentlichtem Insert und DB-Readback

## Erwarteter Supabase-Stand

Das Tool erwartet:

- einen existierenden Public-Bucket, Standardname `firmware`
- die Tabelle `public.firmware_releases`
- die additiven Signaturspalten aus dem Vertrag
- die Public-Read-Policy, die nur `published=true` sichtbar macht

## Hinweise

- `storage_path` wird als `bucket/pfad/zur/datei.bin` gespeichert
- die App baut daraus spaeter automatisch die Download-URL
- neue Objekte verwenden
  `<target>/sha256/<firmware-sha256>.bin`
- bei gleichem `target` + `version` werden abweichende Release-Daten abgelehnt
  und niemals aktualisiert
- ein exakt identischer Lauf ist idempotent: Ein bereits veroeffentlichtes
  Release wird nicht erneut geschrieben; ein noch unveroeffentlichter Lauf
  wird kontrolliert fortgesetzt
- weil der aktuelle Firmware-Bucket public ist, ist ein Objekt mit bekanntem
  exaktem Pfad technisch bereits abrufbar; fuer App und Geraete wird es aber
  erst durch den verifizierten `published=true`-Datensatz auffindbar
- `OTA_SIGNING_MODE=required` ist der Produktionsstandard
- `OTA_SIGNING_MODE=disabled` ist nur ein bewusster Legacy-/Diagnosemodus fuer
  das ECDSA-Manifest und darf nicht fuer neue Produktionsreleases verwendet
  werden; Central bleibt dabei trotzdem RSA-3072-signaturpflichtig
- die privaten Produktionsschluessel duerfen niemals nach Git oder Supabase

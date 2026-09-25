# CampClimate OTA Release Signing v1

Stand: 2026-09-16

## Ziel

Ein Angreifer darf auch dann keine fremde Firmware installieren koennen, wenn er:

- einen Storage-Pfad oder eine OTA-URL manipuliert
- einen Supabase-Release-Datensatz veraendert
- Firmware-Datei und gespeicherten SHA256 gemeinsam austauscht
- einen alten, aber ehemals gueltigen Release erneut anbietet

Die privaten Produktionsschluessel bleiben ausschliesslich beim Hersteller.
Basic, Central und Factory-Installer erhalten nur die jeweils erforderlichen
oeffentlichen Schluessel.

## Kryptografischer Manifestvertrag

- Manifest-Version: `1`
- Algorithmus: `ECDSA P-256` mit `SHA-256`
- Signaturformat: ASN.1-DER, anschliessend Base64
- Textkodierung: UTF-8
- Zeilenende: ausschliesslich `LF`
- SHA256: 64 kleingeschriebene Hex-Zeichen

Exakt signierter Text:

```text
campclimate-firmware-release
manifest_version=1
signature_algorithm=ecdsa-p256-sha256
signing_key_id=<key-id>
target=<basic|central|outdoor>
version=<firmware-version>
release_sequence=<monotone-ganzzahl>
file_size_bytes=<dateigroesse>
sha256=<firmware-sha256>
```

Auch die letzte Zeile endet mit `LF`.

Nicht signiert werden `notes`, `mandatory`, `published`, Download-URL oder
Storage-Pfad. Diese Werte steuern Anzeige und Auslieferung, aber nicht die
Identitaet der Firmware. Der signierte Datei-Hash bindet die konkrete Firmware
an Ziel, Version und Release-Sequenz.

## Zusaetzlicher Central-Binaervertrag

Central-Produktionsimages besitzen vor der Manifestbildung eine zweite
Signaturschicht:

- ESP32-S3 Secure Boot V2
- RSA-3072
- genau ein gueltiger Signaturblock
- Image-Typ `production`
- Hardwarekennung `2.0`
- Image-Policy-Version `1`
- Release-Sequenz im festen `CCIMG001`-Deskriptor identisch mit dem Manifest
- Security-Generation im gueltigen Bereich `0..16`

Der Publisher signiert einen frischen, noch unsignierten Central-Build mit dem
externen RSA-Schluessel und verifiziert das Ergebnis sofort. Erst danach werden
Dateigroesse und SHA256 fuer das ECDSA-Manifest berechnet. Direkt vor dem Upload
wird die RSA-Signatur erneut kryptografisch verifiziert. Dadurch bindet die
Manifest-Signatur exakt das bereits Secure-Boot-signierte BIN.

Dieser Binaervertrag gilt fuer Central auch dann, wenn der alte
`OTA_SIGNING_MODE` bewusst auf `disabled` steht. Basic bleibt von dieser
zusaetzlichen RSA-Schicht unberuehrt.

## Bedeutung der Release-Sequenz

`release_sequence` ist pro Target streng monoton:

- Basic, Central und Outdoor haben getrennte Sequenzen.
- Der Publisher verlangt fuer neue Releases eine groessere Sequenz als im
  veroeffentlichten Katalog; identische Releases koennen idempotent wiederholt werden.
- Basic und Outdoor verlangen auf dem Geraet eine strikt groessere Sequenz. Central erlaubt
  die erneute Installation derselben Sequenz, aber keinen Produktions-Downgrade.
- Kunden-Recovery installiert ebenfalls nur Produktion ab der bestaetigten
  Releaseuntergrenze. Private Factory- und Recovery-Imageklassen erhalten
  dadurch keinen Zugang zum Kundenkatalog.

Die Sequenz ist nicht mit Espressifs eFuse-`secure_version` gleichzusetzen.
Application-Level-Anti-Rollback ist die erste Stufe. Der Publisher kann
Central-BINs inzwischen fuer Hardware Secure Boot signieren. Die kontrollierte
Aktivierung der eFuses, Flash Encryption und der Hardware-Anti-Rollback-Policy
bleiben getrennte Produktionsschritte mit eigenem Hardware-Nachweis.

Die Sequenz ist im Firmware-BIN enthalten. Basic- und Outdoor-Produktionsbuilds enthalten
genau eine Marke:

```text
CCFWSEQ1<little-endian uint64 release_sequence>
```

Central verwendet den 64-Byte-Deskriptor `CCIMG001` an Offset 288. Dessen Wert
wird vom Imagewerkzeug gegen das signierte Image geprueft; die
`CCFWSEQ1`-Marke ist bei Central keine Voraussetzung mehr.

Der Publisher setzt `CAMPCLIMATE_RELEASE_SEQUENCE` beim Build und verweigert
die Signatur, wenn Deskriptor beziehungsweise Basic-/Outdoor-Marke nicht passen. Zusaetzlich wird die
Sequenz gegen den hoechsten signierten Supabase-Stand desselben Targets
geprueft.

## Schluesselmodell

ECDSA P-256 und RSA-3072 sind getrennte Schluessel mit getrennten Aufgaben.

### Privater Manifest-Schluessel

- verschluesselte PKCS#8-PEM-Datei
- niemals in Git, Supabase, Firmware, App oder Cloud-Funktionen
- Arbeitskopie ausserhalb aller Projektordner
- Passphrase im macOS-Schluesselbund
- zwei verschluesselte Offline-Backups an getrennten Orten
- Fingerprint und Key-ID in der technischen Dokumentation

### Oeffentlicher Manifest-Schluessel

- darf in Git liegen
- ist in Basic, Central und beide Factory-Installer eingebaut
- wird ueber `signing_key_id` ausgewaehlt
- darf waehrend einer Rotation parallel zu einem Folgeschluessel vertraut werden

Die Key-ID wird aus Zweck, Algorithmus und dem Anfang des
SHA256-SPKI-Fingerprints gebildet:

```text
production-p256-<16-hex-zeichen>
test-p256-<16-hex-zeichen>
```

Test- und Produktionsschluessel muessen getrennt bleiben.

### Central Secure-Boot-Schluessel

- RSA-3072-Privatschluessel ausschliesslich auf dem geschuetzten Release-Rechner
- Konfiguration nur ueber `CENTRAL_SECURE_BOOT_PRIVATE_KEY`
- echter absoluter Pfad, keine relative Angabe und kein `~`
- ausserhalb aller Git-Repositories
- lokale Dateiberechtigung exakt auf den aktuellen Benutzer begrenzt (`0600`)
- keine Aufnahme des Schluessels oder seines Pfads in Log, Release-Akte,
  Supabase, Firmware oder App
- zwei getrennte, verschluesselte Offline-Backups

Der zum Geraet passende oeffentliche RSA-Schluessel beziehungsweise dessen
Digest wird ueber den Espressif-Secure-Boot-Prozess verankert. Der
RSA-Schluessel ersetzt nicht den P-256-Manifestschluessel.

## Publisher-Ablauf

Im Modus `OTA_SIGNING_MODE=required`:

1. Produktionsfirmware frisch aus den Sources bauen.
2. Release-Sequenz als Build-Metadatum injizieren.
3. bei Central Image-Typ, Hardware, Policy und Sequenz pruefen.
4. bei Central das unsignierte BIN mit RSA-3072 signieren und sofort mit
   `espsecure.py` verifizieren.
5. eingebetteten Sequenzwert aus dem Central-Deskriptor beziehungsweise der
   eindeutigen Basic-/Outdoor-BIN-Marke pruefen.
6. Dateigroesse und SHA256 des auszuliefernden BIN bestimmen.
7. kanonisches Manifest erzeugen.
8. Passphrase aus dem macOS-Schluesselbund lesen.
9. Manifest mit dem privaten P-256-Schluessel signieren.
10. Manifest-Signatur sofort mit dem konfigurierten oeffentlichen Schluessel pruefen.
11. vor dem Upload Datei erneut auf Groesse und SHA256 pruefen und bei Central
    die RSA-Signatur erneut verifizieren.
12. Firmware unter
   `<target>/sha256/<firmware-sha256>.bin` ohne Upsert hochladen.
13. das vollstaendige Storage-Objekt zuruecklesen und Groesse sowie SHA256
   erneut pruefen.
14. Release-Datensatz mit `published=false` neu einfuegen.
15. den unveroeffentlichten Datensatz aus Supabase zuruecklesen und alle
    Identitaets- und Signaturfelder vergleichen.
16. erst danach exakt diesen Datensatz auf `published=true` setzen.
17. lokale Release-Akte neben dem archivierten BIN speichern und private
    Central-Zwischenartefakte entfernen.

Ein vorhandenes beliebiges BIN wird im Pflichtmodus standardmaessig abgelehnt.
Der kontrollierte Ausnahmeweg `OTA_ALLOW_EXISTING_SIGNED_BIN=1` ist kein
Produktionsstandard. Bei Central darf dieser Weg nur ein bereits mit dem
konfigurierten RSA-Schluessel erfolgreich verifiziertes Produktionsimage
kopieren; ein beliebiges Bestands-BIN wird nicht nachsigniert.

## Supabase-Erweiterung

Die additive Phase-1-Migration wurde am 2026-07-16 erfolgreich eingespielt und
verifiziert. `public.firmware_releases` besitzt:

- `manifest_version integer`
- `signature_algorithm text`
- `signing_key_id text`
- `release_sequence bigint`
- `signature_base64 text`

Die Migration ist additiv. Alle 52 bestehenden Releases bleiben lesbar.
Signaturfelder sind per Constraint entweder vollstaendig gesetzt oder
vollstaendig leer. Release-Sequenzen sind pro Target eindeutig.

Der Publisher verhindert Rueckwaertssequenzen bereits vor dem Upload.
Supabase erzwingt die Monotonie zusaetzlich atomar ueber den internen
Sequenzkopf.

## Bestandsgeraete und Bridge-Release

1. Alte Firmware kennt nur HTTPS und SHA256.
2. Signer, Datenbankfelder und Firmware-Pruefer werden vorbereitet.
3. Eine signierte Bridge-Firmware wird ueber den bisherigen OTA-Weg angeboten.
4. Alte Geraete koennen diese Version weiterhin installieren; sie ignorieren
   die zusaetzlichen Signaturfelder.
5. Die Bridge-Firmware enthaelt den oeffentlichen Schluessel und akzeptiert
   danach nur noch gueltig signierte Releases mit hoeherer Sequenz.
6. Neue Produktionsgeraete erhalten die Pruefung direkt ab Werk.
7. Erst nach ausreichender Migration wird der allgemeine Legacy-Pfad gesperrt.

Die erste Installation der Bridge-Firmware auf einem Altgeraet kann
zwangslaeufig noch nicht durch dieses Altgeraet signaturgeprueft werden. Danach
ist die kryptografische Vertrauenskette geschlossen.

Fuer sehr lange offline gebliebene Geraete darf ein spaeterer Legacy-Endpunkt
nur genau die festgelegte Bridge-Version ausliefern, niemals eine frei
waehlbare URL oder beliebige Firmware.

## Umgesetzter Runtime-Vertrag

- Central und Basic pruefen die ECDSA-Signatur.
- Beide Factory-Installer pruefen denselben Vertrag.
- Central uebergibt die Metadaten ueber authentisierte OTA-v2-Pakete.
- Cloud-Commands enthalten nur die Release-ID.
- Central und Basic speichern einen persistenten Anti-Rollback-Stand.

Noch offen:

- erste signierte Bridge-Releases veroeffentlichen und auf Hardware testen
- OTA-Audit-Log
- Secure-Boot-/Flash-Encryption-eFuses kontrolliert in der Produktion aktivieren
- komplette Secure-Boot-, Recovery- und UART-Rettungskette auf Hardware testen
- eFuse-Anti-Rollback-Generationen final festlegen

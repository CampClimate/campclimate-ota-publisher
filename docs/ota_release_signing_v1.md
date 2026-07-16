# CampClimate OTA Release Signing v1

Stand: 2026-07-16

## Ziel

Ein Angreifer darf auch dann keine fremde Firmware installieren koennen, wenn er:

- einen Storage-Pfad oder eine OTA-URL manipuliert
- einen Supabase-Release-Datensatz veraendert
- Firmware-Datei und gespeicherten SHA256 gemeinsam austauscht
- einen alten, aber ehemals gueltigen Release erneut anbietet

Der private Produktionsschluessel bleibt ausschliesslich beim Hersteller. Basic,
Central und Factory-Installer erhalten nur den oeffentlichen Schluessel.

## Kryptografischer Vertrag

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
target=<basic|central>
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

## Bedeutung der Release-Sequenz

`release_sequence` ist pro Target streng monoton:

- Basic und Central haben getrennte Sequenzen.
- Ein normales Produktionsupdate muss eine groessere Sequenz besitzen als die
  aktuell installierte Firmware.
- Gleiche oder kleinere Sequenzen werden im Kundenpfad abgelehnt.
- Ein lokaler Factory-/Recovery-Pfad darf spaeter einen bewusst autorisierten
  Sonderweg erhalten.

Die Sequenz ist nicht mit Espressifs eFuse-`secure_version` gleichzusetzen.
Application-Level-Anti-Rollback ist die erste Stufe. Hardware Secure Boot,
Flash Encryption und eFuse-Anti-Rollback bleiben eine spaetere
Produktionshaertung.

Vor Freigabe fuer Kunden muss die Sequenz auch in der Firmware selbst enthalten
sein. Der Publisher muss dann pruefen, dass Eingabe, Source und BIN denselben
Wert tragen. Die aktuelle Publisher-Vorbereitung nimmt die Sequenz noch als
Operator-Eingabe beziehungsweise aus `env`, prueft sie aber bereits gegen die
hoechste in Supabase vorhandene signierte Sequenz desselben Targets.

## Schluesselmodell

### Privater Schluessel

- verschluesselte PKCS#8-PEM-Datei
- niemals in Git, Supabase, Firmware, App oder Cloud-Funktionen
- Arbeitskopie ausserhalb aller Projektordner
- Passphrase im macOS-Schluesselbund
- zwei verschluesselte Offline-Backups an getrennten Orten
- Fingerprint und Key-ID in der technischen Dokumentation

### Oeffentlicher Schluessel

- darf in Git liegen
- wird spaeter in Basic, Central und beide Factory-Installer eingebaut
- wird ueber `signing_key_id` ausgewaehlt
- darf waehrend einer Rotation parallel zu einem Folgeschluessel vertraut werden

Die Key-ID wird aus Zweck, Algorithmus und dem Anfang des
SHA256-SPKI-Fingerprints gebildet:

```text
production-p256-<16-hex-zeichen>
test-p256-<16-hex-zeichen>
```

Test- und Produktionsschluessel muessen getrennt bleiben.

## Publisher-Ablauf

Im Modus `OTA_SIGNING_MODE=required`:

1. Produktionsfirmware frisch aus den Sources bauen.
2. Dateigroesse und SHA256 bestimmen.
3. kanonisches Manifest erzeugen.
4. Passphrase aus dem macOS-Schluesselbund lesen.
5. Manifest mit dem privaten Schluessel signieren.
6. Signatur sofort mit dem konfigurierten oeffentlichen Schluessel pruefen.
7. vor dem Upload Datei erneut auf Groesse und SHA256 pruefen.
8. Firmware unter
   `<target>/sha256/<firmware-sha256>.bin` ohne Upsert hochladen.
9. das vollstaendige Storage-Objekt zuruecklesen und Groesse sowie SHA256
   erneut pruefen.
10. Release-Datensatz mit `published=false` neu einfuegen.
11. den unveroeffentlichten Datensatz aus Supabase zuruecklesen und alle
    Identitaets- und Signaturfelder vergleichen.
12. erst danach exakt diesen Datensatz auf `published=true` setzen.
13. lokale Release-Akte neben dem archivierten BIN speichern.

Ein vorhandenes beliebiges BIN wird im Pflichtmodus standardmaessig abgelehnt.
Der kontrollierte Ausnahmeweg `OTA_ALLOW_EXISTING_SIGNED_BIN=1` ist kein
Produktionsstandard.

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

Der Publisher verhindert zusaetzlich normale Rueckwaertssequenzen bereits vor
dem Upload. Fuer den spaeteren Mehrprozess- oder CI-Betrieb bleibt ein
serverseitig atomarer Monotonie-Guard als weitere Supabase-Haertung vorgesehen.

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

## Noch nicht durch diese Publisher-Phase geloest

- Signaturpruefung in Central-OTA
- Signaturpruefung in Basic-OTA
- Signaturpruefung in Central- und Basic-Factory-Installer
- Uebergabe der Signaturmetadaten von Central an Basic
- automatischer Abgleich der Release-Sequenz mit Source und BIN
- serverseitig atomare Monotonie-Pruefung fuer parallele Publisher
- Command-Vertrag ausschliesslich ueber serverseitig validierte Release-ID
- Hardware Secure Boot, Flash Encryption und eFuse-Anti-Rollback

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

Die Sequenz ist im Firmware-BIN enthalten. Produktionsbuilds enthalten genau
eine Marke:

```text
CCFWSEQ1<little-endian uint64 release_sequence>
```

Der Publisher setzt `CAMPCLIMATE_RELEASE_SEQUENCE` beim Build und verweigert
die Signatur, wenn Marke oder Wert nicht exakt passen. Zusaetzlich wird die
Sequenz gegen den hoechsten signierten Supabase-Stand desselben Targets
geprueft.

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

## Publisher-Ablauf

Im Modus `OTA_SIGNING_MODE=required`:

1. Produktionsfirmware frisch aus den Sources bauen.
2. Release-Sequenz als Build-Metadatum injizieren.
3. eindeutige BIN-Marke und eingebetteten Sequenzwert pruefen.
4. Dateigroesse und SHA256 bestimmen.
5. kanonisches Manifest erzeugen.
6. Passphrase aus dem macOS-Schluesselbund lesen.
7. Manifest mit dem privaten Schluessel signieren.
8. Signatur sofort mit dem konfigurierten oeffentlichen Schluessel pruefen.
9. vor dem Upload Datei erneut auf Groesse und SHA256 pruefen.
10. Firmware unter
   `<target>/sha256/<firmware-sha256>.bin` ohne Upsert hochladen.
11. das vollstaendige Storage-Objekt zuruecklesen und Groesse sowie SHA256
   erneut pruefen.
12. Release-Datensatz mit `published=false` neu einfuegen.
13. den unveroeffentlichten Datensatz aus Supabase zuruecklesen und alle
    Identitaets- und Signaturfelder vergleichen.
14. erst danach exakt diesen Datensatz auf `published=true` setzen.
15. lokale Release-Akte neben dem archivierten BIN speichern.

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
- Hardware Secure Boot, Flash Encryption und eFuse-Anti-Rollback

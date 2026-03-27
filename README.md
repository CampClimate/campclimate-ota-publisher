# CampClimate OTA Publisher

Kleines lokales Python-Tool, das eine Firmware-`.bin` aus dem `drop`-Ordner nimmt und danach:

- SHA256 berechnet
- Datei nach Supabase Storage hochlaedt
- einen Eintrag in `public.firmware_releases` anlegt oder aktualisiert
- die hochgeladene Datei in `archive` verschiebt

## Einrichtung

1. `.env.example` nach `env` kopieren
2. `SUPABASE_SERVICE_ROLE_KEY` eintragen
3. Sicherstellen, dass dein Supabase-Schema bereits einmalig angelegt wurde

Wenn Python auf macOS mit einem SSL-Zertifikatsfehler scheitert, kannst du fuer den lokalen Test voruebergehend setzen:

```text
SUPABASE_INSECURE_SSL=1
```

Das sollte nur lokal und bewusst als Fallback genutzt werden.

## Nutzung

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

## Erwarteter Supabase-Stand

Das Tool erwartet:

- einen existierenden Public-Bucket, Standardname `firmware`
- die Tabelle `public.firmware_releases`

## Hinweise

- `storage_path` wird als `bucket/pfad/zur/datei.bin` gespeichert
- die App baut daraus spaeter automatisch die Download-URL
- bei gleichem `target` + `version` wird der Release-Eintrag aktualisiert

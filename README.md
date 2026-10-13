# GAMETIKA – komplettes Projekt (Netlify + Render + PostgreSQL)

## Dateien
- `public/index.html`: Login, Registrierung, Profil, Profilbild, Video-Feed, Kommentare, Likes, Follow/Freunde, öffentlicher Live-Chat, private Nachrichten und Admin-Oberfläche. Videos: maximal 35.000.000 Bytes (35 MB). Profilbilder: maximal 3 MiB.
- `server.js`: Express API, PostgreSQL, JWT/Bcrypt, Socket.IO, Uploads und Admin-Routen.
- `package.json`: Backend-Abhängigkeiten und Startskript.
- `render.yaml`: Render-Konfiguration mit persistentem Upload-Datenträger.
- `netlify.toml`: Netlify veröffentlicht `public/`.

## Wichtig vor dem Livebetrieb
Der Frontend-API-Endpunkt in `public/index.html` ist aktuell `https://gametika.onrender.com`. Die Render-Blueprint-Datei verwendet ebenfalls den Dienstnamen `gametika`. Nach dem Deploy muss die tatsächliche Render-Adresse exakt mit `API_BASE` übereinstimmen; bei abweichender URL `API_BASE` in `public/index.html` anpassen und Netlify neu deployen.

## Render einrichten
1. Lade den gesamten Ordnerinhalt in ein eigenes GAMETIKA-GitHub-Repository hoch (nicht in das Montenegro-Reisen-Repository).
2. Erstelle eine PostgreSQL-Datenbank in Render.
3. Erstelle/aktualisiere den Render-Webdienst mit `npm install` als Build Command und `npm start` als Start Command.
4. Setze `DATABASE_URL` auf die interne PostgreSQL-Verbindungs-URL. Setze `JWT_SECRET` auf einen zufälligen geheimen Wert mit mindestens 32 Zeichen. Setze `UPLOAD_DIR=/var/data/uploads`.
5. Setze `ADMIN_USERNAME`, `ADMIN_PASSWORD` und optional `ADMIN_DISPLAY_NAME`. Nutze ein starkes, einzigartiges Admin-Passwort.
6. Der Render-Webdienst braucht einen persistenten Datenträger unter `/var/data`, damit hochgeladene Medien Deployments überleben. Der `render.yaml` enthält die Datenträger-Konfiguration.
7. Nach dem Deploy öffne `https://DEIN-DIENST.onrender.com/health`. Erwartet wird `ok: true` und `database: connected`.

## Netlify einrichten
1. Verbinde Netlify mit dem GAMETIKA-GitHub-Repository.
2. Publish directory: `public`; Build command leer lassen.
3. Deploye und öffne die Website. Registrierung/Login/Uploads/Chat funktionieren erst, wenn Render und PostgreSQL korrekt laufen.

## PayPal
Die E-Mail `Montenegroreisencompany@gmail.com` wird als Empfänger für manuelle Zahlungen angezeigt. Das ist **keine** aktive automatische Zahlungslösung. Für einen echten PayPal-Checkout auf der Website benötigst du eine PayPal-Developer-App und musst `Client ID` und `Secret` sicher als Umgebungsvariablen im Backend hinterlegen. Gib diese Geheimnisse niemals in HTML/GitHub ein.

## Prüfung
Syntaxprüfung von `server.js` und dem Inline-JavaScript sowie grundlegende Projektstruktur können lokal geprüft werden. Ein echter End-to-End-Test von Registrierung, Login, Datenbank, Uploads und Chat ist erst nach Deployment mit deinen echten Render-Daten möglich.

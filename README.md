# Colors - HackMyVM (Medium)

![Colors Icon](Colors.png)

## Übersicht

*   **VM:** Colors
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Colors)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 06. April 2023
*   **Original-Writeup:** https://alientec1908.github.io/Colors_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Die virtuelle Maschine "Colors" von HackMyVM (Schwierigkeitsgrad: Medium) bot einen vielschichtigen Weg zur Kompromittierung. Der Einstieg erfolgte durch die Analyse von Dateien auf einem anonymen FTP-Server, wobei Steganographie zur Offenlegung von Zugangsdaten führte. Port Knocking war notwendig, um den SSH-Port zu öffnen. Nach dem initialen SSH-Zugriff wurde eine Webshell platziert, um als `www-data` zu agieren. Eine unsichere `sudo`-Regel für `vim` ermöglichte die Eskalation zum Benutzer `green`. Durch das Lösen eines "Rate die Zahl"-Spiels wurden Credentials für den Benutzer `purple` erlangt. Die finale Rechteausweitung zu Root erfolgte durch DNS-Spoofing und die Ausnutzung eines weiteren unsicheren `sudo`-Eintrags, der ein Skript ausführte, das seinerseits ein Skript von einer kontrollierbaren URL herunterlud und ausführte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `wget`
*   `stegseek`
*   `steghide`
*   `cat`
*   CyberChef (für Base85 Dekodierung)
*   `ftp`
*   `knock`
*   `exiftool`
*   `telnet`
*   `ssh`
*   `nc` (netcat)
*   `python3` (für Shell-Stabilisierung und Webserver)
*   `stty`
*   `sudo`
*   `vim`
*   `nano`
*   `bettercap` (für ARP- & DNS-Spoofing)
*   `curl`
*   Standard Linux-Befehle (`echo`, `chmod`, `find`, `mv`, `id`, `su`, `cd`, `ls`, `ping`, `apt-get`, `sh`, `ip`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Colors" verlief in folgenden Hauptphasen:

1.  **Reconnaissance & FTP Enumeration:**
    *   Ziel-IP (`192.168.2.120`, Hostname `color.hmv`) via `arp-scan` und `/etc/hosts` identifiziert.
    *   `nmap` zeigte Port 21 (FTP - vsftpd 3.0.3 mit Anonymous Login), Port 22 (SSH - gefiltert) und Port 80 (HTTP - Apache 2.4.54).
    *   Auf dem anonymen FTP-Server wurden leere Dateien (`first`, `second`, `third` mit User/Group IDs 1127, 1039, 1081) und die Datei `secret.jpg` gefunden.
    *   `gobuster` auf Port 80 fand `/index.html` und `/manual/`.

2.  **Steganographie & Port Knocking:**
    *   Mittels `stegseek` (mit `rockyou.txt`) und `steghide` wurde aus `secret.jpg` (Passwort: `Nevermind`) die Datei `more_secret.txt` extrahiert.
    *   Der Inhalt von `more_secret.txt` war Base85-kodiert und enthielt nach Dekodierung die Zugangsdaten `pink:Pink4sPig$$`.
    *   Die User/Group IDs der leeren FTP-Dateien (1127, 1039, 1081) wurden als Port-Knocking-Sequenz interpretiert.
    *   `knock 192.168.2.120 1127 1039 1081` öffnete den SSH-Port (22).

3.  **Initial Access (SSH als pink & Web Shell als www-data):**
    *   FTP-Login als `pink` mit dem Passwort `Pink4sPig$$` war erfolgreich.
    *   Ein eigener öffentlicher SSH-Schlüssel wurde in das `.ssh/authorized_keys`-Verzeichnis von `pink` via FTP hochgeladen.
    *   Erfolgreicher SSH-Login als `pink` mittels Schlüsselauthentifizierung.
    *   (Alternativer Weg/Test im Log) Eine `shell.php` wurde von `pink` in `/var/www/html/` platziert und ausführbar gemacht.
    *   Aufruf der `shell.php` (impliziert) führte zu einer Reverse Shell als `www-data`.

4.  **Privilege Escalation (www-data zu green):**
    *   `sudo -l` für `www-data` zeigte: `(green) NOPASSWD: /usr/bin/vim`.
    *   Mittels `sudo -u green vim -c ':!/bin/sh'` wurde eine Shell als Benutzer `green` erlangt.

5.  **Lateral Movement (green zu purple):**
    *   Im Home-Verzeichnis von `green` wurde das Programm `test_4_green` (gehört `root`) gefunden.
    *   Ein Python-Skript wurde erstellt, um dieses "Rate die Zahl"-Spiel zu lösen.
    *   Das Spiel gab bei Erfolg das Passwort `purpleaslilas` preis.
    *   Mit `su purple` und diesem Passwort wurde zum Benutzer `purple` gewechselt.
    *   Die User-Flag wurde aus `/home/purple/user.txt` gelesen.

6.  **Privilege Escalation (purple zu root):**
    *   `sudo -l` für `purple` zeigte: `(root) NOPASSWD: /attack_dir/ddos.sh`.
    *   Das Skript `/attack_dir/ddos.sh` lud via `curl` ein weiteres Skript (`attack.sh`) von `http://masterddos.hmv/attack.sh` herunter und führte es mit `sh -p` aus.
    *   Mittels `bettercap` wurde ARP-Spoofing gegen das Ziel und DNS-Spoofing für `masterddos.hmv` (Umleitung auf Angreifer-IP) eingerichtet.
    *   Auf dem Angreifer-System wurde ein Webserver mit einer `attack.sh` (die einen Reverse-Shell-Payload enthielt) und ein Netcat-Listener gestartet.
    *   Ausführung von `sudo -u root /attack_dir/ddos.sh` als `purple` lud das manipulierte Skript vom Angreifer herunter und führte es als Root aus.
    *   Eine Root-Shell wurde auf dem Listener des Angreifers empfangen.
    *   Die Root-Flag wurde aus `/root/proof.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Anonymer FTP-Zugang:** Preisgabe von Dateien, die Hinweise auf Port Knocking und Steganographie enthielten.
*   **Steganographie:** Verstecken von Zugangsdaten in einer Bilddatei (`stegseek`, `steghide`, Base85-Dekodierung).
*   **Port Knocking:** Schutz des SSH-Dienstes durch eine spezifische Port-Sequenz.
*   **Unsichere `sudo`-Konfigurationen:**
    *   `www-data` konnte `vim` als `green` ausführen (Shell-Escape).
    *   `purple` konnte ein Skript als `root` ausführen, das Code von einer externen, manipulierbaren Quelle herunterlud und ausführte.
*   **Informationslecks:** Passwörter als Ausgabe von Programmen (Rätselspiel).
*   **DNS-Spoofing & ARP-Spoofing (`bettercap`):** Umleitung von Netzwerkverkehr zur Ausführung von eigenem Code.
*   **Web Shell:** Platzieren und Ausführen einer PHP-Shell für RCE.

## Flags

*   **User Flag (`/home/purple/user.txt`):** `(:Ez_Colors:)`
*   **Root Flag (`/root/proof.txt`):** `(:go_play_some_minecraft:)`

## Tags

`HackMyVM`, `Colors`, `Medium`, `FTP`, `Steganography`, `Port Knocking`, `SSH`, `Web Shell`, `Sudo Privilege Escalation`, `Vim Escape`, `DNS Spoofing`, `ARP Spoofing`, `Bettercap`, `Linux`

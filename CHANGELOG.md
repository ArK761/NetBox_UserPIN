# Changes / Zmeny

The full guides: [`docs/GUIDE_User_PIN_EN.pdf`](docs/GUIDE_User_PIN_EN.pdf) (English) ·
[`docs/NAVOD_User_PIN_SK.pdf`](docs/NAVOD_User_PIN_SK.pdf) (Slovenčina).
Sources of the guides and the build script: `docs/src/` (`python3 docs/src/build.py`).

The version in the code is **2.0.0** (the GitHub release) and **2.0.1** (branch `feature/exception-allowlist`).
The base was 0.38.4 (commit 7bed7de); the interim numbers 2.0.1 … 2.2.2 in the commit history of 27–30 October 2026
were working labels, everything is part of the 2.0.0 line and is listed by topic below.
Verzia v kóde je **2.0.0** (vydanie) a **2.0.1** (vetva `feature/exception-allowlist`); priebežné čísla 2.0.1 … 2.2.2
v histórii commitov boli pracovné označenia, všetko patrí do línie 2.0.0 a je rozdelené podľa tém.

## 2.0.1 – permissions of exceptions / oprávnenia výnimiek

* An exception is no longer "all or nothing": a keeper ticks what the user may use. The password is allowed by
  default; profile, preferences, bookmarks, notifications, subscriptions, API tokens and the API (REST, GraphQL) with a
  token must be allowed one by one. / Výnimka už nie je „všetko alebo nič“: strážca zaškrtáva, čo smie používateľ
  používať. Heslo je povolené predvolene, ostatné (profil, predvoľby, záložky, notifikácie, odbery, API tokeny a API
  s tokenom) sa povoľujú po jednom.
* What is not allowed disappears from the menu and the tabs and the direct address answers 403; a token without the
  allowed API is refused. A keeper is never limited. / Čo nie je povolené, zmizne z menu a kariet a priama adresa
  vráti 403; token bez povoleného API je odmietnutý. Strážca nie je nikdy obmedzený.
* A "Change the password" link in the user menu (NetBox has none); the bell is hidden when notifications are not
  allowed. / Odkaz „Zmeniť heslo“ v menu (NetBox ho nemá); zvonček sa skryje, ak nie sú povolené notifikácie.
* An arrow under the name of every user unfolds the check boxes; green ✓ / red ✗ tags show what is allowed. A user
  who has an exception is not offered again. / Šípka pod menom používateľa rozbalí zaškrtávacie polia; zelené ✓ /
  červené ✗ štítky ukazujú, čo je povolené. Používateľ s výnimkou sa neponúka znova.
* New field `PolicyException.allowed` (migration `0042`). Existing exceptions get only the password. / Nové pole
  `PolicyException.allowed` (migrácia `0042`); existujúce výnimky dostanú len heslo.

## Keys and security / Kľúče a bezpečnosť

* Key rotation covers 2FA, backup codes, the SMTP password and the PIN-only index; `userpin_check` verifies every
  encrypted value. / Rotácia kľúča pokrýva 2FA, záložné kódy, SMTP heslo aj index PIN-only; `userpin_check` overí
  každú šifrovanú hodnotu.
* Remove the PIN of a user without 2FA; `userpin_area_owners` checks eligibility. / Odstránenie PINu používateľa bez
  2FA; `userpin_area_owners` kontroluje oprávnenosť.
* The master manages the PINs while there is no CORE deputy, even with keepers. / Master spravuje PINy, kým nie je
  zástupca CORE, aj pri existujúcich strážcoch.

## The model of protection / Model ochrany

* The PIN rules only the PIN-only accesses and the users in a group or section managers; everybody else works by
  NetBox permissions. / PIN riadi iba prístupy len cez PIN a používateľov v skupine alebo správcov; ostatní podľa
  oprávnení NetBoxu.
* PIN-only accesses are no NetBox users (hidden from lists), have no requests; without a group only the PIN. /
  Prístupy len cez PIN nie sú používatelia NetBoxu (skryté), nemajú žiadosti; bez skupiny len PIN.
* Protection ON rules everybody but keepers and exceptions; OFF leaves NetBox alone and pauses the PIN-only accesses;
  the ON/OFF switch is in the interface (keepers only). / Ochrana ZAP riadi všetkých okrem strážcov a výnimiek; VYP
  necháva NetBox a pozastaví prístupy len cez PIN; prepínač je v rozhraní (len strážcovia).
* Keepers: the last-keeper rule, emergency commands `userpin_keeper`, `userpin_default_deny`. / Strážcovia: pravidlo
  posledného strážcu, núdzové príkazy.

## Section managers and requests / Správcovia úsekov a žiadosti

* A section manager with full power over his section (keepers above), PIN-only accesses under a manager, requests to
  the manager and the keepers, e-mails about the decisions. / Správca úseku s plnou mocou nad úsekom (strážcovia
  nad ním), prístupy len cez PIN pod správcom, žiadosti správcovi aj strážcom, e-maily o rozhodnutiach.

## PIN-only accesses / Prístupy len cez PIN

* E-mails both ways: the person about changes of an administrator; the administrators a summary every N minutes or at
  every change (never both); subject `PinUserNNNN made a change`, body: time, object, changed fields; sent through
  `netbox-rq` after the save. / E-maily oboma smermi: osoba o zmenách správcu; správcovia zhrnutie každých N minút
  alebo pri každej zmene (nikdy oboje); odosiela sa po uložení cez `netbox-rq`.
* Form drop-downs work; own table columns are saved. / Rozbaľovacie zoznamy vo formulároch fungujú; ukladanie vlastných
  stĺpcov.
* Conditions on relation fields: contains / starts with / is one of. / Podmienky pre polia typu relácia: obsahuje /
  začína na / je jedno z.

## Working time / Pracovný čas

* General and own rules, a country with public holidays (`holidays`), working days and hours, always shown. /
  Všeobecné a vlastné pravidlá, krajina so štátnymi sviatkami, pracovné dni a hodiny, vždy zobrazené.
* Read-only outside the time; after the end 30 minutes and one save; the country in the language of the person. /
  Mimo času len čítanie; po konci 30 minút a jedno uloženie; krajina v jazyku osoby.

## Tools / Nástroje

* `tools/pin_check.sh` – checks from outside and on the server; dependency `holidays`. / Kontrola zvonku aj na
  serveri; závislosť `holidays`.
* Slovak translations, README with the 2.x model. / Slovenské preklady, README s modelom 2.x.

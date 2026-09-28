# Návrh: práva k obsahu a dočasný prístup na požiadanie

Stav: **NÁVRH na pripomienkovanie (verzia 2 – ID objektov)** – zatiaľ nič z tohto nie je naprogramované.
Nadväzuje na [navrh-delegovanie-pracoviska.md](navrh-delegovanie-pracoviska.md) (CORE, oddelenia, roly).

---

## 1. Prečo

- Budúce pluginy (Projekty, dokumenty, maily, fotky …) nemajú riešiť vlastné práva. Opýtajú sa PINu:
  „smie človek X urobiť Y s vecou Z?“
- **Nikto nie je boh.** Ani master / CORE nevidí obsah oddelenia, kým mu ho oddelenie nedovolí.
- Keď treba pomôcť (problém so súborom), prístup sa **vyžiada** a správca oddelenia ho **udelí** – iba na
  konkrétnu vec, na krátky čas a so záznamom v audite.

## 2. Zásady

| Zásada | Význam |
|---|---|
| Oddelenie správy od obsahu | CORE spravuje štruktúru (oddelenia, správcovia, PINy); obsah oddelenia riadi jeho správca |
| Predvolene nič | kto nedostal právo, nemá ho – ani superuser |
| Nikto nedá viac, než sám má | správca prideľuje iba vo svojom oddelení a iba to, čo sám smie |
| Práva s dátumom | dočasné práva samy vyprchajú |
| Presun = strata práv | práva viazané na oddelenie zaniknú pri presune do iného oddelenia |
| Všetko do auditu | kto komu čo dal, kto čo použil, kedy, odkiaľ |

## 3. Kto čo smie

| Kto | Smie | Nesmie |
|---|---|---|
| **Master / CORE** | zakladať oddelenia, určovať správcov, spravovať PINy a 2FA; vidieť *kto má aké práva* (kontrola) | vidieť, meniť, mazať **obsah** oddelení bez udeleného prístupu |
| **Správca oddelenia** | prideľovať práva k obsahu svojho oddelenia; udeľovať dočasný prístup | zasahovať do obsahu iného oddelenia |
| **Delegát oddelenia** | zastupuje správcu (s druhým delegátom – štyri oči) | nič mimo oddelenia |
| **Člen** | to, na čo dostal právo | — |

## 4. Katalóg práv (registruje ho každý plugin)

Každý plugin pri štarte povie PINu, aké práva pozná:

```
projects.documents   : read, write, move, delete
projects.mail        : read, send
projects.photos      : read, write, delete
projects.members     : manage
```

PIN tak nemusí vopred vedieť, čo budúce pluginy budú mať. Pri každom práve plugin určí aj **citlivosť**:

- stačí prihlásenie,
- treba odomknutý PIN (napr. čítanie mailov),
- treba PIN + 2FA (napr. mazanie).

## 5. Profily (šablóny)

Aby sa nemuselo klikať 20 zaškrtávadiel pre každého človeka:

| Profil | Obsah |
|---|---|
| Čitateľ | read |
| Editor | read + write |
| Správca obsahu | všetko vrátane move, delete, manage |

*Otvorená otázka č. 2: stačia tieto tri, alebo vlastné profily v UI?*

## 6. Pridelenie práva

Pridelenie = **kto** + **profil alebo konkrétne právo** + **rozsah** + **dokedy (voliteľné)**.

- Rozsah: celé oddelenie (napr. všetky dokumenty IT) alebo konkrétny objekt (projekt P-125479862).
- Dokedy: napr. externista do konca mesiaca – potom právo samo zanikne.
- Prideľuje správca oddelenia (alebo delegát s druhým delegátom), iba ľuďom zo svojho oddelenia.

## 7. Dočasný prístup na požiadanie (Just-in-Time)

Vo svete: Microsoft Customer Lockbox, Azure PIM, CyberArk – technik nevidí dáta, kým mu ich vlastník konkrétne
neschváli, a iba na určitý čas.

### 7.1 Priebeh

1. **Žiadateľ** (napr. ty z CORE) vojde do pluginu a vidí **štruktúru** (priečinky, súbory, zoznam mailov),
   ale obsah neotvorí – tlačidlá sú sivé, s ponukou **„Požiadať o prístup“**.
2. Správca oddelenia ti zavolá: *„problém je so súborom **DOC-000482**“*. Každý objekt má v plugine jedinečné
   **ID** – je smerodajné a vidí ho aj člen oddelenia. Vyhľadáš ID (vidíš iba ID + typ, veľkosť, dátum, nie
   názov ani obsah) → **Požiadať o prístup** a napíšeš **iba dôvod**. Akcie ani čas nevyberáš.
3. **Správcovi oddelenia** sa v jeho relácii zobrazí okno:

   > **Peter Knotek žiada prístup**
   > Súbor: **DOC-000482** – *faktura_0925.pdf* (Účtovníctvo; názov vidí iba správca)
   > Dôvod: poškodený súbor, telefonát s Evou
   >
   > Udeliť: ☐ čítať ☐ upraviť ☐ presunúť ☐ zmazať
   > Na ako dlho: 15 min / 1 h / 4 h / …
   > [ Udeliť ] [ Zamietnuť ]

   **Správca určí rozsah aj čas** a potvrdí **PINom** (nastaviteľné: iba PIN – predvolené / PIN + 2FA;
   voliteľne „pri zmazaní vždy PIN + 2FA“).
4. **Žiadateľ vidí naživo** výsledok: „udelené: čítať, presunúť – do 14:35“. Nepovolené tlačidlá ostanú sivé.

### 7.2 Pravidlá udeleného prístupu

- Iba na **ten jeden objekt** (súbor, mail), nie na celý priečinok.
- Iba **udelené akcie** a iba **do udeleného času** – potom sám zanikne; žiadateľ ho môže ukončiť skôr.
- **Zmazať a presunúť sú jednorazové** – jedno zmazanie, nie hodina mazania.
- Každé otvorenie / úprava / presun / zmazanie sa zapíše do auditu vrátane toho, **kto to udelil**.
- Rovnaký mechanizmus môže použiť ktokoľvek (napr. kolega z iného oddelenia, ktorý potrebuje jeden dokument).

### 7.3 Ako sa správca dozvie o žiadosti

- **Zvonček v NetBoxe + e-mail** – funguje vždy a všade.
- **Vyskakovacie okno** – na stránkach pluginov (PIN, Projekty …). Či ho ide zobraziť aj na bežných stránkach
  NetBoxu (zariadenia, IP …), ešte overím – závisí od toho, čo NetBox 4.7 pluginom dovolí vložiť do každej
  stránky.

## 8. Presun do iného oddelenia

- Práva viazané na oddelenie pri presune **automaticky zaniknú** (PIN).
- Odovzdanie agendy (vlastník projektu, rozrobené úlohy …) rieši plugin, ktorý agendu má. PIN mu dá signály
  `member_moving` / `member_moved`, aby vedel včas reagovať.

## 9. Čo dostanú pluginy (API)

```python
from netbox_user_pin import service, registry

registry.register('projects.documents', actions=('read', 'write', 'move', 'delete'),
                  sensitivity={'read': 'pin', 'delete': 'step_up'})

service.can(user, 'projects.documents', 'read', obj=subor)      # True / False (aj pre superusera!)
service.request_access(user, 'projects.documents', obj=subor, reason='…')
service.grants(user, obj=subor)                                  # čo má udelené a dokedy
```

Kde to ide (bežné view / add / change / delete na objektoch NetBoxu), PIN práva zosynchronizuje aj do NetBox
oprávnení – rovnako ako dnes pri rolách. Jemnejšie práva (napr. „čítať maily projektu“) overuje PIN sám.

## 10. Poctivá poznámka

Plugin zablokuje prístup v NetBoxe. Kto má **prístup k serveru alebo databáze** (root), technicky vidí všetko,
čo nie je zašifrované. Pred ním chráni iba **šifrovanie obsahu** (kľúč oddelenia / projektu + PIN), ktoré sme
rozoberali pri Projektoch.

## 11. Otvorené otázky

| # | Otázka | Môj návrh |
|---|---|---|
| 1 | Má CORE vidieť **názvy súborov a predmety mailov**? | **ROZHODNUTÉ:** každý objekt má v plugine jedinečné **ID**, ktoré je smerodajné. ID vidí aj člen oddelenia a povie ho po telefóne; žiadateľ si ID vyhľadá (vidí iba ID + neutrálne údaje: typ, veľkosť, dátum), dá žiadosť a správca ju vybaví |
| 2 | Profily: stačia Čitateľ / Editor / Správca obsahu, alebo vlastné profily v UI? | začať s tromi, vlastné neskôr |
| 3 | Prideľovať per oddelenie aj per konkrétny objekt, alebo zatiaľ iba per oddelenie? | oboje |
| 4 | Udeľovať dočasný prístup môže **správca aj delegát**, alebo iba správca? | správca alebo jeden delegát |
| 5 | **Maximálna dĺžka** dočasného prístupu? | 24 h |
| 6 | **Núdzový prístup** cez dvoch ľudí z CORE, keď nikto z oddelenia nereaguje? | áno: dvaja z CORE + dôvod, max. 24 h, mail celému oddeleniu |
| 7 | Smie správca dať trvalé právo človeku z **iného oddelenia**? | iba so súhlasom správcu toho oddelenia |
| 8 | **Pravidelná kontrola prístupov** (napr. raz za 6 mesiacov správca potvrdí práva svojich ľudí, nepotvrdené po 30 dňoch zaniknú)? | áno, voliteľné v Nastaveniach |

# Návrh: delegovanie, pracoviská a schvaľovanie štyrmi očami

Stav: **NÁVRH na pripomienkovanie** – zatiaľ nič z tohto nie je naprogramované.
Pripomienky píš priamo sem (alebo mi ich pošli) a dokument upravím.

---

## 1. Prečo

- Delegát bez PINu a 2FA nemá zmysel – nemôže nič potvrdiť.
- Firma má oddelenia (pracoviská). Správu PINov ľudí na pracovisku má robiť ich správca, nie iba hlavný admin.
- Keď niekto chýba (choroba, dovolenka, odchod z firmy), práva sa musia dať bezpečne odovzdať – vždy s pozvánkou,
  kódom v maili a záznamom v audite.

## 2. Pojmy a roly

| Rola | Kto to je | Vidí | Môže |
|---|---|---|---|
| **Superadmin** | NetBox superuser | všetko | všetko; menuje globálnych adminov |
| **Globálny admin** (admin skupina) | delegát menovaný superadminom | všetko | zakladať pracoviská, priraďovať ľudí, menovať / odvolávať správcov pracovísk, pozývať delegátov |
| **Správca pracoviska** | „admin skupiny“ – určí ho superadmin alebo globálny admin | iba ľudí svojho pracoviska a ich audit | povoliť / zakázať PIN, pozvať, reset PINu / 2FA (používateľ potvrdí vo svojej relácii), pozastaviť, pozvať delegátov pracoviska, určiť zastupovanie |
| **Zástupca správcu** | trvalý zástupca na pracovisku | ako správca | preberá práva, keď správca chýba (bez ďalšieho úkonu) |
| **Delegát pracoviska** | určený správcom alebo adminom | iba svoje pracovisko | spolu s iným delegátom / správcom potvrdzuje zmeny (štyri oči), rieši resety |
| **Člen** | bežný používateľ | iba seba | svoj PIN, 2FA, záložné kódy; ak má rolu – „Moja delegácia → Vzdať sa“ |

**Pracovisko** (skupina / oddelenie) je vlastný záznam v plugine, **nie** NetBox skupina – NetBox skupiny nesú
oprávnenia na celý NetBox a nechceme ich miešať. Neskôr ich môže použiť aj plugin Projekty
(„projekt patrí pracovisku IT“).

```
Superadmin
└── Admin skupina (globálni admini / delegáti)          – vidia všetko
    ├── Pracovisko „IT“
    │   ├── Správca pracoviska
    │   ├── Zástupca správcu (trvalý)
    │   ├── Delegáti pracoviska
    │   └── Členovia
    └── Pracovisko „Účtovníctvo“
        └── …
```

## 3. Pozvánka – spoločná pre každú rolu

Každé pridelenie role (globálny admin, správca, zástupca, delegát, dočasné zastupovanie, presun práv) je **pozvánka**.
Rola začne platiť až po prijatí.

1. Kto pozýva, vyberie **platnosť pozvánky: 12 / 24 / 36 / 48 hodín** (predvolené 24).
2. Pozvať sa dá iba používateľ s **e-mailom v overenej doméne** – inak sa pozvánka nedá doručiť.
3. Pozvanému príde **mail s odkazom a kódom** (obsah v kap. 9).
4. Po kliknutí na odkaz:
   - musí sa **prihlásiť** do NetBoxu,
   - ak nemá PIN → najprv si ho nastaví,
   - ak nemá 2FA → nastaví si ju (QR kód + záložné kódy),
   - zadá **kód z mailu**,
   - zaškrtne **„Rozumiem zodpovednosti“**,
   - potvrdí **PINom + 2FA**.
5. Až potom je rola aktívna. Pozývajúci dostane mail „prijaté“.
6. Po uplynutí platnosti pozvánka prepadne; dá sa poslať znova (nový kód).
7. Pozvaný môže pozvánku aj **odmietnuť** – pozývajúci dostane mail.

### Stavy role

| Stav | Význam |
|---|---|
| Čaká na prijatie | pozvánka odoslaná, beží platnosť |
| Prepadla | platnosť uplynula bez prijatia |
| Odmietnutá | pozvaný odmietol |
| Aktívna | prijatá, práva platia |
| Dočasná do … | zastupovanie s dátumom konca |
| Odstupuje | požiadal o vzdanie sa, čaká na odovzdanie (kap. 7) |
| Ukončená | rola skončila (odvolanie, vzdanie, vypnutie štyroch očí) |

V zoznamoch uvidíš pri každom aj to, čo mu chýba: *chýba PIN / chýba 2FA / nemá e-mail*.

## 4. Schvaľovanie štyrmi očami

- **Zapnutie:** superadmin sám – iba ak existujú aspoň **2 aktívni globálni delegáti**
  (spolu so superadminom min. 3 ľudia).
- **Vypnutie:** musia potvrdiť **ľubovoľní dvaja** z admin skupiny (superadmin + niekto, alebo dvaja delegáti).
- **Po vypnutí:**
  - delegovanie **končí** – delegáti strácajú delegačné práva (stav „Ukončená“),
  - všetkým delegátom príde mail: *„Schvaľovanie štyrmi očami bolo zrušené, delegovanie skončilo, ďalej spravujete
    iba svoj PIN.“*
- **Opätovné zapnutie:** treba znova pozvať delegátov (aspoň 2 musia prijať).
- Pri zapnutí aj vypnutí dostanú mail všetci dotknutí.

## 5. Presun práv a zastupovanie

### 5.1 Kto môže presunúť práva správcu pracoviska

- superadmin,
- globálny admin (delegovaný superadminom),
- **keď správca nie je dostupný:** **dvaja delegáti toho istého pracoviska** spolu (štyri oči) – môžu
  - presunúť práva správcu na **iného delegáta v rámci pracoviska**, alebo
  - **pozvať ďalšieho** delegáta / zástupcu.

Admin skupina dostane o každom presune mail a môže ho vrátiť.

### 5.2 Priebeh presunu

1. Iniciátor navrhne presun (komu, dočasne do dátumu alebo trvalo, dôvod) a zvolí platnosť kódu 12–48 h.
2. Ak ide o dvoch delegátov – obaja potvrdia PINom + 2FA (živá stránka ako pri štyroch očiach).
3. Nový držiteľ dostane **mail s kódom** a informáciou o pracovisku a o tom, čo preberá.
4. Prijme cez pozvánku (kap. 3). Kým neprijme, práva ostávajú pôvodnému.
5. Pôvodný držiteľ a admin skupina dostanú mail o dokončení.

### 5.3 Dočasné zastupovanie (choroba, dovolenka)

- Správca (alebo 5.1) určí zástupcu z pracoviska a **dátum „do“**.
- Deň pred koncom príde mail; po dátume sa práva **automaticky vrátia**.
- Dočasný zástupca **nemôže** ďalej odovzdávať práva ani meniť správcu.

### 5.4 Trvalý zástupca správcu

- Každé pracovisko môže mať stáleho zástupcu – pri chorobe netreba nič robiť, práva už má.

### 5.5 Správca odíde z firmy

- Odvolať ho môže superadmin / globálny admin **iba spolu s určením nového** správcu.
- Kým nový neprijme, pracovisko spravuje priamo admin skupina – nič neostane bez správcu.

## 6. Pridávanie a odoberanie delegátov

- Pridanie = pozvánka (kap. 3).
- **Odobratie delegáta** môže iba superadmin (alebo globálny admin), a iba ako **výmena**, ak by počet klesol pod
  minimum – starý ostáva aktívny, kým nový neprijme; potom sa vymenia automaticky.
- **Minimá:**
  - admin skupina: superadmin + **2** globálni delegáti (pri zapnutých štyroch očiach),
  - pracovisko: správca + **2** delegáti (aby mohli nastúpiť dvaja delegáti podľa 5.1) – *otvorená otázka č. 4*.

## 7. Vzdanie sa role

- Každý s rolou vidí menu **„Moja delegácia“**: čo je, na ktorom pracovisku, text zodpovednosti, tlačidlo
  **„Vzdať sa“** (dôvod + PIN + 2FA).
- Nadriadený (správca / admin skupina) dostane notifikáciu v zvončeku + mail.
- Ak by počet klesol pod minimum → stav **„Odstupuje“**: stále potvrdzuje, kým nový neprijme. Až potom rola končí.

## 8. Audit

Každý krok (pozvánka, prijatie, odmietnutie, prepadnutie, presun, zastupovanie, koniec zastupovania, vzdanie sa,
odvolanie, zapnutie / vypnutie štyroch očí) sa zapíše do auditu – kto, komu, pracovisko, kedy, odkiaľ (IP), dôvod.

## 9. Maily (EN / SK podľa nastavenia)

| Udalosť | Komu |
|---|---|
| Pozvánka do role (s kódom a platnosťou) | pozvaný |
| Pozvánka prijatá / odmietnutá / prepadla | pozývajúci |
| Presun práv – kód na prevzatie | nový držiteľ |
| Presun práv dokončený | pôvodný držiteľ, admin skupina |
| Zastupovanie končí zajtra / skončilo | zástupca, správca |
| Vzdanie sa role | nadriadený |
| Štyri oči zapnuté / vypnuté (delegovanie skončilo) | všetci delegáti |

### Vzor pozvánky

> **Predmet:** Delegovanie správy PIN – pracovisko IT
>
> Peter Knotek ťa určil za **delegáta pracoviska IT** pre správu PIN v NetBoxe.
>
> **Čo to znamená**
> - Spolu s ďalším delegátom alebo správcom schvaľuješ citlivé zmeny („štyri oči“) na pracovisku IT.
> - Riešiš resety PINu a 2FA ľudí na pracovisku IT (používateľ ich vždy potvrdí sám).
> - PIN chráni citlivé časti NetBoxu aj ďalších pluginov, ktoré ho vyžadujú (napr. projekty a dokumentácia) –
>   za túto ochranu si spoluzodpovedný.
>
> **Tvoja zodpovednosť**
> - PIN, 2FA ani záložné kódy nikomu nedávaj; telefón s 2FA maj pri sebe.
> - Na žiadosti o schválenie reaguj včas; schváľ iba to, čomu rozumieš a čo je oprávnené.
> - Každá tvoja akcia sa zapisuje do auditu.
> - Funkcie sa môžeš vzdať v menu „Moja delegácia“ (platí po odovzdaní).
>
> **Prijať:** https://netbox.firma.sk/plugins/user-pin/invitation/…
> **Kód:** 482 913 – platí do 29. 09. 2026 14:00 (24 h)
>
> Ak o tom nič nevieš, neprijímaj a kontaktuj administrátora.

## 10. Existujúce dáta

- Terajší delegáti, ktorí majú PIN aj 2FA → ostanú **aktívni** ako globálni delegáti.
- Delegáti bez PINu alebo 2FA → stav **„Čaká na prijatie“** a pošle sa im pozvánka (24 h).
- Delegovanie na NetBox skupinu → prevedie sa na jednotlivých členov (pozvánky), prípadne na pracovisko.

## 11. Postup (fázy)

1. **Fáza 1:** pozvánky s platnosťou 12–48 h, prijatie (kód + PIN + 2FA), stavy, „Moja delegácia → Vzdať sa“,
   vypnutie štyroch očí dvomi ľuďmi (s koncom delegovania), výmena delegáta, maily.
2. **Fáza 2:** pracoviská, správca, zástupca, delegáti pracoviska, dočasné zastupovanie, presun práv dvomi delegátmi,
   viditeľnosť iba vlastného pracoviska.

## 12. Otvorené otázky

| # | Otázka | Môj návrh |
|---|---|---|
| 1 | Môže byť používateľ vo **viacerých pracoviskách**? | nie, iba v jednom |
| 2 | Trvalý **zástupca správcu** áno / nie? | áno, voliteľný |
| 3 | Zmeny správcu pracoviska (povoliť PIN, reset) – cez štyri oči, alebo stačí správca sám? | správca sám; štyri oči iba pre zmeny rolí (delegáti, presun práv) |
| 4 | Minimum delegátov na pracovisku | 2 (inak nefunguje 5.1) |
| 5 | Vypnutie štyroch očí – ruší aj role na pracoviskách, alebo iba globálnych delegátov? | iba globálnych; pracoviská fungujú ďalej, ale presun práv dvomi delegátmi (5.1) nebude dostupný |
| 6 | Trvalý presun správcu dvomi delegátmi bez admina – povoliť? | iba dočasne (max. 30 dní); trvalý presun potvrdí admin skupina |

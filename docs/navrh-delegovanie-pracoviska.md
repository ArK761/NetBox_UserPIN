# Návrh: delegovanie, oddelenia a schvaľovanie štyrmi očami

Stav: **IMPLEMENTOVANÉ vo verzii 0.10.0** (fáza 1 aj 2). Otvorené otázky sú rozhodnuté podľa môjho návrhu –
pozri kap. 13; ak chceš niečo inak, napíš a upravím.

Zmeny vo verzii 2: hierarchia CORE → oddelenie, štyri oči sa nevypínajú, kým existuje oddelenie alebo delegát,
dočasné delegovanie s mailom celému oddeleniu, presun ľudí medzi oddeleniami, prezeranie po PIN + 2FA.

---

## 1. Prečo

- Delegát bez PINu a 2FA nemá zmysel – nemôže nič potvrdiť.
- Firma má oddelenia. Správu PINov ľudí v oddelení robí ich správca, nie iba hlavný admin.
- Keď niekto chýba (choroba, dovolenka, odchod z firmy), práva sa musia dať bezpečne odovzdať – vždy s pozvánkou,
  kódom v maili, informovaním oddelenia a záznamom v audite.

## 2. Hierarchia

```
CORE
├── Admin (superuser)                 – vidí všetko, bez overenia
└── Zástupcovia CORE                  – vidia všetko po overení PIN + 2FA
        │
        │  (CORE zakladá oddelenia a menuje ich správcov)
        ▼
Oddelenie „IT“
├── Správca oddelenia                 – „superadmin skupiny“, core zástupca pre toto oddelenie
├── Zástupcovia správcu               – delegáti oddelenia
└── Používatelia                      – môžu, ale nemusia byť delegáti

Oddelenie „Účtovníctvo“
└── …
```

| Rola | Vidí | Môže |
|---|---|---|
| **Admin (CORE)** | všetko **bez** overenia | všetko; menuje zástupcov CORE |
| **Zástupca CORE** | všetko po **PIN + 2FA** | zakladať / rušiť oddelenia, menovať a odvolávať správcov oddelení, presúvať ľudí medzi oddeleniami |
| **Správca oddelenia** (superadmin skupiny) | svoje oddelenie a jeho ľudí po **PIN + 2FA** | povoliť / zakázať PIN, pozvať, reset PINu / 2FA (používateľ potvrdí sám), pozastaviť, pozvať delegátov oddelenia, dočasne delegovať svoje práva, žiadať o presun človeka do / z iného oddelenia |
| **Delegát oddelenia** | svoje oddelenie po **PIN + 2FA** | spolu s iným delegátom / správcom potvrdzuje zmeny (štyri oči), rieši resety; pri nedostupnom správcovi dvaja delegáti môžu presunúť práva (kap. 5) |
| **Používateľ** | iba seba | svoj PIN, 2FA, záložné kódy; ak má rolu – „Moja delegácia → Vzdať sa“ |

**Oddelenie** je vlastný záznam v plugine, **nie** NetBox skupina – NetBox skupiny nesú oprávnenia na celý NetBox
a nechceme ich miešať. Neskôr ho môže použiť aj plugin Projekty („projekt patrí oddeleniu IT“).

**Prezeranie:** správcovia a delegáti vidia oddelenia a používateľov až po potvrdení **PIN + 2FA**
(platí okno ako pri ostatných správcovských akciách). Admin CORE (superuser) si ich pozerá bez overenia;
na zmeny potrebuje overenie ako doteraz.

## 3. Pozvánka – spoločná pre každú rolu

Každé pridelenie role (zástupca CORE, správca, delegát, dočasné delegovanie, presun práv) je **pozvánka**.
Rola začne platiť až po prijatí.

1. Kto pozýva, vyberie **platnosť: 12 / 24 / 36 / 48 hodín** (predvolené 24).
2. Pozvať sa dá iba používateľ s **e-mailom v overenej doméne**.
3. Pozvanému príde **mail s odkazom, kódom, názvom oddelenia a platnosťou** (vzor v kap. 10).
4. Po kliknutí na odkaz:
   - **prihlási sa** do NetBoxu,
   - ak nemá PIN → najprv si ho nastaví,
   - ak nemá 2FA → nastaví si ju (QR kód + záložné kódy),
   - zadá **kód z mailu**,
   - zaškrtne **„Rozumiem zodpovednosti“**,
   - potvrdí **PINom + 2FA**.
5. Až potom je rola aktívna. Pozývajúci dostane mail „prijaté“.
6. Po uplynutí platnosti pozvánka prepadne; dá sa poslať znova (nový kód).
7. Pozvaný môže pozvánku **odmietnuť** – pozývajúci dostane mail.

### Stavy role

| Stav | Význam |
|---|---|
| Čaká na prijatie | pozvánka odoslaná, beží platnosť |
| Prepadla | platnosť uplynula bez prijatia |
| Odmietnutá | pozvaný odmietol |
| Aktívna | prijatá, práva platia |
| Dočasná do … | dočasné delegovanie s dátumom konca |
| Odstupuje | požiadal o vzdanie sa, čaká na odovzdanie (kap. 8) |
| Ukončená | rola skončila (odvolanie, vzdanie, zrušenie) |

V zoznamoch je pri každom aj to, čo mu chýba: *chýba PIN / chýba 2FA / nemá e-mail*.

## 4. Schvaľovanie štyrmi očami

- **Zapnutie:** admin CORE – iba ak existujú aspoň **2 aktívni zástupcovia CORE**.
- **Kým existuje aspoň jedno oddelenie alebo jeden delegát, štyri oči sa vypnúť nedajú.**
- Vypnúť sa dajú až vtedy, keď **neexistuje žiadne oddelenie** (oddelenia musia byť zrušené – tým končia aj
  ich delegáti); vypnutie potvrdia dvaja (ak je druhý), inak admin sám. Po vypnutí končí delegovanie CORE a
  zástupcovia CORE dostanú mail.
- **Ak skončí delegovanie v CORE** (napr. zástupca CORE odíde), oddelenia fungujú ďalej normálne a štyri oči
  ostávajú zapnuté.
- Pri zapnutí / vypnutí dostanú mail všetci dotknutí.

## 5. Dočasné delegovanie a presun práv

### 5.1 Kto môže delegovať / presunúť práva správcu oddelenia

- admin CORE a zástupcovia CORE,
- správca sám (napr. pred dovolenkou),
- **keď správca nie je dostupný:** **dvaja delegáti toho istého oddelenia** spolu (štyri oči) – môžu
  - presunúť práva správcu na **iného delegáta v rámci oddelenia**, alebo
  - **pozvať ďalšieho** delegáta.

### 5.2 Dočasné delegovanie (s dátumom „do“)

1. Iniciátor vyberie delegáta, **dátum „do“**, dôvod a platnosť kódu (12–48 h).
2. Delegát dostane **mail s kódom** a prijme (kap. 3).
3. Po prijatí príde **mail každému v oddelení**:
   *„Delegát XYZ je teraz správcom (superadminom) oddelenia IT. Jeho práva končia 15. 10. 2026 o 23:59.“*
4. Deň pred koncom príde pripomienka delegátovi aj pôvodnému správcovi.
5. **Po dátume sa práva automaticky vrátia pôvodnému správcovi** – mail celému oddeleniu
   *„Správcom oddelenia IT je opäť Peter Knotek.“*
6. Dočasný správca **nemôže** ďalej odovzdávať práva ani meniť trvalého správcu.

### 5.3 Trvalý presun (pôvodný správca je zrušený / odišiel)

1. CORE (alebo pri nedostupnosti CORE dvaja delegáti oddelenia – *otvorená otázka č. 3*) zruší pôvodného
   správcu **spolu s určením nového**.
2. Nový dostane mail s kódom a prijme.
3. **Mail každému v oddelení:**
   *„Správca Peter Knotek bol zrušený. Práva boli presunuté na XYZ, ktorý je teraz správcom (superadminom)
   oddelenia IT.“*
4. Kým nový neprijme, oddelenie spravuje priamo CORE – nič neostane bez správcu.

## 6. Presun človeka medzi oddeleniami

- Správca oddelenia X **požiada** o presun človeka do oddelenia Y (alebo požiada Y o človeka z Y do X).
- **Správca druhého oddelenia žiadosť potvrdí** (PIN + 2FA). Správcovia si tak ľudí vedia vymeniť medzi sebou.
- CORE môže presúvať priamo.
- Ak je presúvaný človek delegát:
  - v pôvodnom oddelení mu rola **končí** (ak by klesol počet pod minimum → najprv výmena, kap. 7),
  - v novom oddelení je delegátom až po **prijatí pozvánky** (kód v maili).
- Mail: presúvanému, obom správcom a obom oddeleniam (kto prišiel / odišiel).

## 7. Pridávanie a odoberanie delegátov

- Pridanie = pozvánka (kap. 3).
- Odobratie delegáta môže správca oddelenia alebo CORE; ak by počet klesol pod minimum, iba ako **výmena** –
  starý ostáva aktívny, kým nový neprijme; potom sa vymenia automaticky.
- **Minimá:**
  - CORE: admin + **2** zástupcovia CORE (pre zapnutie štyroch očí),
  - oddelenie: správca + **2** delegáti (aby mohli nastúpiť dvaja delegáti podľa 5.1).

## 8. Vzdanie sa role

- Každý s rolou vidí menu **„Moja delegácia“**: čo je, v ktorom oddelení, text zodpovednosti, tlačidlo
  **„Vzdať sa“** (dôvod + PIN + 2FA).
- Nadriadený (správca / CORE) dostane notifikáciu v zvončeku + mail.
- Ak by počet klesol pod minimum → stav **„Odstupuje“**: stále potvrdzuje, kým nový neprijme. Až potom rola končí.

## 9. Audit

Každý krok (pozvánka, prijatie, odmietnutie, prepadnutie, dočasné delegovanie, návrat práv, trvalý presun,
presun medzi oddeleniami, vzdanie sa, odvolanie, zapnutie / vypnutie štyroch očí, prezeranie oddelenia
správcom) sa zapíše do auditu – kto, komu, oddelenie, kedy, odkiaľ (IP), dôvod.

## 10. Maily (EN / SK podľa nastavenia)

| Udalosť | Komu |
|---|---|
| Pozvánka do role (kód, oddelenie, platnosť) | pozvaný |
| Pozvánka prijatá / odmietnutá / prepadla | pozývajúci |
| Dočasné delegovanie – „XYZ je správcom do …“ | **každý v oddelení** |
| Delegovanie končí zajtra | dočasný a pôvodný správca |
| Práva vrátené pôvodnému správcovi | **každý v oddelení** |
| Správca zrušený, práva presunuté na XYZ | **každý v oddelení** |
| Žiadosť o presun človeka medzi oddeleniami | správca druhého oddelenia |
| Presun človeka dokončený | presúvaný, obaja správcovia, obe oddelenia |
| Vzdanie sa role | nadriadený |
| Štyri oči zapnuté / vypnuté | všetci dotknutí |

### Vzor pozvánky

> **Predmet:** Delegovanie správy PIN – oddelenie IT
>
> Peter Knotek ťa určil za **delegáta oddelenia IT** pre správu PIN v NetBoxe.
>
> **Čo to znamená**
> - Spolu s ďalším delegátom alebo správcom schvaľuješ citlivé zmeny („štyri oči“) v oddelení IT.
> - Riešiš resety PINu a 2FA ľudí v oddelení IT (používateľ ich vždy potvrdí sám).
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
> **Kód:** 48291305 – platí do 29. 09. 2026 14:00 (24 h)
>
> Ak o tom nič nevieš, neprijímaj a kontaktuj administrátora.

## 11. Existujúce dáta

- Terajší delegáti s PINom aj 2FA → ostanú **aktívni** ako zástupcovia CORE.
- Delegáti bez PINu alebo 2FA → stav **„Čaká na prijatie“** a pošle sa im pozvánka (24 h).
- Delegovanie na NetBox skupinu → prevedie sa na jednotlivých členov (pozvánky), prípadne na oddelenie.

## 12. Postup (fázy)

1. **Fáza 1:** pozvánky s platnosťou 12–48 h, prijatie (kód + PIN + 2FA), stavy, „Moja delegácia → Vzdať sa“,
   zástupcovia CORE, pravidlo pre štyri oči (kap. 4), výmena delegáta, maily.
2. **Fáza 2:** oddelenia, správca, delegáti oddelenia, dočasné delegovanie s návratom práv, trvalý presun,
   presun ľudí medzi oddeleniami, prezeranie po PIN + 2FA, maily celému oddeleniu.

## 13. Rozhodnutia (pôvodne otvorené otázky)

| # | Otázka | Rozhodnutie (implementované) |
|---|---|---|
| 1 | „Core zástupca pre ODD“ – je **správca oddelenia** zároveň členom CORE (vidí aj ostatné oddelenia), alebo je to človek z CORE, ktorý oddelenie iba **dozoruje** a oddelenie má ešte vlastného správcu? | správca oddelenia **nie je** členom CORE, vidí iba svoje oddelenie; CORE vidí všetko |
| 2 | Môže byť používateľ vo **viacerých oddeleniach**? | nie, iba v jednom |
| 3 | Trvalý presun správcu dvomi delegátmi bez CORE – povoliť? | nie; dvaja delegáti môžu iba **dočasne** (max. 30 dní), trvalý presun potvrdí CORE |
| 4 | Zmeny správcu oddelenia (povoliť PIN, reset) – cez štyri oči, alebo stačí správca sám? | správca sám; štyri oči iba pre zmeny rolí (delegáti, presun práv, presun ľudí) |
| 5 | Dostane mail o dočasnom delegovaní naozaj **každý** v oddelení, alebo iba tí, čo majú PIN? | každý s e-mailom v overenej doméne |


## 14. Doplnenie (rozhodnuté, zatiaľ neimplementované)

- **Master v PINe ≠ superuser NetBoxu** – v `configuration.py`:
  ```python
  PLUGINS_CONFIG = {
      'netbox_user_pin': {
          'masters': ['admin'],              # vždy master v PINe (nedá sa odobrať cez web)
          'superusers_are_masters': False,   # True = každý superuser NetBoxu je automaticky master
      },
  }
  ```
  Iný superuser má v PINe iba svoj PIN, kým ho master nedeleguje.
- **Zaradenie do oddelenia** – ľudí bez oddelenia zaraďuje CORE (master, zástupcovia CORE), bez ohľadu na to,
  či majú PIN, aj priamo zo stránky Používatelia (Akcie → Presunúť do oddelenia, potvrdenie PINom). Potom ho
  vidí správca oddelenia a povolí mu PIN / práva.
- **Núdzový príkaz (bash)** vidia iba ľudia s oprávnením „Prístup na server (SSH)“; na stránke Môj PIN nebude.
- **Štruktúra oddelení** – plná šírka, e-mail, oddelenia zbalené do jedného riadku s rozbalením, vyhľadávanie,
  problémové (červené, žlté) navrchu, veľké oddelenia po častiach.
- **Karta prehliadača** – čistý názov bez HTML („NetBox PIN – …“).

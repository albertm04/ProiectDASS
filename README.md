# Break the Login 

Aplicație de autentificare realizată pentru cursul **Dezvoltarea Aplicațiilor Software Securizate (DASS)**.

Proiectul compară două versiuni ale aceleiași aplicații:

- **v1** – variantă vulnerabilă, creată intenționat pentru demonstrație
- **v2** – variantă securizată, în care vulnerabilitățile au fost remediate

Tehnologii folosite:

- **Python**
- **Flask**
- **SQLite**

---

## Scopul proiectului

Scopul acestui proiect este să evidențieze, într-un mod practic, diferența dintre o implementare nesigură și una securizată a unui sistem de autentificare.

Aplicația include funcționalități de bază precum:

- register
- login
- logout
- reset password

Varianta **v1** conține vulnerabilități intenționate pentru demonstrarea riscurilor, iar varianta **v2** arată cum pot fi aplicate măsuri corecte de securitate.

---

## Structura proiectului

- **v1_vulnerable/** – versiunea vulnerabilă
- **v2_secure/** – versiunea securizată

---

## Diferențe între v1 și v2

### v1 – varianta vulnerabilă

Versiunea v1 a fost construită pentru a demonstra probleme de securitate frecvente într-o aplicație de autentificare:

- acceptă parole foarte slabe
- parolele sunt stocate nesigur
- nu există protecție împotriva atacurilor brute force
- permite **user enumeration**
- gestionează nesigur sesiunile
- folosește token predictibil și reutilizabil pentru resetarea parolei

### v2 – varianta securizată

Versiunea v2 păstrează aceleași funcționalități, dar introduce măsuri de protecție:

- hashing modern cu **bcrypt**
- politică minimă pentru parole
- mesaj generic la autentificare
- blocare temporară după 5 încercări eșuate
- resetare parolă cu token aleatoriu, cu expirare și unică folosință
- gestionare mai sigură a sesiunii

---

## Conturi de test

După rularea scripturilor de seed, pot fi folosite următoarele conturi:

### v1 – http://127.0.0.1:5000

| Email           | Parolă |
|----------------|--------|
| victim@test.com | 123 |
| admin@test.com  | parola |
| user@test.com   | 1 |

Această versiune acceptă parole foarte slabe și este folosită pentru demonstrarea vulnerabilităților.

### v2 – http://127.0.0.1:5001

| Email           | Parolă |
|----------------|--------|
| victim@test.com | Parola123 |
| admin@test.com  | Admin123! |
| user@test.com   | User2024 |

Această versiune aplică reguli mai stricte de securitate și este folosită pentru demonstrarea remedierii vulnerabilităților.

---

## Exemple de comportament

### În v1

- poți face login cu parole foarte slabe
- la autentificare, aplicația afișează mesaje diferite pentru:
  - utilizator inexistent
  - parolă greșită
- linkul de resetare a parolei este predictibil și reutilizabil

### În v2

- parolele slabe nu mai sunt acceptate
- aplicația afișează același mesaj pentru credențiale invalide
- după 5 încercări greșite, contul este blocat temporar
- linkul de resetare este aleatoriu, expiră și poate fi folosit o singură dată

---

## Exemplu rapid de testare

### v1
- Login: `victim@test.com` / `123`
- User enumeration:
  - `inexistent@test.com` / orice
  - `victim@test.com` / parolagresita
- Reset password: link reutilizabil

### v2
- Login: `victim@test.com` / `Parola123`
- Mesaj generic pentru orice autentificare invalidă
- Blocare după 5 parole greșite
- Reset password cu link one-time

---

## Concluzie

Proiectul evidențiază clar diferența dintre o aplicație de autentificare vulnerabilă și una securizată.

- **v1** arată cum pot fi exploatate greșeli comune de implementare
- **v2** arată cum pot fi prevenite aceste probleme prin măsuri standard de securitate

AuthX este un exemplu practic util pentru înțelegerea principiilor de bază din dezvoltarea aplicațiilor software securizate.

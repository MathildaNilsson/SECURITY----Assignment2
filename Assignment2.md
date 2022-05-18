Assignment 2 <br>
Mathilda Nilsson


## 1. Säkerhetshål

XSS - create quiz

## Exploit
1. Logga in som användare på hemsidan ``http://localhost:8080/`` och välj ``create quiz``.
2. När du ska ge en titel till ditt quiz anger du:  `<script>alert("")</script>`
3. Detta kommer göra att varje gång man går in på ``play`` -fliken och programet laddar in titlarna får användaren en `alert` - ruta.

## Vulnerability

Sårbarheten finns i methoden ``createQuiz``:

     try (Connection c = db.getConnection()) {
            // Save the quiz itself.
            String title = context.formParam("quiz-title");
            boolean isPublic = context.formParam("quiz-public") != null;
            PreparedStatement s1 = c.prepareStatement(
                "INSERT INTO quiz (user_id, title, datetime, public) VALUES (?, ?, ?, ?)",
                Statement.RETURN_GENERATED_KEYS
            );
            s1.setInt(1, context.sessionAttribute("userId"));
            s1.setString(2, title);

Genom att användarens inmatning av titeln bara tas in som en sträng och inte kontrolleras har användaren
fritt fram till att skriva in vilken sträng den än vill. 

## Fix

Vi löser detta genom att lägga in en `Encode`:

        try (Connection c = db.getConnection()) {
            // Save the quiz itself.
            String title = context.formParam("quiz-title");
            String testTitle = Encode.forHtml(title);
            boolean isPublic = context.formParam("quiz-public") != null;
            PreparedStatement s1 = c.prepareStatement(
                "INSERT INTO quiz (user_id, title, datetime, public) VALUES (?, ?, ?, ?)",
                Statement.RETURN_GENERATED_KEYS
            );
            s1.setInt(1, context.sessionAttribute("userId"));
            s1.setString(2, testTitle);

Sätt in en Encode.forHtml som testar strängen på tecken?
Resultatet av Encode läggs sedan in som den som sätts in i prepared statement. 

---

XSS - Search

## Exploit

1. Skicka url ``http://localhost:8080/search?search=%3Cscript%3Ealert%28%29%3C%2Fscript%3E`` till någon som har ett konto på hemsidan.
2. Användaren loggar in och får en `alert` - ruta.


## Vulnerability

## Fix

---

Path traversal - pom.xml

## Exploit

1. I flags column, gå in ``http://localhost:8080/flag?name=../pom.xml``
2. Hämta POM filen.
3. mm

## Vulnerability

## Fix

---

## 2. Access control

| 	         | 1 	   | 2     | 3	    | 4  	  | 5	   |
|-----------|-------|-------|-------|-------|------|
| Brad   	  | W, R	 | W, R	 | 	R    | 	R    | 	    |
| Angelina	 | 	  R  | 	 R   | W, R	 | 	R    | 	    |
| Will	     | 	 R   | 	 R   | 	 R   | 	W, R | W, R |

---
## 3. Lösenord

1.<b>Vilka lösenord har användarna Angelina och Will?</b>
<br>
Will - `triforce`
<br>
Angelina -

2.<b>Hur tog du reda på detta? Förklara på teknisk nivå, inklusive varför det inte räcker att titta i filen create.sql.</b>

       for(String pass : assignment()){
            String hash = createHashWithoutSalt(pass);
            if(hash.equals("7d533f81b0943bec5c4feb7b2e25d341986e0e84465c2b64107d597f1b71133f1b605d30eb28aada2c4d5801290ae3a28735a5eb4aea5c2fbfcb63c03ad511cc")){
                System.out.println("Wills password är: " +pass);
                System.out.println(hash);
                break;
            }
            i++;
            System.out.println(i);
        }


3.Hur skulle applikationen behöva ändras för att förhindra denna attack? Förklara på teknisk nivå, inklusive referenser till relevanta metoder och/eller kodrader.

---
## 4. Rate limiting

---
## 5. Säkerhetsprinciper
Assignment 2 <br>
Mathilda Nilsson


## 1. Säkerhetshål

XSS - create quiz

## Exploit
1. Logga in som användare på hemsidan ``http://localhost:8080/`` och välj ``create quiz``.
2. När du ska ge en titel till ditt quiz anger du:  `<script>alert("")</script>` och sedan sparar du quizen. 
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

De som ser quizen kommer få koden körd i sin webbläsare.  

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
Blir ofarlig och skrivs ut som en vanlig String.
Encoda innan databas!!!
Innan encode Html
Efter något annat

---

XSS - Search

## Exploit

1. Gå till hemsidan `(http://localhost:8080/)`
2. Logga in som en användare och välj `Search` fliken.
3. Klistra in `<script>alert("")</script>"` i sökrutan.
4. Detta skapar URL: ``http://localhost:8080/search?search=%3Cscript%3Ealert%28%29%3C%2Fscript%3E`` 
 som man kan skicka till någon som har ett konto på hemsidan.
5. Användaren som fått länken loggar in och får en `alert` - ruta.

## Vulnerability

Sårbarheten finns i metoden `searchPage`:

        if (context.queryParam("search") != null) {
            // Show what term the user searched for.
            content +=
                "<p>Search results for: " + context.queryParam("search") + "</p>" +
                "<ul>";
            try (Connection c = db.getConnection()) {
                // Make sure to only get the quizzes that are public or belong to the current user.
                PreparedStatement s = c.prepareStatement(
                    "SELECT quiz.id AS quiz_id, title, username, public " +
                    "FROM quiz " +
                    "JOIN user ON quiz.user_id = user.id " +
                    "WHERE instr(title, ?) " +
                    "AND (public = TRUE OR user.id = ?)"
                );
                s.setString(1, (context.queryParam("search")));
                s.setInt(2, context.sessionAttribute("userId"));

I denna metoden finns det ingenting som testar användarens `input` i sökfältet, man tar bara rakt av det som skrivits in en ``queryParam``
och kör det mot databasen. Problemet som uppstår här ligger just i `queryParam`, då inputen som användaren skriver in där kommer att visas 
som ``http://localhost:8080/search?search=%3Cscript%3Ealert%28%29%3C%2Fscript%3E`` i URL:en.

Det som blir möjligt med denna sårbarheten är att en potentiell hacker kan skriva egen källkod som om den var en utvecklare på hemsidan.
Man kan då skriva in kod som ger ny karaktär, utseende och manipulera hemsidan till att visa nya sökfält/användatfält för andra användare
som loggar in men den nya URL:en. Man kan manipulera hemsidan så att en användare inte ser skillnad på URL/layout som gör att utomstående tror på hemsidan och
skriver in personliga uppgifter som skickas tilll den hacker som skapat attacken. 

Url innehåller det skadade på en legitim hemsida.

## Fix

Vi lägger till följande kod i metoden ``searchPage``:

        if (context.queryParam("search") != null) {
            // Show what term the user searched for.
            String search = context.queryParam("Search");
            content +=
                "<p>Search results for: " + Encode.forHtml(search) + "</p>" +
                "<ul>";

Vi skapar en String för  att returnera värdet av `context.queryParam("Search")` så vi kan testa användarens input.
Vi tar värdet av `String search` och testar det för HTML genom att sätta en `Encode` och skriver ut resultatet till användaren. 
Har användaren försökt lägga in `script/html` värden kommer applikationen returnera `NULL`.


---


<b>Path traversal - pom.xml</b>

## Exploit

1. Gå till hemsidan `(http://localhost:8080/)`
2. Logga in en användare och välj `FLAG` fliken.
3. Lägg till `flag?name=../pom.xml` efter `(http://localhost:8080/)` i URL.
4. Då har man lyckats att få åtkomst till en annan mapp och skriva ut den aktuella filen. I detta 
fall skrivs pom filen ut i webbläsaren. 


## Vulnerability

Sårbarheten finns i metoden `singleFlagPage`:

    private static void singleFlagPage(Context context) throws IOException {
        String flagName = context.queryParam("name");
        Path path = Path.of("flags/" + flagName);
        String svg = Files.readString(path);
        context.contentType("image/svg+xml; charset=UTF-8");
        context.result(svg);
    }

Detta går att göra för att `String flagName` sätts in av användaren genom en `context.queryParam`.
När man sedan sätter Path så adderas bara användarens input med `"flags/"` där utvecklaren tänkt att alla bilder på
flaggorna skulle hämtas från. På detta sätt ger man en poteniell hacker full makt till att skriva
in precis vad den vill i fältet som en sträng och där av kunna hämta ut vilken fil som helst.

Genom att hackern använder sig av `../` innan den anger filnamnet kan den manipulera filename och ändra riktningen 
på Path till en helt annan mapp. Vilket resulterar i att man kan hämta andra filer inne i andra mappar än den tänkta 
`(flags/)` mappen.



## Fix

Vi lägger till följande kod i metoden `singleFlagPage`:

    private static void singleFlagPage(Context context) throws IOException {
        String flagName = context.queryParam("name");
        Path path = Path.of("flags/" + flagName).toAbsolutePath().normalize();
        Path folder = Path.of("flags").toRealPath();
        if(!path.startsWith((folder))){
            context.result("Not allowed entry");
            return;
        }


Vi vill begränsa vad användaren kan skriva in i `queryParam("name")` dvs URL fältet
och gör detta genom att skapa ett Path objekt som vi kan referera till. <br>
Vi skapar en Path av den input vi fått av användaren i `queryParam`, där vi sätter `"flags/"` + `flagName` och
använder oss av ``toAbsolutPath`` vilket kommer returnera en Path som representerar den absoluta pathen som
ännu inte finns. Sedan använder vi oss av ``normalize`` för att returnera ett resultat av en Path som tar bort alla oväntade värden så som: `../`, `./` etc. <br>
<br>
Sedan skapar vi en ny Path av den folder (``"flags/"``) vi kommer vilja referera till så vi gör detta genom att skapa en motsvarighet till ursprungs mappen. Därför använder
vi oss av ``toRealPath`` .
<br><br>
Genom att kontrollera att URL:en `path` som användaren namngett och som vi normaliserat motsvarar den Path vi skapat av referensen av vår `folder` kan vi säkerställa att
användaren inte kommer runt säkerheten i applikationen och får istället ett felmeddelande som säger
att det inte är tillåtet att komma åt andra mappar än den utvecklaren satt upp som default.


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
Angelina - `jumpstart`

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


3. <b>Hur skulle applikationen behöva ändras för att förhindra denna attack? Förklara på teknisk nivå, inklusive referenser till relevanta metoder och/eller kodrader. </b>

---
## 4. Rate limiting

1. <b>Hur lång tid skulle det ta för någon med tillgång till filen 100k.txt att hitta användarnas lösenord med en online brute-force-attack? Skriv ett svar för varje användare (Brad, Angelina, Will)
och beskriv tydligt hur du kom fram till svaret (exempelvis med en formel). Förutsätt att lösenorden testas i ordning, 
uppifrån och ner, samt att anfallaren kan testa 10.000 lösenord per minut.</b>

- Brad: `apples` : `595 försök / 10,000 försök per minut = 0,0595 minuter x 60 sekunder per minut = 3,57 sek.` 
- Angelina: `jumpstart` : `77169 försök / 10,000 per minut = 7,7169 minuter = ca 7 minuter 43 sek.`
- Will: `triforce` : `21067 försök / 10,000 försök per minut = 2,1067 minuter = ca 2 minuter 6 sek.`

2. <b>Hur lång tid skulle samma attack ta om applikationen begränsade varje användare till 5 inloggningsförsök per minut?
Skriv ett svar för varje användare (Brad, Angelina, Will) och beskriv tydligt hur du kom fram till svaret (exempelvis med en formel). 
Ge ett exakt svar, inte en approximation. Förutsätt att lösenorden testas i ordning, uppifrån och ner. </b>

- Brad: `595 försök / 5 försök per minut = 119 minuter = 1 tim 59 min` 
- Angelina: `77169 försök / 5 försök per minut = 15433,8 minuter / 1440 minuter per dag = 10,7179167 dagar`
- Will: `21067 försök / 5 försök per minut = 4213,4 minuter / 1440 minutwe per dagr = 2,92597222 dagar `


3. <b>Hur skulle applikationen behöva ändras för att begränsa antalet inloggningsförsök på detta sätt? 
Förklara på teknisk nivå, inklusive referenser till relevanta metoder och/eller kodrader.</b>

Försök förklara hur sådan kod/lösning skulle se ut. 

---
## 5. Säkerhetsprinciper

<b>Vilka är de viktigaste lärdomarna och principerna om säkerhet som du kommer att ta med dig från denna kurs?</b>

- Vad användare kan använda för input .. Som kan skada säkerhet/program.. Enkelt att attackera pga input
- Blockera input från användare .. Lärt att/hur begränsningarna funkar
- Varje gång vi får input? Vad kan användaren skicka in? 
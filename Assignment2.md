Assignment 2 <br>
Mathilda Nilsson


## 1. Säkerhetshål

**XSS - create quiz**

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

Genom att användarens inmatning av titeln tas in som en sträng genom `context.formParam` och inte kontrolleras har användaren
fritt fram till att skriva in vilken sträng den vill. Eftersom vi inte har en metod som kollar eller begränsar vad det är för tecken 
som kommer in av användaren kan den skriva in tecken som `<`, `>` och på så sätt för det möjligt att utsätta hemsidan för en 
cross site script attack. 

`String title` blir resultatet av inputen i `context.formParam` och sätts direkt in i databasen. Detta gör att varje gång någon öppnar 
`Play` fliken i spelet kommer titlarna laddas in och har man tillgång till denna quiz där attacken är skapad i titeln kommer man bli utsatt 
för attacken. 

Detta är en `Stored XSS Attacks` eftersom att attacken är permanent lagrad via titel i quizzens databas. Den som blir utsatt för attacken blir utsatt när
applikationen hämtar information från databasen där scriptet är lagrat. 


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

Vi sätter in en `Encode.forHtml` som encodar strängen på HTML kod och returnerar resultatet av encoden som en sträng. 
`Encode.forHtml` kommer att ta `<` och `>` som bildar javascript kod och encoda dem till specialtecken vilket gör att det lagras som
en ren sträng i databasen och blir ofarlig för applikationen och användare. 
Exempel:
<br>
`<` till `&lt;`
<br>
`>`till `&gt;`
<br>
Resultatet av Encode är det som vi lägger in i vårt prepared statement för att undvika att få in osäker input in i vår databas. <br>


---

**XSS - Search**

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

I denna metoden finns det ingenting som kontrollerar användarens `input` i sökfältet, man tar bara rakt av det som skrivits in en ``queryParam``
och kör det mot databasen. Problemet som uppstår här ligger just i `queryParam`, då inputen som användaren skriver in där kommer att visas 
som ``http://localhost:8080/search?search=%3Cscript%3Ealert%28%29%3C%2Fscript%3E`` i URL:en.

Det som blir möjligt med denna sårbarheten är att en potentiell hacker kan skriva egen källkod som om den var en utvecklare på hemsidan.
Man kan då skriva in kod som ger ny karaktär, utseende och manipulera hemsidan till att visa nya sökfält/användatfält för andra användare
som loggar in men den nya URL:en. Man kan manipulera hemsidan så att en användare inte ser skillnad på URL/layout som gör att utomstående tror på hemsidan och
skriver in personliga uppgifter som skickas tilll den hacker som skapat attacken. 

Denna typ av XSS attack kallas `Reflected XSS Attack` eftersom att den utförs via en Webb genom tex:
ett sökresultat. `Reflected attacks` skickas till den utsatta via andra vägar än på själva hemsidan. Det kan tex vara via mejl eller andra hemsidor. 


## Fix

Vi lägger till följande kod i metoden ``searchPage``:

        if (context.queryParam("search") != null) {
            // Show what term the user searched for.
            String search = context.queryParam("Search");
            content +=
                "<p>Search results for: " + Encode.forHtml(search) + "</p>" +
                "<ul>";

Vi skapar en String för  att returnera värdet av `context.queryParam("Search")` så vi kan encoda användarens input.
Vi tar värdet av `String search` och encodar det för HTML genom att sätta en `Encode` och skriver ut resultatet till användaren.
`Encode.forHtml` kommer att ta `<` och `>` som bildar javascript kod och encoda dem till specialtecken vilket gör att det lagras som
en ren sträng och blir ofarlig för applikationen och användare. 
Applikationen kommer att leta efter ett sökresultat som är encodat till en ren sträng och returnera resultatet av det. 


---


**Path traversal - pom.xml**

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

**SQL injection - reveal private quiz**

## Exploit

1. Gå till hemsidan `(http://localhost:8080/)` 
2. Logga in som `Brad` med lösenord `apples` och gå in på `PLAY` fliken.
3. Välj en quiz `Actors by Angelina` och notera att URL är `http://localhost:8080/play/3`
4. Ändra URL så den blir: `http://localhost:8080/play/5`, då kommer ett fel meddelande `"No quiz with ID 5, or you are not allowed to access this quiz."`
5. Lägg till `--` i slutet av URL : `http://localhost:8080/play/5--` detta gör att du nu får åtkomst till den privata quizen. 


## Vulnerability

Sårbarheten finns i metoden `singleQuizData`:

    private static void singleQuizData(Context context) throws SQLException {
        try (Connection c = db.getConnection()) {
            // Get the quiz info and put it in a map.
            Statement quizStatement = c.createStatement();
            String quizSql =
                "SELECT * FROM quiz " +
                // Either the current user owns the quiz and can access it whether it's public or not.
                "WHERE id = " + context.pathParam("quiz_id") + " " +
                "AND user_id = " + context.sessionAttribute("userId") + " " +
                // Or it's public and anybody can access it.
                "OR public = TRUE AND id = " + context.pathParam("quiz_id");
            ResultSet quizRows = quizStatement.executeQuery(quizSql);

När hackern använder sig av `--` gör man detta för att använda sig av SQL kommentars syntax. Det som matas in efter och hämtas av SQL queryt -- kommer bli bortkommenterat.
Detta funkar pga att applikationen använder sig av ren SQL i executeQuery. quizid sätts i metoden `context.sessionAttribute("userId")` där quizid sätts i URL och requestar efter den specifika quizen med det id:et.
SQL queryt som skickas till databasen blir då: `ResultSet quizRows = quizStatement.executeQuery(quizSql);` där `String quizSql` är : `SELECT * FROM quiz WHERE id = 5 AND user_id = 1 OR public = TRUE AND id = 5`
Resultatet är tänkt att bli att användaren ska få fram quizzet med id 5 och som är publikt för just den användaren som är inloggad. 

Detta betyder att lägger hackern in ``--`` kommer SQL queryt ändras till:
`SELECT * FROM quiz WHERE id = 5`
Vilket resulterar i att SQL kommandot kommer hämta quizet med id = 5 och ladda in det utan att sätta begränsningar på vem som är inloggad och om quizen är publikt eller inte.


## Fix

Vi täpper igen säkerhetshålet genom att använda oss av PreparedStatement:

    private static void singleQuizData(Context context) throws SQLException {
        try (Connection c = db.getConnection()) {
            int userId = context.sessionAttribute("userId");
            String quizSql = "SELECT * FROM quiz WHERE id =? AND user_id =? OR public =? AND id =?";
            PreparedStatement s = c.prepareStatement(quizSql);
            s.setString(1,context.pathParam("quiz_id"));
            s.setInt(2, userId);
            s.setBoolean(3, true);
            s.setString(4,context.pathParam("quiz_id"));
            ResultSet quizRows = s.executeQuery();

Genom att använda oss av PreparedStatements kan vi begränsa användarinput i URL som sätts i ``pathParam``. PreparedStatements kommer att tolka inputen som värden och inte som ett rent SQL query där `'` används som fritext och som en hacker kan utnyttja och sätta in eget ``' för att ändra queryt.

Utan det som PreparedStatement hjälper oss att göra är vi specificerar vart i queryt vi vill ha användarens input med `?`.
Vi kan sedan med hjälp av PreparedStatement specificera vad vi vill ha för värde på varje `?` med `setString`, `setInt`, `setBoolean` och applikationen kommer då att endast tolka varje värde som en satt sträng.


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

Eftersom att de lösenord som ligger i `create.sql` är hashade måste man jämföra dem med hashade lösenord, det är inte lika enkelt att ta ett 
redan hashat lösenord och få tillbaka det ursprungsform. <br>
För att få fram lösenordet körde jag igenom alla 100 000 vanligaste lösenord genom en metod som hashar dem och sedan jämför de hashade lösenorden med 
lösenorden som låg i databasen:

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

Där assignment är en lista på alla 100,000 lösenord. För varje lösenord i listan hashade jag dem och sedan matchade dem mot det hashade
lösenordet som vi ville knäcka. 

Hade man gjort en riktig lösenordsattack hade hackern antagligen inte haft tillgång till `create.sql`filen och hade då behövt göra en `SQLinjection` attack på applikationen. 


3. <b>Hur skulle applikationen behöva ändras för att förhindra denna attack? Förklara på teknisk nivå, inklusive referenser till relevanta metoder och/eller kodrader. </b>

För att förhundra denna attack kan man lägga till `Salt` på alla de sparade lösenorden. `Salt`är ett extra slags lager som hashar lösenorden med unika tecken för att öka deras komplexitet
utan att försvåra det för användarna när dem väljer lösenord. Så även om vi har flera användare som har samma lösenord kommer alla dessa lösenord få unika tecken och göra det extra svårt för hackers att 
knäcka lösenorden i en eventuell läcka. Att addera salt på lösenorden saktar även ner poteniella `dictonary och brut-force attacker`.

Först skapas unik salt:

    public static String createSalt() {
        byte[] saltBytes = new byte[128];
        new SecureRandom().nextBytes(saltBytes);
        String salt = Hex.encodeHexString(saltBytes);
        return salt;
    }

Sedan skickar man in `lösenord` och `salt` för att säkerställa att alla sparade lösenord blir unika hash:


    public static String createHash(String password, String salt) {
        try {
            // NIST recommends an iteration count of at least 10,000.
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 10000, 256);
            byte[] hashBytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(spec).getEncoded();
            String hash = Hex.encodeHexString(hashBytes);
            return hash;
        }


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
- Angelina: `77169 försök / 5 försök per minut = 15433,8 minuter / 1440 minuter per dag = 10,7179167 dagar = mellan 10-11 dagar`
- Will: `21067 försök / 5 försök per minut = 4213,4 minuter / 1440 minuter per dag = 2,92597222 dagar = nästan 3 dagar `


3. <b>Hur skulle applikationen behöva ändras för att begränsa antalet inloggningsförsök på detta sätt? 
Förklara på teknisk nivå, inklusive referenser till relevanta metoder och/eller kodrader.</b>

Man behöver sätta en gräns på hur många gånger som en användare kan skriva in fel användarnamn och lösenord och efter det sätta en gräns på efter hur lång tid applikationen
eller hemsidan ska låta användaren testa att logga in igen. <br>

Ändra log in metoden. 

**!BEHÖVS GÖRAS KLART!**

---
## 5. Säkerhetsprinciper

**Vilka är de viktigaste lärdomarna och principerna om säkerhet som du kommer att ta med dig från denna kurs?**

Jag hade inte jättemycket erfarenhet om säker mjukvara innan vi började kursen men känner att jag fått med mig väldigt mycket
kunskap och nyttiga tankeställare som kan vara bra att ta med mig ut i arbetslivet men även privat.
Dels har man fått stor inblick i hur stor makt användare kan få om man inte kontrollerar deras input via text/formulär i sin applikation/hemsida.
Användare kan använda inputs till att göra allt från att få fram hemliga filer genom `Path Traversal`, skicka in HTML kod via 
`Cross Site Script` till att få åtkomst till databas via `SQL injection`, vilket kan göra stor skada mot säkerheten. 
<br><br>
Jag tar även med mig all bra kunskap om att täppa igen säkerhetshålen och hur man begränsar att få en potentiell attack mot sig och hur 
begränsningarna man lägger in fungerar. 

Lösenord 

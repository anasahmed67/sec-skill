# Java Security Guidance & Language Pack

This reference provides language-specific vulnerability patterns, sources, sinks, framework idiosyncrasies, and secure coding practices for Java and Spring Boot applications.

---

## 1. Sources & Sinks in Java

### Untrusted Sources
- **Spring Boot / Servlets:** `@RequestParam`, `@PathVariable`, `@RequestBody`, `HttpServletRequest.getParameter()`, `HttpServletRequest.getHeader()`, `HttpServletRequest.getCookies()`.
- **JAX-RS:** `@QueryParam`, `@PathParam`, `@HeaderParam`, `@Context HttpHeaders`.
- **Message Queues:** JMS `Message.getText()`, Kafka `@KafkaListener(ConsumerRecord)`.

### Critical Sinks
- **SQL Execution:** `Statement.executeQuery()`, `Statement.executeUpdate()`, `EntityManager.createNativeQuery(unparameterizedString)`.
- **Command Execution:** `Runtime.getRuntime().exec()`, `ProcessBuilder.start()`.
- **XML External Entity (XXE):** `DocumentBuilderFactory.newDocumentBuilder().parse()`, `SAXParser.parse()`, `XMLInputFactory.createXMLStreamReader()`.
- **Deserialization:** `ObjectInputStream.readObject()`, `XMLDecoder.readObject()`.
- **LDAP Injection:** `DirContext.search(name, filter, ...)`.
- **Path Traversal:** `new File(basePath, userInput)`, `Paths.get(basePath, userInput)`.
- **Cryptographic Algorithms:** `Cipher.getInstance("DES")`, `MessageDigest.getInstance("MD5")`.

---

## 2. Common Vulnerabilities & Remediations

### SQL Injection (CWE-89)
*Vulnerable:*
```java
String query = "SELECT * FROM accounts WHERE owner = '" + req.getParameter("owner") + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```
*Secure:*
```java
String query = "SELECT * FROM accounts WHERE owner = ?";
PreparedStatement ps = connection.prepareStatement(query);
ps.setString(1, req.getParameter("owner"));
ResultSet rs = ps.executeQuery();
```

### XML External Entity (XXE Injection - CWE-611)
*Vulnerable:*
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(xmlPayload)));
```
*Secure:*
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// Explicitly disable external entity resolution and DTD processing
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(xmlPayload)));
```

### Insecure Deserialization (CWE-502)
*Vulnerable:*
```java
ByteArrayInputStream bais = new ByteArrayInputStream(untrustedData);
ObjectInputStream ois = new ObjectInputStream(bais);
Object obj = ois.readObject(); // Invokes gadget chains via Serializable
```
*Secure:*
```java
// Prefer JSON parsing (Jackson / Gson) with polymorphic typing disabled
ObjectMapper mapper = new ObjectMapper();
UserDto user = mapper.readValue(untrustedData, UserDto.class);

// If Java serialization is mandatory, use ObjectInputFilter (Java 9+):
ois.setObjectInputFilter(ObjectInputFilter.Config.customFilter({
    info -> info.serialClass() == AllowedClass.class ?
        ObjectInputFilter.Status.ALLOWED : ObjectInputFilter.Status.REJECTED
}));
```

### OS Command Injection (CWE-78)
*Vulnerable:*
```java
Runtime.getRuntime().exec("sh -c 'echo " + userInput + "'");
```
*Secure:*
```java
// Use ProcessBuilder with explicit tokenized argument array
ProcessBuilder pb = new ProcessBuilder("echo", userInput);
Process process = pb.start();
```

---

## 3. Future Language Packs (Go, Rust, Ruby, PHP, C/C++)

For languages outside v1 (Python, JS/TS, Java):
- SecSkill applies generic regex heuristics and relies on Stage 4 LLM contextual analysis.
- Findings are explicitly labeled with an advisory:
  > *[Language Advisory: Non-v1 Language Pack]*
  > *Analysis conducted using generalized heuristic analysis and LLM contextual triage. Static AST validation is reduced. Cross-validation with dedicated compiler tooling (e.g., `cargo audit`, `govulncheck`, `brakeman`, `clang-tidy`) is recommended.*


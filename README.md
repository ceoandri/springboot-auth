# springboot-auth

## Prequisite
1. Springboot v3.0.6
2. Java 17

## How to use this library for your maven project
1. Add this repository setting in your `pom.xml`
    ```xml
    <repositories>
        <repository>
            <id>nexus-solecode-snapshots</id>
            <name>nexus-solecode-snapshots</name>
            <url>https://nexus.solecode.tech/repository/maven-snapshots/</url>
        </repository>
    </repositories>
    ```
2. Add the dependency you need inside `pom.xml`.
    ```xml
    <dependency>
        <groupId>gratis.contoh</groupId>
        <artifactId>auth</artifactId>
        <version>1.0-SNAPSHOT</version>
        <scope>compile</scope>
    </dependency>
    ```
3. Run `mvn clean install` inside your project directory

## How To Use
```
@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/1")
    @Authorize
    public ResponseEntity<String> apiSample(HttpServletRequest request) {
        return ResponseEntity.ok("Hello world!");
    }
    
    @PostMapping("/2")
    @Authorize(
			roles = {"SUPER ADMIN", "ADMIN"}, 
			module = "API", 
			accessTypes = {"CREATE", "UPDATE"})
    public ResponseEntity<String> apiSample(HttpServletRequest request, ModelRequest item) {
        return ResponseEntity.ok("Hello world!");
    }
	
}
```
it's mandatory to always put `HttpServletRequest` as a first parameter 
roles, module, and accessTypes are optional. but, if you want to set the accessType, you need to set module

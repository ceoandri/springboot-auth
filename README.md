# springboot-auth

## Prerequisite
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
1. Create configuration file as catcher
```
@Configuration
@ComponentScan("gratis.contoh.auth.catcher")
@EnableAspectJAutoProxy
public class AuthCatcherConfiguration {

}
```

2. Create configuration file that implement `AuthorizeValidator`.
```
@Configuration
public class AuthValidatorConfiguration implements AuthorizeValidator {

    @Override
    public Boolean verify(String headerValue, String[] roles, String module, String[] accessType) {
        // put your logic here. just return true when passed and false when failed
    }

}
```
- `headerValue` contains token or something that you passed from FE that need to be authorize.
- `roles` contains list of role or []
- `module` contains module 
- `accessType` contains list of access type or []

3. Use annotation `@Authorize` in your method
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
it's mandatory to always put `HttpServletRequest` as a first parameter. `roles`, `module`, and `accessTypes` are optional. but, if you want to set the `accessType`, you need to set `module`

# spring-auth

## Prerequisite
1. Springboot v3
2. Java 17 or later
 
## How to use this library for your maven project
1. Add this repository setting in your `pom.xml`
```xml
<repositories>
	<repository>
		<id>contoh-gratis</id>
		<name>contoh-gratis</name>
		<url>https://nexus.contoh.gratis/repository/maven-public/</url>
	</repository>
</repositories>
```
2. Add the dependency you need inside `pom.xml`.
```xml
<dependency>
	<groupId>gratis.contoh</groupId>
	<artifactId>auth</artifactId>
	<version>1.0.0</version>
</dependency>
```
3. Run `mvn clean install` inside your project directory

## How To Use
1. Create configuration file that implement `AuthorizeValidator`.
```
@Configuration
@ComponentScan("gratis.contoh.auth.catcher")
@EnableAspectJAutoProxy
public class AuthValidatorConfiguration implements AuthorizeValidator {

    @Override
    public Boolean isAuthenticate(String headerValue) {
        // put your logic here. just return true when passed and false when failed
    }
    
    @Override
    public Boolean isAuthorize(String headerValue, String[] roles, String module, String[] accessType) {
        // put your logic here. just return true when passed and false when failed
    }

}
```
- `headerValue` contains token or something that you passed from FE that need to be authorize.
- `roles` contains list of role or []
- `module` contains module 
- `accessType` contains list of access type or []

2. Use annotation `@Authorize` in your method
```
@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/1")
    @Authorize
    public ResponseEntity<String> apiSample() {
        return ResponseEntity.ok("Hello world!");
    }
    
    @PostMapping("/2")
    @Authorize(
	header = "Authorization", //The default value is Authorization
	// The default value is Bearer, you can edit it with Basic or anything you want
	// If you using custom name, the headerValue will as is from header value sent from FE
	// i.e if you send token '123123 asdasd1 124123', the header value will filled with '123123 asdasd1 124123'
	authType = "Bearer", 
	roles = {"SUPER ADMIN", "ADMIN"}, 
	module = "API", 
	accessTypes = {"CREATE", "UPDATE"})
    public ResponseEntity<String> apiSample(HttpServletRequest request, ModelRequest item) {
        return ResponseEntity.ok("Hello world!");
    }
	
}
```
`roles`, `module`, and `accessTypes` are optional.

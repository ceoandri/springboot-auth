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

# java-netrc parser
A simple, lightweight component to provide .netrc file parsing in Java applications. Has no dependencies, just a single parser class and Credentials POJO.

I have required this in numerous projects, both simple and complex, so I extracted it from larger libraries for simple use.

## Updated for Kotlin DSL Gradle and Java 11



## Usage

```java
import co.cdjones.security.auth.NetrcParser;
import co.cdjones.security.auth.Credentials;

public class Test {
    public static void main(String[] args) {
        NetrcParser netrc = NetrcParser.getInstance();
        Credentials credentials = netrc.getCredentials("localhost");

        System.out.println(credentials.user());
    }
}
```

## Getting it

The original java-netrc library can be found with jitpack.io

The artifacts are provided by JitPack. Example usage for Gradle:

```groovy
allprojects {
    repositories {
        mavenCentral()
        maven { url 'https://jitpack.io' }
    }
}

dependencies {
    compile "com.github.cdjones32:java-netrc:1.0.1"
}
```

## History 
1.0.1 - Fixed an issue where comments which were not at the start of a line would still be parsed.

### Credits
The source for this was taken almost verbatim from the OpenSource Jenkins [git-client-plugin](https://github.com/jenkinsci/git-client-plugin/blob/9aba79579829a2826b2485b708ab6e724e1853b7/src/main/java/org/jenkinsci/plugins/gitclient/Netrc.java)


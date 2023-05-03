/*
 * This file was generated by the Gradle 'init' task.
 *
 * This generated file contains a sample Kotlin library project to get you started.
 * For more details take a look at the 'Building Java & JVM projects' chapter in the Gradle
 * User Manual available at https://docs.gradle.org/8.1/userguide/building_java_projects.html
 */

plugins {
    // Apply the org.jetbrains.kotlin.jvm Plugin to add support for Kotlin.
    id("org.jetbrains.kotlin.jvm") version "1.8.10"

    // Apply the java-library plugin for API and implementation separation.
    `java-library`
    `maven-publish`
}

group = "com.sys1yagi"
version = "0.0.1-SNAPSHOT"
description = "netrc parser"

publishing {
    publications.create<MavenPublication>("maven") {
        from(components["java"])
    }

    repositories {
        maven {
	          // releases
            name = "caeneus"
            setAllowInsecureProtocol(true)
	          credentials(PasswordCredentials::class)
            // only if we have a version and it does not end with SNAPSHOT use the releases
            if (hasProperty("version") && 
                    !property("version").toString().endsWith("-SNAPSHOT")) {
                url = uri("http://caeneus.fritz.box:8081/repository/caeneus-1")
       	        mavenContent {
            	      releasesOnly()
                }
            } else {
                url = uri("http://caeneus.fritz.box:8081/repository/caeneus-2")
       	        mavenContent {
            	      snapshotsOnly()
                }
            }
	      }
    }

    tasks.withType<JavaCompile>() {
        options.encoding = "UTF-8"
    }

    tasks.withType<Javadoc>() {
        options.encoding = "UTF-8"
    }
}

repositories {
    maven {
        setAllowInsecureProtocol(true)        
        url = uri("http://caeneus.fritz.box:8081/repository/caeneus-3/")
    }
    gradlePluginPortal()
}

dependencies {
    // Use the JUnit 5 integration.
    testImplementation(platform("org.junit:junit-bom:5.9.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    // testImplementation("org.junit.jupiter:junit-jupiter-engine:5.9.1")

    testImplementation("commons-io:commons-io:2.11.0")

    api("org.slf4j:slf4j-api:2.0.7")
    testImplementation("ch.qos.logback:logback-core:1.4.7")
    testImplementation(libs.logback.classic)

}

// Apply a specific Java toolchain to ease working on different environments.
java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(11))
    }
}

tasks.named<Test>("test") {
    // Use JUnit Platform for unit tests.
    useJUnitPlatform()
}
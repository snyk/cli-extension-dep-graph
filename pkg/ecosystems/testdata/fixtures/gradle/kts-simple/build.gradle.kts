plugins {
    java
}

group = "com.snyk.fixtures"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.google.guava:guava:33.3.1-jre")
    implementation("org.apache.commons:commons-lang3:3.14.0")
}

plugins {
    id("org.springframework.boot") version Versions.springboot
    id("org.graalvm.buildtools.native") version Versions.nativeBuildTools
}

graalvmNative {
    binaries {
        named("main"){
            sharedLibrary.set(false)
            mainClass.set("com.labijie.dummy.ApplicationKt")
        }

    }
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation(project(":oauth2-authorization-server-starter"))
    implementation(project(":oauth2-resource-server-starter"))
    implementation("com.h2database:h2")
    implementation(project(":dummy-auth-server-starter"))
}
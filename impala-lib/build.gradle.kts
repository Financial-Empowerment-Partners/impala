import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library") version "9.3.2"
    // AGP 9 has built-in Kotlin: the kotlin-android plugin must NOT be applied.
    // It stays on the classpath (apply false) so built-in Kotlin resolves KGP
    // 2.4.0 instead of the 2.2.x AGP bundles as its floor.
    id("org.jetbrains.kotlin.android") version "2.4.0" apply false
}

android {
    namespace = "com.payala.impala"
    compileSdk = 37

    defaultConfig {
        minSdk = 24

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        // IsoDepBibo logs via android.util.Log on the exception paths the
        // unit tests exercise; return 0 instead of throwing "not mocked".
        unitTests.isReturnDefaultValues = true
        unitTests.isIncludeAndroidResources = true
    }

    lint {
        // Integration artifact, not a Play submission; report lint findings
        // without failing `build`.
        abortOnError = false
    }
}

kotlin {
    // Java 21 toolchain: Robolectric's SDK-36 sandbox requires >= 21, and its
    // ASM cannot read newer (e.g. JDK 26) class files — so pin rather than
    // inherit the launcher JDK. Bytecode still targets 17 (below).
    jvmToolchain(21)

    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.core:core-ktx:1.19.0")
    // Resolved via composite build (settings.gradle.kts includes ../impala-card).
    // Dependency substitution maps this coordinate to the :sdk project.
    implementation("com.impala:sdk:0.0.1-HEAD")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.mockito:mockito-core:5.23.0")
    testImplementation("org.robolectric:robolectric:4.16.1")
    testImplementation("androidx.test:core:1.7.0")
    testImplementation("androidx.test.ext:junit:1.3.0")

    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
}

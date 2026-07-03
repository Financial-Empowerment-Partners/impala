plugins {
    // Must match the AGP version of the included impala-card build
    // (impala-card/gradle/libs.versions.toml `agp`): a composite build can
    // only load one AGP version.
    id("com.android.application") version "8.12.0-alpha06"
}

android {
    namespace = "com.payala.impala"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.payala.impala"
        // Floor inherited from impala-card's :sdk Android library (minSdk 30).
        minSdk = 30
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    testOptions {
        unitTests {
            // IsoDepBibo logs via android.util.Log on the exception paths the
            // unit tests exercise; return 0 instead of throwing "not mocked".
            isReturnDefaultValues = true
        }
    }
    lint {
        // Integration artifact, not a Play submission; report lint findings
        // without failing `build`.
        abortOnError = false
    }
}

dependencies {

    implementation("androidx.appcompat:appcompat:1.7.0")
    // Substituted with the impala-card included build's :sdk project
    // (see settings.gradle.kts).
    implementation("com.impala:sdk:0.0.1-HEAD")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.mockito:mockito-core:5.11.0")
    implementation("androidx.core:core:1.12.0")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
}

import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    // org.jetbrains.kotlin.android is NOT applied: AGP 9's built-in Kotlin
    // compiles Kotlin sources (kotlin {} DSL below still configures it).
    id("com.google.gms.google-services")
}

val localProperties = Properties()
val localPropertiesFile = rootProject.file("local.properties")
if (localPropertiesFile.exists()) {
    localProperties.load(localPropertiesFile.inputStream())
}

android {
    namespace = "com.payala.impala.demo"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.payala.impala.demo"
        minSdk = 24
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    flavorDimensions += "network"
    productFlavors {
        // Flavor token must not start with "test" (Android Gradle Plugin forbids it),
        // so the flavor is named "tnet". The Stellar network, applicationId suffix,
        // versionName suffix, and TESTNET_* local.properties keys remain "testnet"
        // so installed app identity and config keys are unchanged.
        create("tnet") {
            dimension = "network"
            applicationIdSuffix = ".testnet"
            versionNameSuffix = "-testnet"

            buildConfigField("String", "STELLAR_NETWORK", "\"testnet\"")
            buildConfigField("String", "BRIDGE_BASE_URL",
                "\"${localProperties.getProperty("TESTNET_BRIDGE_BASE_URL", "http://10.0.2.2:8080")}\"")
            buildConfigField("String", "GITHUB_CLIENT_ID",
                "\"${localProperties.getProperty("TESTNET_GITHUB_CLIENT_ID", "YOUR_GITHUB_CLIENT_ID")}\"")
            // No GitHub client-secret field: the bridge performs the OAuth code→token
            // exchange server-side, so the secret never ships in the APK.
            buildConfigField("String", "GITHUB_REDIRECT_URI",
                "\"${localProperties.getProperty("TESTNET_GITHUB_REDIRECT_URI", "impala://github-callback")}\"")
            buildConfigField("String", "GOOGLE_WEB_CLIENT_ID",
                "\"${localProperties.getProperty("TESTNET_GOOGLE_WEB_CLIENT_ID", "YOUR_GOOGLE_WEB_CLIENT_ID")}\"")
            buildConfigField("String", "OKTA_ISSUER_URL",
                "\"${localProperties.getProperty("TESTNET_OKTA_ISSUER_URL", "")}\"")
            buildConfigField("String", "OKTA_CLIENT_ID",
                "\"${localProperties.getProperty("TESTNET_OKTA_CLIENT_ID", "")}\"")
            buildConfigField("String", "OKTA_REDIRECT_URI",
                "\"${localProperties.getProperty("TESTNET_OKTA_REDIRECT_URI", "impala://okta-callback")}\"")
        }
        create("live") {
            dimension = "network"

            buildConfigField("String", "STELLAR_NETWORK", "\"pubnet\"")
            buildConfigField("String", "BRIDGE_BASE_URL",
                "\"${localProperties.getProperty("LIVE_BRIDGE_BASE_URL", "https://api.impala.example.com")}\"")
            buildConfigField("String", "GITHUB_CLIENT_ID",
                "\"${localProperties.getProperty("LIVE_GITHUB_CLIENT_ID", "YOUR_GITHUB_CLIENT_ID")}\"")
            // No GitHub client-secret field: the bridge performs the OAuth code→token
            // exchange server-side, so the secret never ships in the APK.
            buildConfigField("String", "GITHUB_REDIRECT_URI",
                "\"${localProperties.getProperty("LIVE_GITHUB_REDIRECT_URI", "impala://github-callback")}\"")
            buildConfigField("String", "GOOGLE_WEB_CLIENT_ID",
                "\"${localProperties.getProperty("LIVE_GOOGLE_WEB_CLIENT_ID", "YOUR_GOOGLE_WEB_CLIENT_ID")}\"")
            buildConfigField("String", "OKTA_ISSUER_URL",
                "\"${localProperties.getProperty("LIVE_OKTA_ISSUER_URL", "")}\"")
            buildConfigField("String", "OKTA_CLIENT_ID",
                "\"${localProperties.getProperty("LIVE_OKTA_CLIENT_ID", "")}\"")
            buildConfigField("String", "OKTA_REDIRECT_URI",
                "\"${localProperties.getProperty("LIVE_OKTA_REDIRECT_URI", "impala://okta-callback")}\"")
        }
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        // java.time is used throughout (AppLogger, fragments) but minSdk is 24;
        // desugaring backports it so API 24/25 devices don't crash at runtime.
        isCoreLibraryDesugaringEnabled = true
    }

}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // Backports java.time (and other java.util/java.io APIs) below API 26.
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")

    // AndroidX Core
    implementation("androidx.core:core-ktx:1.19.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.13.0")
    implementation("androidx.fragment:fragment-ktx:1.8.9")
    // 2.10.0 is the latest 2.10.x stable (2.11.0 is rc-only as of 2026-06); re-check before bumping.
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.10.0")
    implementation("androidx.lifecycle:lifecycle-livedata-ktx:2.10.0")
    implementation("androidx.constraintlayout:constraintlayout:2.2.1")
    implementation("androidx.recyclerview:recyclerview:1.4.0")

    // Material Design 3
    implementation("com.google.android.material:material:1.14.0")

    // Navigation
    implementation("androidx.navigation:navigation-fragment-ktx:2.9.8")
    implementation("androidx.navigation:navigation-ui-ktx:2.9.8")

    // Networking: OkHttp + Retrofit + Gson
    // Retrofit 3.0.0's POM declares okhttp 4.12.0 (compile scope); Gradle
    // conflict-resolves upward to 5.4.0. OkHttp 5 keeps the okhttp3 package
    // and a 4.x-source-compatible API.
    implementation("com.squareup.okhttp3:okhttp:5.4.0")
    implementation("com.squareup.okhttp3:logging-interceptor:5.4.0")
    implementation("com.squareup.retrofit2:retrofit:3.0.0")
    implementation("com.squareup.retrofit2:converter-gson:3.0.0")
    implementation("com.google.code.gson:gson:2.14.0")

    // Encrypted SharedPreferences (backs TokenManager's secure token store).
    // NOTE: androidx.security:security-crypto 1.1.0 stable shipped 2025-07 (this
    // is the final release; it is still deprecated upstream in favor of Tink).
    // For new work prefer migrating the TokenManager store to Tink directly or
    // the platform Keystore. Tracked as a follow-up; TokenManager already takes
    // an injectable SharedPreferences so the backing store can be swapped
    // without touching call sites.
    implementation("androidx.security:security-crypto:1.1.0")

    // Google Sign-In via Credential Manager
    implementation("androidx.credentials:credentials:1.6.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.6.0")
    implementation("com.google.android.libraries.identity.googleid:googleid:1.1.1")

    // Custom Tabs for GitHub OAuth
    implementation("androidx.browser:browser:1.10.0")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    // Firebase Cloud Messaging
    implementation(platform("com.google.firebase:firebase-bom:34.14.1"))
    implementation("com.google.firebase:firebase-messaging")

    // Testing
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.16.1")
    testImplementation("androidx.test:core:1.7.0")
    testImplementation("androidx.test.ext:junit:1.3.0")
    testImplementation("androidx.arch.core:core-testing:2.2.0")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("org.mockito:mockito-core:5.23.0")
    testImplementation("org.mockito.kotlin:mockito-kotlin:6.3.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
}

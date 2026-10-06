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
            // Applet-instance AID of the testnet CAP (impala-card/applet/build.xml applet.aid.app).
            buildConfigField("String", "CARD_APPLET_AID",
                "\"${localProperties.getProperty("TESTNET_CARD_APPLET_AID", "01020304050607080102")}\"")
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
            // Live CAP instance AID (CI variable IMPALA_CARD_LIVE_AID_APP). Empty means
            // no SELECT: the card's default-selected applet answers.
            buildConfigField("String", "CARD_APPLET_AID",
                "\"${localProperties.getProperty("LIVE_CARD_APPLET_AID", "")}\"")
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

    testOptions {
        // Robolectric tests read the merged manifest and resources (ManifestTest,
        // card error strings).
        unitTests.isIncludeAndroidResources = true
    }

    // T1 end-to-end lane (src/e2e): JVM tests that drive the app's real flow
    // classes against a LIVE bridge with a jcardsim card issued by the
    // impala-card issuance tool. They compile with the unit tests and skip
    // unless IMPALA_E2E_BRIDGE_URL is set; `./gradlew :app:e2eTnetDebug` runs
    // only them.
    sourceSets {
        getByName("test") { kotlin.srcDir("src/e2e/java") }
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
    // Java 21 toolchain: Robolectric's SDK-36 sandbox requires >= 21, and its
    // ASM cannot read newer (e.g. JDK 26) class files — so pin rather than
    // inherit the launcher JDK. Bytecode still targets 17 (below).
    jvmToolchain(21)

    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // Backports java.time (and other java.util/java.io APIs) below API 26.
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")

    // Card SDK (com.impala.sdk.flows: identity, auth, redemption, credit) and the
    // Android card module (NFC reader mode, sessions). Both resolve to sibling
    // builds via settings.gradle.kts.
    implementation("com.impala:sdk:0.0.1-HEAD")
    implementation("com.payala:impala-lib:0.0.1-HEAD")

    // AndroidX Core
    implementation("androidx.core:core-ktx:1.19.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.13.0")
    implementation("androidx.fragment:fragment-ktx:1.8.9")
    // 2.10.0 is the latest 2.10.x stable (2.11.0 is rc-only as of 2026-06); re-check before bumping.
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.11.0")
    implementation("androidx.lifecycle:lifecycle-livedata-ktx:2.11.0")
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
    // The real ImpalaApplet on jcardsim + a JCA test issuer (../impala-card :simulator).
    testImplementation("com.impala:simulator:0.0.1-HEAD")
    // The issuance ceremony (impala-card tools/issue) for the e2e lane.
    testImplementation("com.impala:issue:0.0.1-HEAD")
    testImplementation("org.robolectric:robolectric:4.16.1")
    testImplementation("androidx.test:core:1.7.0")
    testImplementation("androidx.test.ext:junit:1.3.0")
    testImplementation("androidx.arch.core:core-testing:2.2.0")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("org.mockito:mockito-core:5.23.0")
    testImplementation("org.mockito.kotlin:mockito-kotlin:6.3.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    // ActivityScenario + lifecycle monitor for the card UI lane (CardLoginUiTest).
    androidTestImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}

// `./gradlew :app:e2eTnetDebug` — the e2e lane only (needs IMPALA_E2E_BRIDGE_URL;
// see app/src/e2e/README.md). Plain unit-test runs include these classes too,
// where they skip.
val e2eRequested = gradle.startParameter.taskNames.any { it.substringAfterLast(':') == "e2eTnetDebug" }
tasks.withType<Test>().configureEach {
    if (e2eRequested && name == "testTnetDebugUnitTest") {
        filter.includeTestsMatching("com.payala.impala.demo.e2e.*")
        outputs.upToDateWhen { false }
        testLogging { events("passed", "skipped", "failed"); showStandardStreams = true }
        listOf(
            "IMPALA_E2E_BRIDGE_URL", "IMPALA_E2E_OPERATOR_TOKEN_FILE", "IMPALA_E2E_OPERATOR_ACCOUNT",
            "IMPALA_E2E_OPERATOR_PASSWORD_FILE", "IMPALA_E2E_HOLDER_PASSWORD_FILE", "IMPALA_E2E_SLOW"
        ).forEach { key -> System.getenv(key)?.let { environment(key, it) } }
    }
}
tasks.register("e2eTnetDebug") {
    group = "verification"
    description = "Card login/transfer end-to-end tests against a live bridge (IMPALA_E2E_BRIDGE_URL)"
    dependsOn("testTnetDebugUnitTest")
}

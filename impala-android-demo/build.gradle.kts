plugins {
    id("com.android.application") version "9.2.1" apply false
    // AGP 9 has built-in Kotlin; this entry is classpath-only (never applied in
    // :app) so built-in Kotlin resolves KGP 2.4.0 instead of its bundled floor.
    id("org.jetbrains.kotlin.android") version "2.4.0" apply false
    id("com.google.gms.google-services") version "4.4.4" apply false
}

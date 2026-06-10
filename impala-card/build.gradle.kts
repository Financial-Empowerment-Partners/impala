plugins {
    //trick: for the same plugin versions in all sub-modules
    alias(libs.plugins.androidKmpLibrary).apply(false)
    alias(libs.plugins.kotlinMultiplatform).apply(false)
    alias(libs.plugins.mavenPublish).apply(false)
}

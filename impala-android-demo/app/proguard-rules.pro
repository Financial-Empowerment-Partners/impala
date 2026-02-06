# Retrofit
-keepattributes Signature
-keepattributes *Annotation*
-keep class com.payala.impala.demo.model.** { *; }
-dontwarn retrofit2.**
-keep class retrofit2.** { *; }

# Gson
-keep class com.google.gson.** { *; }
-keepattributes EnclosingMethod

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**

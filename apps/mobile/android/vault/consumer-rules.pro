# What code shrinking must leave as it is for the shared code's library to
# be called, in any app that uses this module: JNA finds native functions
# by the names of the generated interface's methods and reads structures'
# fields by name and annotation, so neither JNA nor the bindings may be
# renamed or removed.
-keep class com.sun.jna.** { *; }
-keep class * extends com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class org.opensecretmanager.vault.** { *; }
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod
-dontwarn java.awt.**

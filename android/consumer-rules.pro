## BouncyCastle - required by iText7 for PDF signing
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

## iText7
-keep class com.itextpdf.** { *; }
-dontwarn com.itextpdf.**

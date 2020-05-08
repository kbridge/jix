# Java Installer Extractor

Extract files in Oracle JDK installer without running it. (Includes `COPYRIGHT` and `src.zip`.)

Works for JDK7 - JDK14.

License: MIT

Download: Releases

Usage:

```
jix <installer path> <output directory>
```

Build with MinGW:

```
mingw32-make
```

Build with MSVC:

```
cl /Fe:jix.exe /W4 jix.c miniz.c /MT /link ole32.lib oleaut32.lib uuid.lib cabinet.lib
```

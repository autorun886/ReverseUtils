# frida_dump

## 1. dump android module

### usage:

​	**python dump_so.py**

​	**python dump_so.py so_name**

```
➜  frida_dump git:(master) ✗ python dump_so.py libc.so              
{'name': 'libc.so', 'base': '0xf2282000', 'size': 819200, 'path': '/apex/com.android.runtime/lib/bionic/libc.so'}
android/SoFixer32: 1 file pushed. 5.9 MB/s (91848 bytes in 0.015s)
libc.so.dump.so: 1 file pushed. 21.4 MB/s (819200 bytes in 0.036s)
adb shell /data/local/tmp/SoFixer -m 0xf2282000 -s /data/local/tmp/libc.so.dump.so -o /data/local/tmp/libc.so.dump.so.fix.so
[main_loop:87]start to rebuild elf file
[Load:69]dynamic segment have been found in loadable segment, argument baseso will be ignored.
[RebuildPhdr:25]=============LoadDynamicSectionFromBaseSource==========RebuildPhdr=========================
[RebuildPhdr:37]=====================RebuildPhdr End======================
[ReadSoInfo:549]=======================ReadSoInfo=========================
[ReadSoInfo:696]soname 
[ReadSoInfo:699]Unused DT entry: type 0x6ffffffb arg 0x00000001
[ReadSoInfo:599] rel (DT_REL) found at 15f20
[ReadSoInfo:603] rel_size (DT_RELSZ) 1703
[ReadSoInfo:699]Unused DT entry: type 0x6ffffffa arg 0x000005f5
[ReadSoInfo:591] plt_rel (DT_JMPREL) found at 19458
[ReadSoInfo:595] plt_rel_count (DT_PLTRELSZ) 617
[ReadSoInfo:584]symbol table found at 32ac
[ReadSoInfo:580]string table found at 10e58
[ReadSoInfo:699]Unused DT entry: type 0x6ffffef5 arg 0x0000a98c
[ReadSoInfo:629] constructors (DT_INIT_ARRAY) found at b5954
[ReadSoInfo:633] constructors (DT_INIT_ARRAYSZ) 4
[ReadSoInfo:637] destructors (DT_FINI_ARRAY) found at b3000
[ReadSoInfo:641] destructors (DT_FINI_ARRAYSZ) 2
[ReadSoInfo:699]Unused DT entry: type 0x6ffffff0 arg 0x00009b4c
[ReadSoInfo:699]Unused DT entry: type 0x6ffffffc arg 0x0000a860
[ReadSoInfo:699]Unused DT entry: type 0x6ffffffd arg 0x00000009
[ReadSoInfo:699]Unused DT entry: type 0x6ffffffe arg 0x0000a95c
[ReadSoInfo:699]Unused DT entry: type 0x6fffffff arg 0x00000001
[ReadSoInfo:703]=======================ReadSoInfo End=========================
[RebuildShdr:42]=======================RebuildShdr=========================
[RebuildShdr:536]=====================RebuildShdr End======================
[RebuildRelocs:783]=======================RebuildRelocs=========================
[RebuildRelocs:809]=======================RebuildRelocs End=======================
[RebuildFin:709]=======================try to finish file rebuild =========================
[RebuildFin:733]=======================End=========================
[main:123]Done!!!
/data/local/tmp/libc.so.dump.so.fix.so: 1 file pulled. 29.0 MB/s (819882 bytes in 0.027s)
libc.so_0xf2282000_819200_fix.so
```

## 2. dump android dex

```Text
frida -U --no-pause -f packagename  -l dump_dex.js
     ____
    / _  |   Frida 12.4.8 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/
Spawned `packagename`. Resuming main thread!
[Google Pixel XL::packagename]-> [dlopen:] libart.so
_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE 0x7ac6dc4f74
[DefineClass:] 0x7ac6dc4f74
[dump dex]: /data/data/packagename/files/7aab800000_8341c4.dex
```


## 3. [Recommended] Use dexCache to dump Android DEX files
```
frida -UF -l dexCache_dump.js
     ____
    / _  |   Frida 16.7.19 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Android Emulator 5554 (id=emulator-5554)
dalvik.system.DelegateLastClassLoader[DexPathList[[zip file "/data/user_de/0/com.google.android.gms/app_chimera/m/00000002/DynamiteLoader.apk"],nativeLibraryDirectories=[/system/lib64, /system_ext/lib64]]] /data/user_de/0/com.google.android.gms/app_chimera/m/00000002/DynamiteLoader.apk 0x77d228a2f02c 0x24a3c 
                0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
77d228a2f02c  64 65 78 0a 30 33 35 00 41 1f 99 26 52 fb 1a ab  dex.035.A..&R...
77d228a2f03c  b4 8a 64 29 d6 ae cb 20 58 99 82 f4 47 bf dc 64  ..d)... X...G..d
77d228a2f04c  3c 4a 02 00 70 00 00 00 78 56 34 12 00 00 00 00  <J..p...xV4.....
77d228a2f05c  00 00 00 00 6c 49 02 00 60 05 00 00 70 00 00 00  ....lI..`...p...
77d228a2f06c  c1 01 00 00 f0 15 00 00 ad 01 00 00 f4 1c 00 00  ................
77d228a2f07c  79 01 00 00 10 31 00 00 b0 05 00 00 d8 3c 00 00  y....1.......<..
77d228a2f08c  ea 00 00 00 58 6a 00 00 a4 c2 01 00 98 87 00 00  ....Xj..........
77d228a2f09c  f8 a8 01 00 fa a8 01 00 fd a8 01 00 07 a9 01 00  ................
77d228a2f0ac  0f a9 01 00 31 a9 01 00 39 a9 01 00 3d a9 01 00  ....1...9...=...
77d228a2f0bc  4f a9 01 00 53 a9 01 00 59 a9 01 00 6b a9 01 00  O...S...Y...k...
77d228a2f0cc  7a a9 01 00 7e a9 01 00 85 a9 01 00 95 a9 01 00  z...~...........
77d228a2f0dc  a0 a9 01 00 aa a9 01 00 c7 a9 01 00 ce a9 01 00  ................
77d228a2f0ec  d9 a9 01 00 e0 a9 01 00 f4 a9 01 00 07 aa 01 00  ................
77d228a2f0fc  24 aa 01 00 2a aa 01 00 58 aa 01 00 5f aa 01 00  $...*...X..._...
77d228a2f10c  67 aa 01 00 6e aa 01 00 75 aa 01 00 7f aa 01 00  g...n...u.......
77d228a2f11c  94 aa 01 00 9c aa 01 00 a6 aa 01 00 af aa 01 00  ................
[find dex]: /data/data/com.android.chrome/files/dump_dex_com.android.chrome/class.dex
[dump dex]: /data/data/com.android.chrome/files/dump_dex_com.android.chrome/class.dex
```

### Thanks

[https://github.com/F8LEFT/SoFixer](https://github.com/F8LEFT/SoFixer)
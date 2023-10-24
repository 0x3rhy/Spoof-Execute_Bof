all:
	i686-w64-mingw32-gcc -o dist/spoofSpawn.x86.o -Os -DBOF -c src/main.c -lntdll
	i686-w64-mingw32-strip --strip-unneeded dist/spoofSpawn.x86.o
	x86_64-w64-mingw32-gcc -o dist/spoofSpawn.x64.o -Os -DBOF -c src/main.c -lntdll
	x86_64-w64-mingw32-strip --strip-unneeded dist/spoofSpawn.x64.o

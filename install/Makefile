# install.c is in the download.  installui.m is bundled.
include ../env.mk

all: install.dylib wad.bin 

install.dylib: install.o copier.o 
	$(GCC_UNIVERSAL) -dynamiclib -o $@ $^ -framework Foundation -framework CoreFoundation libtar.a liblzma.a -framework GraphicsServices

%.o: %.c common.h 
	$(GCC_UNIVERSAL) -Iheaders -std=gnu99 -c -o $@ $< -Werror

wad.bin: install.dylib riot.tar.xz
	python wad.py $^

tarball:
	rm -f riot.tar.xz
	(cd fs; tar -cvf ../riot.tar *; cd ..)
	xz riot.tar


clean:
	rm -f install.dylib *.o wad.bin
	

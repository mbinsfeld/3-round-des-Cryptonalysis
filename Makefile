all: hwdes.c
	gcc -o hwdes hwdes.c

clean:
	$(RM) hwdes
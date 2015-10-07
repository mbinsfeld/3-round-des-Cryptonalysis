all: hwdes.c
	g++ -o hwdes hwdes.cpp

clean:
	$(RM) hwdes
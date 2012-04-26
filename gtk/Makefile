
CFLAGS = -g -Wall
LIBS = `pkg-config --cflags --libs gtk+-2.0` -lpthread

gtkui.o: gtkui.c
	gcc $(CFLAGS) -c -o gtkui.o gtkui.c $(LIBS)

clean:
	rm -rf gtkui.o

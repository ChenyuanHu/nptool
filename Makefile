
CFILES = main.c analyser.c cvrttime.c
HFILES = adapter.h  analyser.h  cvrttime.h  proto_headers.h
OBJECTS = $(CFILES:.c=.o)

LIBS := -lpthread -lpcap `pkg-config --cflags --libs gtk+-2.0` 
CFLAGS = -g -Wall

all: $(OBJECTS)
	make -C gtk
	gcc $(CFLAGS) -o nptool $^ gtk/gtkui.o $(LIBS)

%.o: %.c $(HFILES)
	gcc $(CFLAGS) -c -o $@ $< 

clean:
	make -C gtk clean
	rm -rf nptool $(OBJECTS) tags

tags:
	ctags -R *

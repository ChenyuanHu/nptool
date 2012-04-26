#ifndef __GTKUI_H__
#define __GTKUI_H__

#include "../adapter.h"

struct interface_list {
	char *name;
	struct interface_list *next;
};

void gui_set_interface_list(struct interface_list *list);

void gui_register_exit(void (*fun)(void));
void gui_register_stop(void (*fun)(void));

pthread_t gui_pthread_start(int *argc, char ***argv);

int gui_wait_capture(char *iface);

int gui_add_packet(struct pkt_summary *, struct pkt_analytree *, 
		unsigned char *data);

#endif /* __GTKUI_H__ */

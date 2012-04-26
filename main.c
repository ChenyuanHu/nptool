#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <pcap.h>

#include "gtk/gtkui.h"
#include "adapter.h"
#include "analyser.h"
#include "cvrttime.h"

#define FLITER_STR_MAX_SIZE	200
#define SNAPLEN		10000
//#define SNAPLEN		64
#define IS_PROMISC	1
#define WAITMS		0

static pthread_t guipid;
static pthread_t cappid;
static pcap_t *pd;
static pcap_if_t *if_list;

static void capture_loop()
{
	struct pcap_pkthdr *head;
	const u_char *data;
	u_char *data2;
	static int count = 0;
	int ret;

	struct pkt_summary *summary = NULL;
	struct pkt_analytree *analytree = NULL;

	while(1) {
		if ((ret = pcap_next_ex(pd, &head, &data)) < 0) {
			if (ret == -2) /* pcap_breakloop() was called */
				break;
			fprintf(stderr, "pcap_next_ex err: %d\n", ret);
			exit(1);
		}
		count++;

		data2 = malloc(head->caplen);
		if (data2 == NULL) {
			perror("malloc return NULL");
			exit(1);
		}
		memcpy(data2, data, head->caplen);

		if (pkt_analyse(&summary, &analytree, data2, 
				head->caplen, head->len) != 0) {
			fprintf(stderr, "pkt_analyse err\n");
			exit(1);
		}

		summary->no = count;
		timeval_to_ascii(&head->ts, summary->time, STR_TIME_LEN);
		
		gui_add_packet(summary, analytree, data2);
	}
}

static void start_capture(char *ifname)
{
	char errbuf[PCAP_ERRBUF_SIZE];
//	char filter_exp[FLITER_STR_MAX_SIZE];
//	struct bpf_program filter;
//	bpf_u_int32 mask;
//	bpf_u_int32 net;

	if ((pd = pcap_open_live(ifname, SNAPLEN, IS_PROMISC, 
			WAITMS, errbuf)) == NULL) {
		fprintf(stderr, "pcap_open err %s, %s\n", ifname, errbuf);
		exit(1);
	}

	capture_loop();

	if (pd != NULL) {
		pcap_close(pd);
		pd = NULL;
	}
}

static struct interface_list* get_interface_list()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	struct interface_list *itfc_list, *pre, *p;

	if (pcap_findalldevs(&if_list, errbuf) != 0) {
		fprintf(stderr, "pcap_findalldev err: %s\n", errbuf);
	}
	itfc_list = NULL;
	pre = NULL;
	p = NULL;
	while (if_list) {
		if (itfc_list == NULL) {
			if ((itfc_list = malloc(sizeof(*itfc_list))) <= 0) {
				perror("malloc err");
				return NULL;
			}
			itfc_list->name = if_list->name;
			itfc_list->next = NULL;
			pre = itfc_list;
		} else {
			if ((p = malloc(sizeof(*itfc_list))) <= 0) {
				perror("malloc err");
				return NULL;
			}
			p->name = if_list->name;
			p->next = NULL;
			pre->next = p;
			pre = p;
		}
		if_list = if_list->next;
	}
	return itfc_list;
}

static void exit_fun()
{
	exit(1);
}
static void stop_fun()
{
	pthread_kill(cappid, SIGUSR1);
	if (pd != NULL) {
		pcap_breakloop(pd);
		pd = NULL;
	}
}

static void idle_sig(int sig)
{
	return;
}
int main(int argc, char *argv[])
{
	struct interface_list *itfc_list;
	char iface[100];

	pd = NULL;

	gui_register_exit(&exit_fun);
	gui_register_stop(&stop_fun);

	itfc_list = get_interface_list();
	gui_set_interface_list(itfc_list);

	guipid = gui_pthread_start(&argc, &argv);

	cappid = pthread_self();

	signal(SIGUSR1, idle_sig);
	while (gui_wait_capture(iface) == 0) {
		start_capture(iface);
	}

	printf("exit\n");
	pcap_freealldevs(if_list);
	return 0;
}

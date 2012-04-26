#ifndef __ANALYSER_H__
#define __ANALYSER_H__

#include "adapter.h"
#include <sys/time.h>

int pkt_analyse(struct pkt_summary **summary, 
		struct pkt_analytree **analytree, 
		const unsigned char *data, unsigned int caplen, unsigned int len);

#endif /* __ANALYSER_H__ */

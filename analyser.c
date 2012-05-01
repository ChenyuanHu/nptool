#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>

#include "analyser.h"
#include "proto_headers.h"

static void free_analytree(struct pkt_analytree *analytree)
{
	if (analytree == NULL)
		return ;
	free_analytree(analytree->child);
	analytree->child = NULL;
	free_analytree(analytree->next);
	analytree->next = NULL;
	free(analytree);
}
static int tcp_dump(struct pkt_summary *summ, struct pkt_analytree **analytree,
		const unsigned char *data, unsigned int size)
{
	struct pkt_analytree *atree;
	struct pkt_analytree *child;
	struct npt_tcp_hdr *hdr;
	uint16_t sport;       /* source port */
	uint16_t dport;       /* destination port */
	uint32_t seq;
	uint32_t ack;
	uint16_t hdr_len;
	uint8_t tcp_flags;
	uint16_t win;         /* window */
	uint16_t sum;         /* checksum */
	uint16_t urp;         /* urgent pointer */

	int ret;
	ret = 0;

	if ((atree = malloc(sizeof(*atree))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		*analytree = NULL;
		return -1;
	}
	bzero(atree, sizeof(*atree));

	hdr = (struct npt_tcp_hdr *)data;

	sport = ntohs(hdr->th_sport);
	dport = ntohs(hdr->th_dport);
	seq = ntohl(hdr->th_seq);
	ack = ntohl(hdr->th_ack);
	hdr_len = hdr->th_off;
	tcp_flags = hdr->th_flags;

	win = ntohs(hdr->th_win);
	sum = ntohs(hdr->th_sum);
	urp = ntohs(hdr->th_urp);

	if (size < NPT_TCP_H) 
		goto err;

	strncpy(atree->comment, "TCP protocol", STR_COMMENT_LEN);
	atree->next = NULL;
	if ((atree->child = malloc(sizeof(*atree))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = atree->child;
	snprintf(child->comment, STR_INFO_LEN, "Source port: %u", sport);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "Destination port: %u", dport);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "seq: %u", seq);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "ack: %u", ack);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "hdr length: %u", hdr_len);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "flag: 0x%u", tcp_flags);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "win: %u", win);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "sum: %u", sum);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "urp: %u", urp);
	child->child = NULL;
	child->next = NULL;

	snprintf(summ->proto, STR_PROTO_LEN, "tcp");

	ret = 0;
	
	*analytree = atree;
	return ret;	
err:
	free_analytree(atree);
	*analytree = NULL;
	return -1;

}
static int udp_dump(struct pkt_summary *summ, struct pkt_analytree **analytree,
		const unsigned char *data, unsigned int size)
{
	struct pkt_analytree *atree;
	struct pkt_analytree *child;
	struct npt_udp_hdr *hdr;
	uint16_t sport;       /* source port */
	uint16_t dport;       /* destination port */
	uint16_t ulen;        /* length */
	uint16_t sum;         /* checksum */
	int ret;
	ret = 0;

	if ((atree = malloc(sizeof(*atree))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		*analytree = NULL;
		return -1;
	}
	bzero(atree, sizeof(*atree));

	hdr = (struct npt_udp_hdr *)data;

	sport = ntohs(hdr->uh_sport);
	dport = ntohs(hdr->uh_dport);
	ulen = ntohs(hdr->uh_ulen);
	sum = ntohs(hdr->uh_sum);

	if (size < NPT_UDP_H) 
		goto err;

	strncpy(atree->comment, "UDP protocol", STR_COMMENT_LEN);
	atree->next = NULL;
	if ((atree->child = malloc(sizeof(*atree))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = atree->child;
	snprintf(child->comment, STR_INFO_LEN, "Source port: %u", sport);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "Destination port: %u", dport);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "udp length: %u", ulen);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "check sum : 0x%x", sum);
	child->child = NULL;
	child->next = NULL;

	snprintf(summ->proto, STR_PROTO_LEN, "udp");

	ret = 0;
	
	*analytree = atree;
	return ret;	
err:
	free_analytree(atree);
	*analytree = NULL;
	return -1;

}
static int ip_dump(struct pkt_summary *summ, struct pkt_analytree **analytree,
		const unsigned char *data, unsigned int size)
{
	uint8_t proto;
	uint8_t ip_head_len;
	uint8_t ip_ver;
	uint16_t ip_len;
	struct pkt_analytree *atree;
	struct pkt_analytree *child;
	struct npt_ipv4_hdr *hdr;
	int ret;
	ret = 0;

	if ((atree = malloc(sizeof(*atree))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		*analytree = NULL;
		return -1;
	}
	bzero(atree, sizeof(*atree));

	hdr = (struct npt_ipv4_hdr *)data;

	ip_ver = hdr->ip_v;
	ip_head_len = (hdr->ip_hl) * 4;
	ip_len = ntohs(hdr->ip_len);
	proto = hdr->ip_p;

	if (size < ip_head_len) 
		goto err;
	if (ip_ver != 4) 
		goto err;

	strncpy(atree->comment, "IP protocol", STR_COMMENT_LEN);
	atree->next = NULL;
	if ((atree->child = malloc(sizeof(*atree))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = atree->child;
	snprintf(child->comment, STR_INFO_LEN, "Source IP: %u.%u.%u.%u",
			hdr->ip_src[0], hdr->ip_src[1], hdr->ip_src[2], hdr->ip_src[3]);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "Destination IP: %u.%u.%u.%u",
			hdr->ip_dst[0], hdr->ip_dst[1], hdr->ip_dst[2], hdr->ip_dst[3]);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "ip head length: %u", ip_head_len);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "ip length: %u", ip_len);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "ip version: %u", ip_ver);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "proto : 0x%x", proto);
	child->child = NULL;
	child->next = NULL;

	ret = -1;

	switch(proto) {
	case IP_PROTO_UDP:
		ret = udp_dump(summ, &(atree->next), data + NPT_IPV4_H, size - NPT_IPV4_H);
		break;
	case IP_PROTO_TCP:
		ret = tcp_dump(summ, &(atree->next), data + NPT_IPV4_H, size - NPT_IPV4_H);
		break;
	}
	snprintf(summ->dst, STR_DST_LEN, "%u.%u.%u.%u",
			hdr->ip_dst[0], hdr->ip_dst[1], hdr->ip_dst[2], hdr->ip_dst[3]);

	snprintf(summ->src, STR_SRC_LEN, "%u.%u.%u.%u",
			hdr->ip_src[0], hdr->ip_src[1], hdr->ip_src[2], hdr->ip_src[3]);

	if (hdr->ip_dst[0] == 0xff && hdr->ip_dst[1] == 0xff &&
			hdr->ip_dst[2] == 0xff && hdr->ip_dst[3] == 0xff) {
		snprintf(summ->info, STR_INFO_LEN, "%s broadcast", summ->src);
	} else {
		snprintf(summ->info, STR_INFO_LEN, "%s -> %s", summ->src, summ->dst);
	}
	if (ret != 0) {
		snprintf(summ->proto, STR_PROTO_LEN, "ip");
	}
	ret = 0;
	
	*analytree = atree;
	return ret;	
err:
	free_analytree(atree);
	*analytree = NULL;
	return -1;

}
static int ethernet_dump(struct pkt_summary *summ, struct pkt_analytree **analytree,
		const unsigned char *data, unsigned int size)
{
	uint16_t proto;
	struct pkt_analytree *atree;
	struct pkt_analytree *child;
	struct npt_ethernet_hdr *hdr;
	int ret;
	ret = 0;

	if ((atree = malloc(sizeof(*atree))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		*analytree = NULL;
		return -1;
	}
	bzero(atree, sizeof(*atree));

	if (size < NPT_ETH_H) 
		goto err;

	hdr = (struct npt_ethernet_hdr *)data;

	proto = ntohs(hdr->ether_type);

	strncpy(atree->comment, "ethernet protocol", STR_COMMENT_LEN);
	atree->next = NULL;
	if ((atree->child = malloc(sizeof(*atree))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = atree->child;
	snprintf(child->comment, STR_INFO_LEN, 
			"Source MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			hdr->ether_shost[0], hdr->ether_shost[1], 
			hdr->ether_shost[2], hdr->ether_shost[3], 
			hdr->ether_shost[4], hdr->ether_shost[5]
			);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, 
			"Destination MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			hdr->ether_dhost[0], hdr->ether_dhost[1], 
			hdr->ether_dhost[2], hdr->ether_dhost[3], 
			hdr->ether_dhost[4], hdr->ether_dhost[5]
			);
	child->child = NULL;
	if ((child->next = malloc(sizeof(*child))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		goto err;
	}
	child = child->next;
	snprintf(child->comment, STR_INFO_LEN, "type : 0x%x", proto);
	child->child = NULL;
	child->next = NULL;

	ret = -1;
	switch(proto) {
	case ETHERTYPE_IP:
		ret = ip_dump(summ, &(atree->next), data + NPT_ETH_H, size - NPT_ETH_H);
		break;
	}
	if (ret != 0) {
		snprintf(summ->dst, STR_DST_LEN, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
				hdr->ether_dhost[0], hdr->ether_dhost[1], 
				hdr->ether_dhost[2], hdr->ether_dhost[3], 
				hdr->ether_dhost[4], hdr->ether_dhost[5]);

		snprintf(summ->src, STR_SRC_LEN, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
				hdr->ether_shost[0], hdr->ether_shost[1], 
				hdr->ether_shost[2], hdr->ether_shost[3], 
				hdr->ether_shost[4], hdr->ether_shost[5]);

		snprintf(summ->proto, STR_PROTO_LEN, "ethernet");
		if (hdr->ether_dhost[0] == 0xff && hdr->ether_dhost[1] == 0xff &&
				hdr->ether_dhost[2] == 0xff && hdr->ether_dhost[3] == 0xff &&
				hdr->ether_dhost[4] == 0xff && hdr->ether_dhost[5] == 0xff) {
			snprintf(summ->info, STR_INFO_LEN, "%s broadcast", summ->src);
		} else {
			snprintf(summ->info, STR_INFO_LEN, "%s -> %s", 
					summ->src, summ->dst);
		}
	}
	ret = 0;
	
	*analytree = atree;
	return ret;	
err:
	free_analytree(atree);
	*analytree = NULL;
	return -1;

}

int pkt_analyse(struct pkt_summary **summary, struct pkt_analytree **analytree, 
		const unsigned char *data, unsigned int caplen, unsigned int len)
{
	struct pkt_summary *summ;
	struct pkt_analytree *atree;
	int ret;
	
	if ((summ = malloc(sizeof(*summ))) == NULL) {
		fprintf(stderr, "malloc err %s\n", __FUNCTION__);
		*analytree = NULL;
		return -1;
	}
	bzero(summ, sizeof(*summ));

	summ->len = len;
	summ->caplen = caplen;

	ret = ethernet_dump(summ, &atree, data, caplen);

	*summary = summ;
	*analytree = atree;
	return ret;
}

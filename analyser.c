#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>

#include "analyser.h"
#include "proto_headers.h"

#define UPDATE_DST 1
#define UPDATE_SRC 2
#define UPDATE_PRO 4
#define UPDATE_INFO 8

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

static int icmpv4_dump(struct pkt_summary *summ, struct pkt_analytree **analytree,
		const unsigned char *data, unsigned int size)
{
	struct pkt_analytree *atree;
	struct pkt_analytree *child;
	struct npt_icmpv4_hdr *hdr;

	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t ident;
	uint16_t seq_num;

	char *pchar;

	int ret;
	ret = 0;

	hdr = (struct npt_icmpv4_hdr *)data;

	type = hdr->icmp_type;
	code = hdr->icmp_code;
	checksum = ntohs(hdr->icmp_sum);
	ident = ntohs(hdr->hun.echo.id);
	seq_num = ntohs(hdr->hun.echo.seq);

	if (type == ICMP_ECHO)
		pchar = "Echo (ping) request";
	else if (type == ICMP_ECHOREPLY)
		pchar = "Echo (ping) reply";
	else
		pchar = "";

	if (size < NPT_ICMPV4_ECHO_H) 
		goto err;

	ANALY_TREE_ADD_PROTO(err, atree, "ICMP protocol");
	ANALY_TREE_ADD_FST_COMM(err, atree, child, "Type: %u (%s)", type, pchar);
	ANALY_TREE_ADD_COMM(err, child, "Code: %u", code);

	if (type == ICMP_ECHOREPLY || type == ICMP_ECHO) {
		ANALY_TREE_ADD_COMM(err, child, "Checksum: %u", checksum);
		ANALY_TREE_ADD_COMM(err, child, "Identifier: %u", ident);
		ANALY_TREE_ADD_COMM(err, child, "Sequence number: %u", seq_num);
	} else {
		ANALY_TREE_ADD_COMM(err, child, "Checksum: %u", checksum);
	}

	snprintf(summ->proto, STR_PROTO_LEN, "ICMP");

	snprintf(summ->info, STR_INFO_LEN, "%s", pchar);

	ret = UPDATE_PRO | UPDATE_INFO;
	
	*analytree = atree;
	return ret;	
err:
	free_analytree(atree);
	*analytree = NULL;
	return -1;

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

	ANALY_TREE_ADD_PROTO(err, atree, "TCP protocol");
	ANALY_TREE_ADD_FST_COMM(err, atree, child, "Source port: %u", sport);
	ANALY_TREE_ADD_COMM(err, child, "Destination port: %u", dport);
	ANALY_TREE_ADD_COMM(err, child, "seq: %u", seq);
	ANALY_TREE_ADD_COMM(err, child, "ack: %u", ack);
	ANALY_TREE_ADD_COMM(err, child, "hdr length: %u", hdr_len);
	ANALY_TREE_ADD_COMM(err, child, "flag: 0x%u", tcp_flags);
	ANALY_TREE_ADD_COMM(err, child, "win: %u", win);
	ANALY_TREE_ADD_COMM(err, child, "sum: %u", sum);
	ANALY_TREE_ADD_COMM(err, child, "urp: %u", urp);

	snprintf(summ->proto, STR_PROTO_LEN, "TCP");

	ret = UPDATE_PRO;
	
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

	hdr = (struct npt_udp_hdr *)data;

	sport = ntohs(hdr->uh_sport);
	dport = ntohs(hdr->uh_dport);
	ulen = ntohs(hdr->uh_ulen);
	sum = ntohs(hdr->uh_sum);

	if (size < NPT_UDP_H) 
		goto err;

	ANALY_TREE_ADD_PROTO(err, atree, "UDP protocol");
	ANALY_TREE_ADD_FST_COMM(err, atree, child, "Source port: %u", sport);
	ANALY_TREE_ADD_COMM(err, child, "Destination port: %u", dport);
	ANALY_TREE_ADD_COMM(err, child, "udp length: %u", ulen);
	ANALY_TREE_ADD_COMM(err, child, "check sum : 0x%x", sum);

	snprintf(summ->proto, STR_PROTO_LEN, "UDP");

	ret = UPDATE_PRO;
	
	*analytree = atree;
	return ret;	
err:
	free_analytree(atree);
	*analytree = NULL;
	return -1;
}
static int arp_dump(struct pkt_summary *summ, struct pkt_analytree **analytree,
		const unsigned char *data, unsigned int size)
{
	struct pkt_analytree *atree;
	struct pkt_analytree *child;
	struct npt_arp_hdr *hdr;


	uint16_t hrd;         /* format of hardware address */
	uint16_t pro;         /* format of protocol address */
	uint8_t  hln;         /* length of hardware address */
	uint8_t  pln;         /* length of protocol address */
	uint16_t op;          /* operation type */

	char *htype;
	char *optype;
	int ret;
	ret = 0;

	hdr = (struct npt_arp_hdr *)data;

	if (size < NPT_ARP_H) 
		goto err;

	hrd = ntohs(hdr->ar_hrd);
	pro = ntohs(hdr->ar_pro);
	hln = hdr->ar_hln;
	pln = hdr->ar_pln;
	op = ntohs(hdr->ar_op);

	switch (hrd) {
	case ARPHRD_NETROM:
		htype = "from KA9Q: NET/ROM pseudo";
		break;
	case ARPHRD_ETHER:
		htype = "Ethernet 10Mbps";
		break;
	case ARPHRD_EETHER:
		htype = "Experimental Ethernet";
		break;
	case ARPHRD_AX25:
		htype = "AX.25 Level 2";
		break;
	case ARPHRD_PRONET:
		htype = "PROnet token ring";
		break;
	case ARPHRD_CHAOS:
		htype = "Chaosnet";
		break;
	case ARPHRD_IEEE802:
		htype = "IEEE 802.2 Ethernet/TR/TB";
		break;
	case ARPHRD_ARCNET:
		htype = "ARCnet";
		break;
	case ARPHRD_APPLETLK:
		htype = "APPLEtalk";
		break;
	case ARPHRD_LANSTAR:
		htype = "Lanstar";
		break;
	case ARPHRD_DLCI:
		htype = "Frame Relay DLCI";
		break;
	case ARPHRD_ATM:
		htype = "ATM";
		break;
	case ARPHRD_METRICOM:
		htype = "Metricom STRIP (new IANA id)";
		break;
	case ARPHRD_IPSEC:
		htype = "IPsec tunnel";
		break;
	}
	switch (op) {
	case ARPOP_REQUEST:
		optype = "req to resolve address";
		break;
	case ARPOP_REPLY:
		optype = "resp to previous request";
		break;
	case ARPOP_REVREQUEST:
		optype = "req protocol address given hardware";
		break;
	case ARPOP_REVREPLY:
		optype = "resp giving protocol address";
		break;
	case ARPOP_INVREQUEST:
		optype = "req to identify peer";
		break;
	case ARPOP_INVREPLY:
		optype = "resp identifying peer";
		break;
	}

	ANALY_TREE_ADD_PROTO(err, atree, "ARP protocol");
	ANALY_TREE_ADD_FST_COMM(err, atree, child, "Hardware type: %s", htype);
	ANALY_TREE_ADD_COMM(err, child, "Protocol type: 0x%x", pro);
	ANALY_TREE_ADD_COMM(err, child, "Hardware address length: %u", hln);
	ANALY_TREE_ADD_COMM(err, child, "Protocol address length: %u", pln);
	if (pln == 4 && hln == 6 && pro == ETHERTYPE_IP && hrd == ARPHRD_ETHER) {
		ANALY_TREE_ADD_COMM(err, child, "Operation Type : %s", optype);
		ANALY_TREE_ADD_COMM(err, child, "Sender MAC address:"
				" %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
				data[NPT_ARP_H + 0], data[NPT_ARP_H + 1], data[NPT_ARP_H + 2],
				data[NPT_ARP_H + 3], data[NPT_ARP_H + 4], data[NPT_ARP_H + 5]);
		ANALY_TREE_ADD_COMM(err, child, "Sender IP address: %u.%u.%u.%u",
				data[NPT_ARP_H + 6], data[NPT_ARP_H + 7],
				data[NPT_ARP_H + 8], data[NPT_ARP_H + 9]);
		ANALY_TREE_ADD_COMM(err, child, "Target MAC address:"
				" %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
				data[NPT_ARP_H + 10], data[NPT_ARP_H + 11], data[NPT_ARP_H + 12],
				data[NPT_ARP_H + 13], data[NPT_ARP_H + 14], data[NPT_ARP_H + 15]);
		ANALY_TREE_ADD_COMM(err, child, "Target IP address: %u.%u.%u.%u",
				data[NPT_ARP_H + 16], data[NPT_ARP_H + 17],
				data[NPT_ARP_H + 18], data[NPT_ARP_H + 19]);

		snprintf(summ->info, STR_INFO_LEN, "Who has %u.%u.%u.%u? Tell %u.%u.%u.%u",
				data[NPT_ARP_H + 16], data[NPT_ARP_H + 17],
				data[NPT_ARP_H + 18], data[NPT_ARP_H + 19],
				data[NPT_ARP_H + 6], data[NPT_ARP_H + 7],
				data[NPT_ARP_H + 8], data[NPT_ARP_H + 9]);
		ret = UPDATE_INFO;
	} else {
		ANALY_TREE_ADD_COMM(err, child, "Operation Type : %s", optype);
	}

	snprintf(summ->proto, STR_PROTO_LEN, "ARP");

	ret = ret | UPDATE_PRO;
	
	*analytree = atree;
	return ret;	
err:
	free_analytree(atree);
	*analytree = NULL;
	return -1;

}
static int ipv4_dump(struct pkt_summary *summ, struct pkt_analytree **analytree,
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

	hdr = (struct npt_ipv4_hdr *)data;

	ip_ver = hdr->ip_v;
	ip_head_len = (hdr->ip_hl) * 4;
	ip_len = ntohs(hdr->ip_len);
	proto = hdr->ip_p;

	if (size < ip_head_len) 
		goto err;
	if (ip_ver != 4) 
		goto err;

	ANALY_TREE_ADD_PROTO(err, atree, "IP protocol");
	ANALY_TREE_ADD_FST_COMM(err, atree, child, "Source IP: %u.%u.%u.%u",
			hdr->ip_src[0], hdr->ip_src[1], hdr->ip_src[2], hdr->ip_src[3]);
	ANALY_TREE_ADD_COMM(err, child, "Destination IP: %u.%u.%u.%u",
			hdr->ip_dst[0], hdr->ip_dst[1], hdr->ip_dst[2], hdr->ip_dst[3]);
	ANALY_TREE_ADD_COMM(err, child, "ip head length: %u", ip_head_len);
	ANALY_TREE_ADD_COMM(err, child, "ip length: %u", ip_len);
	ANALY_TREE_ADD_COMM(err, child, "ip version: %u", ip_ver);
	ANALY_TREE_ADD_COMM(err, child, "proto : 0x%x", proto);

	ret = -1;

	switch(proto) {
	case IP_PROTO_UDP:
		ret = udp_dump(summ, &(atree->next), data + NPT_IPV4_H, size - NPT_IPV4_H);
		break;
	case IP_PROTO_TCP:
		ret = tcp_dump(summ, &(atree->next), data + NPT_IPV4_H, size - NPT_IPV4_H);
		break;
	case IP_PROTO_ICMPV4:
		ret = icmpv4_dump(summ, &(atree->next), data + NPT_IPV4_H, size - NPT_IPV4_H);
		break;
	}

	if (ret < 0 || ((ret & UPDATE_DST) != UPDATE_DST))
		snprintf(summ->dst, STR_DST_LEN, "%u.%u.%u.%u",
				hdr->ip_dst[0], hdr->ip_dst[1], hdr->ip_dst[2], hdr->ip_dst[3]);

	if (ret < 0 || ((ret & UPDATE_SRC) != UPDATE_SRC))
		snprintf(summ->src, STR_SRC_LEN, "%u.%u.%u.%u",
				hdr->ip_src[0], hdr->ip_src[1], hdr->ip_src[2], hdr->ip_src[3]);

	if (ret < 0 || ((ret & UPDATE_INFO) != UPDATE_INFO)) {
		if (hdr->ip_dst[0] == 0xff && hdr->ip_dst[1] == 0xff &&
				hdr->ip_dst[2] == 0xff && hdr->ip_dst[3] == 0xff) {
			snprintf(summ->info, STR_INFO_LEN, "%s broadcast", summ->src);
		} else {
			snprintf(summ->info, STR_INFO_LEN, "%s -> %s", summ->src, summ->dst);
		}
	}
	if (ret < 0 || ((ret & UPDATE_PRO) != UPDATE_PRO))
		snprintf(summ->proto, STR_PROTO_LEN, "IP");

	ret = UPDATE_DST | UPDATE_SRC | UPDATE_INFO | UPDATE_PRO;
	
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

	if (size < NPT_ETH_H) 
		goto err;

	hdr = (struct npt_ethernet_hdr *)data;

	proto = ntohs(hdr->ether_type);

	ANALY_TREE_ADD_PROTO(err, atree, "ethernet protocol");
	ANALY_TREE_ADD_FST_COMM(err, atree, child,
			"Source MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			hdr->ether_shost[0], hdr->ether_shost[1], 
			hdr->ether_shost[2], hdr->ether_shost[3], 
			hdr->ether_shost[4], hdr->ether_shost[5]
			);
	ANALY_TREE_ADD_COMM(err, child, 
			"Destination MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			hdr->ether_dhost[0], hdr->ether_dhost[1], 
			hdr->ether_dhost[2], hdr->ether_dhost[3], 
			hdr->ether_dhost[4], hdr->ether_dhost[5]
			);
	ANALY_TREE_ADD_COMM(err, child, "type : 0x%x", proto);

	ret = -1;
	switch(proto) {
	case ETHERTYPE_IP:
		ret = ipv4_dump(summ, &(atree->next), data + NPT_ETH_H, size - NPT_ETH_H);
		break;
	case ETHERTYPE_ARP:
		ret = arp_dump(summ, &(atree->next), data + NPT_ETH_H, size - NPT_ETH_H);
		break;
	}

	if (ret < 0 || ((ret & UPDATE_DST) != UPDATE_DST)) {
		if (hdr->ether_dhost[0] == 0xff && hdr->ether_dhost[1] == 0xff &&
				hdr->ether_dhost[2] == 0xff && hdr->ether_dhost[3] == 0xff &&
				hdr->ether_dhost[4] == 0xff && hdr->ether_dhost[5] == 0xff) {
			snprintf(summ->dst, STR_DST_LEN, "Broadcast");
		} else {
			snprintf(summ->dst, STR_DST_LEN, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
					hdr->ether_dhost[0], hdr->ether_dhost[1], 
					hdr->ether_dhost[2], hdr->ether_dhost[3], 
					hdr->ether_dhost[4], hdr->ether_dhost[5]);
		}
	}

	if (ret < 0 || ((ret & UPDATE_SRC) != UPDATE_SRC))
		snprintf(summ->src, STR_SRC_LEN, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
				hdr->ether_shost[0], hdr->ether_shost[1], 
				hdr->ether_shost[2], hdr->ether_shost[3], 
				hdr->ether_shost[4], hdr->ether_shost[5]);

	if (ret < 0 || ((ret & UPDATE_PRO) != UPDATE_PRO))
		snprintf(summ->proto, STR_PROTO_LEN, "ETHERNET");

	if (ret < 0 || ((ret & UPDATE_INFO) != UPDATE_INFO)) {
		if (hdr->ether_dhost[0] == 0xff && hdr->ether_dhost[1] == 0xff &&
				hdr->ether_dhost[2] == 0xff && hdr->ether_dhost[3] == 0xff &&
				hdr->ether_dhost[4] == 0xff && hdr->ether_dhost[5] == 0xff) {
			snprintf(summ->info, STR_INFO_LEN, "%s broadcast", summ->src);
		} else {
			snprintf(summ->info, STR_INFO_LEN, "%s -> %s", 
					summ->src, summ->dst);
		}
	}
	ret = UPDATE_DST | UPDATE_SRC | UPDATE_INFO | UPDATE_PRO;
	
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
	if (ret > 0)
		ret = 0;

	*summary = summ;
	*analytree = atree;
	return ret;
}

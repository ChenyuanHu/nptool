#ifndef __ADAPTER_H__
#define __ADAPTER_H__

#define STR_TIME_LEN	50
#define STR_DST_LEN		50
#define STR_SRC_LEN		50
#define STR_PROTO_LEN	10
#define STR_INFO_LEN	200

#define STR_COMMENT_LEN	300

struct pkt_summary {
	int no;
	char time[STR_TIME_LEN];
	char dst[STR_DST_LEN];
	char src[STR_SRC_LEN];
	char proto[STR_PROTO_LEN];
	int len;
	int caplen;
	char info[STR_INFO_LEN];
};
struct pkt_analytree {
	char comment[STR_COMMENT_LEN];
	struct pkt_analytree *child;
	struct pkt_analytree *next;
};

#endif /* __ADAPTER_H__ */

#ifndef __ADAPTER_H__
#define __ADAPTER_H__

#define STR_TIME_LEN	50
#define STR_DST_LEN		50
#define STR_SRC_LEN		50
#define STR_PROTO_LEN	10
#define STR_INFO_LEN	200

#define STR_COMMENT_LEN	300

#include <stdlib.h>
#include <stdio.h>

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

#ifdef ERROUT
#error ERR_OUT defined
#endif
#define ERR_OUT fprintf

/* ANALY_TREE_ADD_PROTO_LEV(struct pkt_analytree atree, child, comm, goto err)*/
#define ANALY_TREE_ADD_PROTO(err, atree, comm...) do { \
	atree = NULL; \
	if ((atree = malloc(sizeof(struct pkt_analytree))) == NULL) { \
		ERR_OUT(stderr, "malloc err %s\n", __FUNCTION__); \
		goto err; \
	} \
	snprintf(atree->comment, STR_COMMENT_LEN, ##comm); \
	atree->next = NULL; \
	atree->child = NULL; \
	} while(0)

#define ANALY_TREE_ADD_FST_COMM(err, atree, child, comm...) do { \
	if ((atree->child = malloc(sizeof(struct pkt_analytree))) == NULL) { \
		ERR_OUT(stderr, "malloc err %s\n", __FUNCTION__); \
		goto err; \
	} \
	child = atree->child; \
	snprintf(child->comment, STR_COMMENT_LEN, ##comm); \
	child->child = NULL; \
	child->next = NULL; \
	}while(0) 

#define ANALY_TREE_ADD_COMM(err, child, comm...) do { \
	if ((child->next = malloc(sizeof(struct pkt_analytree))) == NULL) { \
		fprintf(stderr, "malloc err %s\n", __FUNCTION__); \
		goto err; \
	} \
	child = child->next; \
	snprintf(child->comment, STR_COMMENT_LEN, ##comm); \
	child->child = NULL; \
	child->next = NULL; \
	}while(0)

#endif /* __ADAPTER_H__ */

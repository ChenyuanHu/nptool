#ifndef __PROTO_HEADERS_H__
#define __PROTO_HEADERS_H__

#include <stdint.h>

#define NPT_LIL_ENDIAN 1
#undef NPT_BIG_ENDIAN

/*
 * Nptool defines header sizes.
 */
#define NPT_ARP_H            0x08    /**< ARP header w/o addrs: 8 bytes */
#define NPT_ARP_ETH_IP_H     0x1c    /**< ARP w/ ETH and IP:   28 bytes */
#define NPT_DHCPV4_H         0xf0    /**< DHCP v4 header:     240 bytes */
#define NPT_UDP_DNSV4_H      0x0c    /**< UDP DNS v4 header:   12 bytes */
#define NPT_TCP_DNSV4_H      0x0e    /**< TCP DNS v4 header:   14 bytes */
#define NPT_ETH_H            0x0e    /**< Ethernet header:     14 bytes */
#define NPT_ICMPV4_H         0x04    /**< ICMP header base:     4 bytes */
#define NPT_ICMPV4_ECHO_H    0x08    /**< ICMP_ECHO header:     8 bytes */
#define NPT_ICMPV4_MASK_H    0x0c    /**< ICMP_MASK header:    12 bytes */
#define NPT_ICMPV4_UNREACH_H  0x08   /**< ICMP_UNREACH header:  8 bytes */
#define NPT_ICMPV4_TIMXCEED_H 0x08   /**< ICMP_TIMXCEED header: 8 bytes */
#define NPT_ICMPV4_REDIRECT_H 0x08   /**< ICMP_REDIRECT header: 8 bytes */
#define NPT_ICMPV4_TS_H      0x14    /**< ICMP_TIMESTAMP headr:20 bytes */
#define NPT_ICMPV6_H         0x08    /**< ICMP6 header base:    8 bytes */
#define NPT_ICMPV6_UNREACH_H 0x08    /**< ICMP6 unreach base:   8 bytes */
#define NPT_IGMP_H           0x08    /**< IGMP header:          8 bytes */
#define NPT_IPV4_H           0x14    /**< IPv4 header:         20 bytes */
#define NPT_IPV6_H           0x28    /**< IPv6 header:         40 bytes */
#define NPT_IPV6_FRAG_H      0x08    /**< IPv6 frag header:     8 bytes */
#define NPT_IPV6_ROUTING_H   0x04    /**< IPv6 frag header base:4 bytes */
#define NPT_IPV6_DESTOPTS_H  0x02    /**< IPv6 dest opts base:  2 bytes */
#define NPT_IPV6_HBHOPTS_H   0x02    /**< IPv6 hop/hop opt base:2 bytes */
#define NPT_IPSEC_ESP_HDR_H  0x0c    /**< IPSEC ESP header:    12 bytes */
#define NPT_IPSEC_ESP_FTR_H  0x02    /**< IPSEC ESP footer:     2 bytes */
#define NPT_IPSEC_AH_H       0x10    /**< IPSEC AH header:     16 bytes */
#define NPT_RPC_CALL_H       0x28    /**< RPC header:          40 bytes
                                         * (assuming 8 byte auth header)
                                         */
#define NPT_RPC_CALL_TCP_H   0x2c    /**< RPC header:          44 bytes
                                         * (with record marking)
                                         */
#define NPT_TCP_H            0x14    /**< TCP header:          20 bytes */
#define NPT_UDP_H            0x08    /**< UDP header:           8 bytes */

/* ethernet addresses are 6 octets long */
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN      0x6
#endif

/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
struct npt_ethernet_hdr
{
    uint8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    uint16_t ether_type;                 /* protocol */
};

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP           0x0806  /* addr. resolution protocol */
#endif
#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP        0x8035  /* reverse addr. resolution protocol */
#endif

/* 
 *  ARP header
 *  Address Resolution Protocol
 *  Base header size: 8 bytes
 */
struct npt_arp_hdr
{
    uint16_t ar_hrd;         /* format of hardware address */
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
    uint16_t ar_pro;         /* format of protocol address */
    uint8_t  ar_hln;         /* length of hardware address */
    uint8_t  ar_pln;         /* length of protocol addres */
    uint16_t ar_op;          /* operation type */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
    /* address information allocated dynamically */
};

#ifndef IPV4_ADDR_LEN
#define IPV4_ADDR_LEN 4
#endif
/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
struct npt_ipv4_hdr
{
#if (NPT_LIL_ENDIAN)
    uint8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (NPT_BIG_ENDIAN)
    uint8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    uint8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    uint16_t ip_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    uint8_t ip_ttl;          /* time to live */
    uint8_t ip_p;            /* protocol */
#ifndef IP_PROTO_UDP
#define IP_PROTO_UDP 0x11
#endif
#ifndef IP_PROTO_TCP
#define IP_PROTO_TCP 0x06
#endif
#ifndef IP_PROTO_ICMPV4
#define IP_PROTO_ICMPV4 0x01
#endif
    uint16_t ip_sum;         /* checksum */
    uint8_t ip_src[IPV4_ADDR_LEN]; 
	uint8_t ip_dst[IPV4_ADDR_LEN]; /* source and dest address */
};

/*
 *  IP options
 */
#ifndef IPOPT_EOL
#define IPOPT_EOL       0   /* end of option list */
#endif
#ifndef IPOPT_NOP
#define IPOPT_NOP       1   /* no operation */
#endif   
#ifndef IPOPT_RR
#define IPOPT_RR        7   /* record packet route */
#endif
#ifndef IPOPT_TS
#define IPOPT_TS        68  /* timestamp */
#endif
#ifndef IPOPT_SECURITY
#define IPOPT_SECURITY  130 /* provide s,c,h,tcc */   
#endif
#ifndef IPOPT_LSRR
#define IPOPT_LSRR      131 /* loose source route */
#endif
#ifndef IPOPT_SATID
#define IPOPT_SATID     136 /* satnet id */
#endif
#ifndef IPOPT_SSRR
#define IPOPT_SSRR      137 /* strict source route */
#endif

/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct npt_tcp_hdr
{
    uint16_t th_sport;       /* source port */
    uint16_t th_dport;       /* destination port */
    uint32_t th_seq;          /* sequence number */
    uint32_t th_ack;          /* acknowledgement number */
#if (NPT_LIL_ENDIAN)
    uint8_t  th_x2:4,         /* (unused) */
             th_off:4;        /* data offset */
#endif
#if (NPT_BIG_ENDIAN)
    uint8_t  th_off:4,        /* data offset */
             th_x2:4;         /* (unused) */
#endif
    uint8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    uint16_t th_win;         /* window */
    uint16_t th_sum;         /* checksum */
    uint16_t th_urp;         /* urgent pointer */
};

/*
 *  UDP header
 *  User Data Protocol
 *  Static header size: 8 bytes
 */
struct npt_udp_hdr
{
    uint16_t uh_sport;       /* source port */
    uint16_t uh_dport;       /* destination port */
    uint16_t uh_ulen;        /* length */
    uint16_t uh_sum;         /* checksum */
};


/*
 *  ICMP header
 *  Internet Control Message Protocol
 *  Base header size: 4 bytes
 */
struct npt_icmpv4_hdr
{
    uint8_t icmp_type;       /* ICMP type */
#ifndef     ICMP_ECHOREPLY
#define     ICMP_ECHOREPLY                  0
#endif
#ifndef     ICMP_UNREACH
#define     ICMP_UNREACH                    3
#endif
#ifndef     ICMP_SOURCEQUENCH
#define     ICMP_SOURCEQUENCH               4
#endif
#ifndef     ICMP_REDIRECT
#define     ICMP_REDIRECT                   5
#endif
#ifndef     ICMP_ECHO
#define     ICMP_ECHO                       8
#endif
#ifndef     ICMP_ROUTERADVERT
#define     ICMP_ROUTERADVERT               9
#endif
#ifndef     ICMP_ROUTERSOLICIT
#define     ICMP_ROUTERSOLICIT              10
#endif
#ifndef     ICMP_TIMXCEED
#define     ICMP_TIMXCEED                   11
#endif
#ifndef     ICMP_PARAMPROB
#define     ICMP_PARAMPROB                  12
#endif
#ifndef     ICMP_TSTAMP
#define     ICMP_TSTAMP                     13
#endif
#ifndef     ICMP_TSTAMPREPLY
#define     ICMP_TSTAMPREPLY                14
#endif
#ifndef     ICMP_IREQ
#define     ICMP_IREQ                       15
#endif
#ifndef     ICMP_IREQREPLY
#define     ICMP_IREQREPLY                  16
#endif
#ifndef     ICMP_MASKREQ
#define     ICMP_MASKREQ                    17
#endif
#ifndef     ICMP_MASKREPLY
#define     ICMP_MASKREPLY                  18
#endif
    uint8_t icmp_code;       /* ICMP code */
#ifndef     ICMP_UNREACH_NET
#define     ICMP_UNREACH_NET                0
#endif
#ifndef     ICMP_UNREACH_HOST
#define     ICMP_UNREACH_HOST               1
#endif
#ifndef     ICMP_UNREACH_PROTOCOL
#define     ICMP_UNREACH_PROTOCOL           2
#endif
#ifndef     ICMP_UNREACH_PORT
#define     ICMP_UNREACH_PORT               3
#endif
#ifndef     ICMP_UNREACH_NEEDFRAG
#define     ICMP_UNREACH_NEEDFRAG           4
#endif
#ifndef     ICMP_UNREACH_SRCFAIL
#define     ICMP_UNREACH_SRCFAIL            5
#endif
#ifndef     ICMP_UNREACH_NET_UNKNOWN
#define     ICMP_UNREACH_NET_UNKNOWN        6
#endif
#ifndef     ICMP_UNREACH_HOST_UNKNOWN
#define     ICMP_UNREACH_HOST_UNKNOWN       7
#endif
#ifndef     ICMP_UNREACH_ISOLATED
#define     ICMP_UNREACH_ISOLATED           8
#endif
#ifndef     ICMP_UNREACH_NET_PROHIB
#define     ICMP_UNREACH_NET_PROHIB         9
#endif
#ifndef     ICMP_UNREACH_HOST_PROHIB
#define     ICMP_UNREACH_HOST_PROHIB        10
#endif
#ifndef     ICMP_UNREACH_TOSNET
#define     ICMP_UNREACH_TOSNET             11
#endif
#ifndef     ICMP_UNREACH_TOSHOST
#define     ICMP_UNREACH_TOSHOST            12
#endif
#ifndef     ICMP_UNREACH_FILTER_PROHIB
#define     ICMP_UNREACH_FILTER_PROHIB      13
#endif
#ifndef     ICMP_UNREACH_HOST_PRECEDENCE
#define     ICMP_UNREACH_HOST_PRECEDENCE    14
#endif
#ifndef     ICMP_UNREACH_PRECEDENCE_CUTOFF
#define     ICMP_UNREACH_PRECEDENCE_CUTOFF  15
#endif
#ifndef     ICMP_REDIRECT_NET
#define     ICMP_REDIRECT_NET               0
#endif
#ifndef     ICMP_REDIRECT_HOST
#define     ICMP_REDIRECT_HOST              1
#endif
#ifndef     ICMP_REDIRECT_TOSNET
#define     ICMP_REDIRECT_TOSNET            2
#endif
#ifndef     ICMP_REDIRECT_TOSHOST
#define     ICMP_REDIRECT_TOSHOST           3
#endif
#ifndef     ICMP_TIMXCEED_INTRANS
#define     ICMP_TIMXCEED_INTRANS           0
#endif
#ifndef     ICMP_TIMXCEED_REASS
#define     ICMP_TIMXCEED_REASS             1
#endif
#ifndef     ICMP_PARAMPROB_OPTABSENT
#define     ICMP_PARAMPROB_OPTABSENT        1
#endif

    uint16_t icmp_sum;   /* ICMP Checksum */

    union
    {
        struct
        {
            uint16_t id; /* ICMP id */
            uint16_t seq;/* ICMP sequence number */
        } echo;

#undef icmp_id
#undef icmp_seq
#define icmp_id     hun.echo.id
#define icmp_seq    hun.echo.seq
 
        uint32_t gateway; /* gateway host */
        struct
        {
            uint16_t pad;/* padding */
            uint16_t mtu;/* MTU size */
        } frag;
    } hun;
    union
    {
        struct
        {
            uint32_t its_otime;
            uint32_t its_rtime;
            uint32_t its_ttime;
        } ts;
        struct
        {
            struct npt_ipv4_hdr idi_ip;
            /* options and then 64 bits of data */
        } ip;
        uint32_t mask;
        int8_t data[1];

#undef icmp_mask
#define icmp_mask    dun.mask
#undef icmp_data
#define icmp_data    dun.data

#undef icmp_otime
#define icmp_otime   dun.ts.its_otime
#undef icmp_rtime
#define icmp_rtime   dun.ts.its_rtime
#undef icmp_ttime
#define icmp_ttime   dun.ts.its_ttime
    }dun;
};

#endif /* __PROTO_HEADERS_H__ */

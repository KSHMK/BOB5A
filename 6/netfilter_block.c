#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <errno.h>

void failed(char* str)
{
	printf("Error: %s\n",str);
	exit(-1);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *vdata)
{
	int id = 0;
	int len, ret;
	struct nfqnl_msg_packet_hdr *ph;
	struct ip *iph;
	struct tcphdr *tcph;
	unsigned char* data;

	if((ph = nfq_get_msg_packet_hdr(nfa)))
	{
		id = ntohl(ph->packet_id);
		printf("hw_proto=0x%04x id=%u ",ntohs(ph->hw_protocol),id);
	}
	
	ret = nfq_get_payload(nfa,&data);
	if(ret >= 0)
	{
		iph = (struct ip*)data;
		if(iph->ip_p == 0x06)
		{
			tcph = (struct tcphdr*)&data[iph->ip_hl*4];
			len = ntohs(iph->ip_len)
				- (iph->ip_hl*4)
				- (tcph->th_off*4);
			if(len > 0)
			{
				if(strstr(&data[(iph->ip_hl*4)+(tcph->th_off*4)],"Host: www.sex.com")
						!= NULL)
				{
					printf("packet DENIED\n");
					return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
				}
			}
		}
	}

	printf("packet ACCEPTED\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(void)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("Open library\n");
	if(!(h = nfq_open()))
		failed("ntq_open");
	printf("unbinding AF_INET\n");
	if(nfq_unbind_pf(h,AF_INET)<0)
		failed("nfq_unbind_pf");
	printf("binding AF_INET\n");
	if(nfq_bind_pf(h,AF_INET)<0)
		failed("nfq_bind_pf");
	printf("binding socket to queue 0\n");
	if(!(qh  = nfq_create_queue(h, 0, &cb, NULL)))
		failed("nfq_create_queue");
	printf("setting copy packet mode\n");
	if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
		failed("nfq_set_mode");

	fd = nfq_fd(h);

	while(1)
	{
		if((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
		{
			printf("Recved\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		if(rv < 0 && errno == ENOBUFS)
		{
			printf("Losing packet\n");
			continue;
		}
		perror("recv failed");
		break;
	}
	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

	printf("closing library handle\n");
	nfq_close(h);
	return 0;
}


#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <cstdio>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#define MACSIZE 6
#define TCP 6
#define HTTP 80
#define HTTPS 443

#pragma pack(push, 1)
struct TcpPacket final
{
    EthHdr eth_;
    IpHdr ip_;
    TcpHdr tcp_;
    char tcpData[256];
};
struct Packet final
{
    EthHdr eth_;
    IpHdr ip_;
    TcpHdr tcp_;
    char tcpData[56];
};
#pragma pack(pop)

void usage() {
    printf("syntax : ./tcp-block <interface> <pattern>\n");
    printf("sample : ./tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

char *strnstr(const char *big, const char *little, size_t len)
{
        size_t llen;
        size_t blen;
        size_t i;

        if (!*little)
                return ((char *)big);
        llen = strlen(little);
        blen = strlen(big);
        i = 0;
        if (blen < llen || len < llen)
                return (0);
        while (i + llen <= len)
        {
                if (big[i] == *little && !strncmp(big + i, little, llen))
                        return ((char *)big + i);
                i++;
        }
        return (0);
}

Mac getMyMac(char* dev) {
   uint8_t myMac[MACSIZE];
   struct ifreq ifr;
   int sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if(sockfd < 0) {
      printf("socket error\n");
      exit(1);
   }
   strcpy(ifr.ifr_name, dev);
   if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
      printf("ioctl error\n");
      exit(1);
   }
   memcpy(myMac, ifr.ifr_hwaddr.sa_data, sizeof(myMac));
   close(sockfd);
   return Mac(myMac);
}

void forRST(pcap_t *handle, TcpPacket *packet, pcap_pkthdr *header, Mac myMac){
    TcpPacket *orgpkt = (TcpPacket*)malloc(header->caplen);
    memcpy(orgpkt, packet, header->caplen);
    int dataSize = (orgpkt->ip_.len()) - (orgpkt->ip_.hl()<<2) - (orgpkt->tcp_.off()<<2);
    orgpkt->eth_.smac_ = myMac;
    orgpkt->ip_.len_ = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    orgpkt->ip_.sum_ = htons(IpHdr::calcChecksum(&(orgpkt->ip_)));
    orgpkt->tcp_.seq_ = htonl(orgpkt->tcp_.seq() + dataSize);
    orgpkt->tcp_.off_rsvd_ = (sizeof(TcpHdr)/4)<<4;
    orgpkt->tcp_.flags_ = 0x14;
    orgpkt->tcp_.sum_ = htons(TcpHdr::calcChecksum(&(orgpkt->ip_), &(orgpkt->tcp_)));
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(orgpkt), header->caplen);
    if (res != 0){
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    else printf("Forward RST success\n");
    free(orgpkt);
}

void backFIN(pcap_t *handle, TcpPacket *packet, pcap_pkthdr *header, Mac myMac){
    char reDirect[56] = "HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
    Packet *orgpkt = (Packet*)malloc(header->caplen + strlen(reDirect));
    memcpy(orgpkt, packet, header->caplen);
    memcpy(orgpkt->tcpData,reDirect,sizeof(reDirect));
    int dataSize = (orgpkt->ip_.len()) - (orgpkt->ip_.hl()<<2) - (orgpkt->tcp_.off()<<2);
    orgpkt->eth_.smac_ = myMac;
    orgpkt->eth_.dmac_ = packet->eth_.smac_;
    orgpkt->ip_.len_ = htons(sizeof(IpHdr) + sizeof(TcpHdr) + strlen(reDirect));
    orgpkt->ip_.sum_ = htons(IpHdr::calcChecksum(&(orgpkt->ip_)));
    orgpkt->ip_.ttl_ = 128;
    orgpkt->ip_.sip_ = packet->ip_.dip_;
    orgpkt->ip_.dip_ = packet->ip_.sip_;

    orgpkt->tcp_.sport_ = packet->tcp_.dport_;
    orgpkt->tcp_.dport_ = packet->tcp_.sport_;
    orgpkt->tcp_.seq_ = packet->tcp_.ack_;
    orgpkt->tcp_.ack_ = htonl(orgpkt->tcp_.seq() + dataSize);
    orgpkt->tcp_.off_rsvd_ = (sizeof(TcpHdr)/4)<<4;
    orgpkt->tcp_.flags_ = 0x11;
    orgpkt->tcp_.sum_ = htons(TcpHdr::calcChecksum(&(orgpkt->ip_), &(orgpkt->tcp_)));
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(orgpkt), header->caplen + strlen(reDirect));
    if (res != 0){
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    else printf("Backward FIN success\n");
    free(orgpkt);
}
void backRST(pcap_t *handle, TcpPacket *packet, pcap_pkthdr *header, Mac myMac){
    TcpPacket *orgpkt = (TcpPacket*)malloc(header->caplen);
    memcpy(orgpkt, packet, header->caplen);
    int dataSize = (orgpkt->ip_.len()) - (orgpkt->ip_.hl()<<2) - (orgpkt->tcp_.off()<<2);
    orgpkt->eth_.smac_ = myMac;
    orgpkt->eth_.dmac_ = packet->eth_.smac_;
    orgpkt->ip_.len_ = htons(orgpkt->ip_.hl()<<2 + orgpkt->tcp_.off()<<2);
    orgpkt->ip_.sum_ = htons(IpHdr::calcChecksum(&(orgpkt->ip_)));
    orgpkt->ip_.ttl_ = 128;
    orgpkt->ip_.sip_ = packet->ip_.dip_;
    orgpkt->ip_.dip_ = packet->ip_.sip_;
    orgpkt->tcp_.sport_ = packet->tcp_.dport_;
    orgpkt->tcp_.dport_ = packet->tcp_.sport_;
    orgpkt->tcp_.seq_ = packet->tcp_.ack_;
    orgpkt->tcp_.ack_ = htonl(orgpkt->tcp_.seq() + dataSize);
    orgpkt->tcp_.off_rsvd_ = (sizeof(TcpHdr)>>2)<<4;
    orgpkt->tcp_.flags_ = 0x14;
    orgpkt->tcp_.sum_ = htons(TcpHdr::calcChecksum(&(orgpkt->ip_), &(orgpkt->tcp_)));
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(orgpkt), header->caplen);
    if (res != 0){
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    else printf("Backward RST success\n");
    free(orgpkt);
}

int main(int argc, char* argv[]){
    if (argc != 3) {
                usage();
                return -1;
        }
    char* dev = argv[1];
    char* pattern = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr){
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    Mac myMac = getMyMac(dev);

    while(true){
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res==0){
            continue;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return -1;
        }
        TcpPacket* pkt = (TcpPacket*)packet;
        if(pkt->ip_.p_==TCP){
            int len = pkt->ip_.len();
            int ip_len = pkt->ip_.hl()<<2;
            int tcp_len = pkt->tcp_.off()<<2;
            int pay_len = len - ip_len - tcp_len;
            if(pay_len>0){
                if((strnstr(pkt->tcpData,pattern,pay_len))!= NULL){
                    if((pkt->tcp_.sport() == HTTP) || (pkt->tcp_.dport() == HTTP)){
                        forRST(handle,pkt,header,myMac);
                        backFIN(handle,pkt,header,myMac);
                    }
                    else if((pkt->tcp_.sport() == HTTPS) || (pkt->tcp_.dport() == HTTPS)){
                        forRST(handle,pkt,header,myMac);
                        backRST(handle,pkt,header,myMac);
                    }
                }
            }
        }
    }
    pcap_close(handle);
    return 0;
}

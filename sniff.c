#include <arpa/inet.h>
#include <ctype.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myheader.h"

#define ETHER_HDR_LEN 14

static void print_payload(const u_char *payload, int len) {
    if (len <= 0) {
        printf("   (No Application Data)\n");
        return;
    }

    printf("   Payload (%d bytes):\n   ----\n   ", len);
    for (int i = 0; i < len; ++i) {
        unsigned char c = payload[i];
        if (c == '\n') {
            printf("\n   ");
        } else if (isprint(c) || c == '\r' || c == '\t') {
            putchar(c);
        } else {
            putchar('.');
        }
    }
    printf("\n   ----\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != 0x0800) {
        return;
    }

    struct ipheader *ip = (struct ipheader *)(packet + ETHER_HDR_LEN);
    int ip_header_len = ip->iph_ihl * 4;

    if (ip_header_len < 20 || ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;

    int total_ip_len = ntohs(ip->iph_len);
    int payload_len = total_ip_len - ip_header_len - tcp_header_len;
    const u_char *payload = packet + ETHER_HDR_LEN + ip_header_len + tcp_header_len;

    int captured_available = (int)header->caplen - (ETHER_HDR_LEN + ip_header_len + tcp_header_len);
    if (payload_len > captured_available) {
        payload_len = captured_available;
    }
    if (payload_len < 0) {
        payload_len = 0;
    }

    printf("\n==================== TCP PACKET ====================\n");
    printf("[Ethernet Header]\n");
    printf("   Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("   Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    printf("[IP Header]\n");
    printf("   Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Dst IP  : %s\n", inet_ntoa(ip->iph_destip));
    printf("   (IP header len = %d bytes)\n", ip_header_len);

    printf("[TCP Header]\n");
    printf("   Src Port : %d\n", ntohs(tcp->tcp_sport));
    printf("   Dst Port : %d\n", ntohs(tcp->tcp_dport));
    printf("   (TCP header len = %d bytes)\n", tcp_header_len);

    printf("[HTTP Message]\n");
    if (ntohs(tcp->tcp_sport) == 80 || ntohs(tcp->tcp_dport) == 80) {
        printf("   (port 80 → likely HTTP)\n");
    }
    print_payload(payload, payload_len);
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";

    if (argc > 1) {
        handle = pcap_open_offline(argv[1], errbuf);
        if (!handle) {
            fprintf(stderr, "open_offline: %s\n", errbuf);
            return 1;
        }
    } else {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
            fprintf(stderr, "장치를 찾을 수 없음: %s\n", errbuf);
            return 1;
        }

        printf("[*] capturing on: %s\n", alldevs->name);
        handle = pcap_open_live(alldevs->name, BUFSIZ, 1, 1000, errbuf);
        pcap_freealldevs(alldevs);
        if (!handle) {
            fprintf(stderr, "open_live: %s\n", errbuf);
            return 1;
        }
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "filter error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}

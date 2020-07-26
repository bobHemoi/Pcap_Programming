#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>

#include "libnet-headers-sample.h"

#define ETHERNET_LENGTH 14
#define IP_LENGTH       20
#define TCP_LENGTH      20
#define TCP_CHECK       6

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}


void print_IP(const ipv4_hdr* ip) {
    printf("\nIP HEADER\n");

    uint32_t ip_addr = ntohl(ip->ip_src);
    printf("SOURCE      IP: ");
    for (int i = 3 ; i>= 0 ; i--){
        printf("%d.", (ip_addr >> i*8) & 0xFF); 
    }
    printf("\n");

    ip_addr = ntohl(ip->ip_dst);
    printf("DESTINATION IP: ");
    for (int i = 3 ; i>= 0 ; i--){
        printf("%d.", (ip_addr >> i*8) & 0xFF); 
    }
    printf("\n");    
    
}

void print_ethernet(const ethernet_hdr* eth) {
    printf("\nETHERNET HEADER\n");

    printf("SOURCE      MAC:");
    for (int i = 0 ; i<= 5 ; i++){
        printf("%02x:", eth->ether_shost[i]);
    }
    printf("\n");

    printf("Destination MAC:");
    for (int i = 0 ; i<= 5 ; i++){
        printf("%02x:", eth->ether_dhost[i]);
    }
    printf("\n");

}

void print_TCP(const tcp_hdr* tcp){
    printf("\nTCP HEADER\n");

    uint16_t sport = ntohs(tcp->th_sport);
    uint16_t dport = ntohs(tcp->th_dport);
    printf("SOURCE      PORT: %d\n", sport);
    printf("DESTINATION PORT: %d\n", dport);
}

void print_Payload(const u_char* payload, uint32_t packet_len){
        printf("\nPAYLOAD\n");

        int payload_len = packet_len - ETHERNET_LENGTH - IP_LENGTH - TCP_LENGTH;
        payload_len = 16 < payload_len ? 16 : payload_len;
        for (int i=0;i< payload_len;i++){
            printf("%02x ", payload[i]);
        }
        printf("\n"); 
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    // root 권한에서만 가능함
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char*       packet;
        const ethernet_hdr* ethernet;
        const ipv4_hdr*     ip;
        const tcp_hdr*      tcp;
        u_char*          payload;

        payload[16] ={0, };

 
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        
        printf("\n%u bytes captured\n", header->caplen);
        
        ethernet = (ethernet_hdr *)(packet);
        
        ip = (ipv4_hdr *)(packet + ETHERNET_LENGTH);
        if (ip->ip_p != TCP_CHECK){
            printf("This packet isn't TCP\n");
            continue;
        }

        tcp = (tcp_hdr *)(packet + ETHERNET_LENGTH + IP_LENGTH);

        payload = (u_char *)(packet + ETHERNET_LENGTH + IP_LENGTH + TCP_LENGTH);
        
        print_ethernet(ethernet);
        print_IP(ip);
        print_TCP(tcp);
        print_Payload(payload, header->caplen);
    }

    pcap_close(handle);
}

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
        printf("%x:", eth->ether_shost[i]);
    }
    printf("\n");

    printf("Destination MAC:");
    for (int i = 0 ; i<= 5 ; i++){
        printf("%x:", eth->ether_shost[i]);
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

void print_Payload(const u_char* payload, const ipv4_hdr* ip){
        printf("\nPAYLOAD\n");
        int len_payload = ntohs(ip->ip_len) - IP_LENGTH - TCP_LENGTH;
        len_payload = 16 < len_payload ? 16 : len_payload;
        for (int i=0;i< len_payload;i++){
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

        // header에는 이름이 들어감, 시간도
        // 패킷의 정보에는 시각 정보도 있고, 몇바이트 잡혔는지도 나와있음 -> 버퍼의 시작 위치
        // wireshark -> ethernet -> destination
        // 실제로 잡힌 헤더는 이더넷 헤더부터임 click -> ethernet header 맨앞에있는 것은 destination
        // IP header에는 버전이 있고 길이가 있고 (45)
        // 위치를 알아내서 source, Destination도 확인하세요
        // protocol field도 확인하세요, TCP 헤더 위치는 Ip헤더의 위치를 확인하면 됨
        // TCP 데이터 시작 위치 부터 16바이트 까지 출력을 해주면 된다
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        
        printf("\n%u bytes captured\n", header->caplen);
        
        ethernet = (ethernet_hdr *)(packet);
        
        ip = (ipv4_hdr *)(packet + ETHERNET_LENGTH);
        uint16_t ip_size = ip->ip_len;
        if (ip->ip_p != TCP_CHECK){
            printf("This packet isn't TCP\n");
            continue;
        }

        tcp = (tcp_hdr *)(packet + ETHERNET_LENGTH + IP_LENGTH);
        int tcp_size = sizeof(tcp);

        payload = (u_char *)(packet + ETHERNET_LENGTH + IP_LENGTH + TCP_LENGTH);
        



        print_ethernet(ethernet);
        print_IP(ip);
        print_TCP(tcp);
        print_Payload(payload, ip);
    }

    pcap_close(handle);
}

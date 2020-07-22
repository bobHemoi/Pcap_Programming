#include <pcap.h>
#include <stdio.h>
#include "libnet-headers-sample.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
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
        // 여기부터 내 코드를 집어넣으면 된다
        printf("\n%u bytes captured\n", header->caplen);
        
        printf("\nETHERNET HEADER\n");
        ethernet = (ethernet_hdr *)(packet);
        printf("SOURCE      MAC: %u\n", ethernet->ether_shost);
        printf("Destination MAC: %u\n", ethernet->ether_dhost);

        ip = (ipv4_hdr *)(packet + 14);
        printf("\nIP HEADER\n");
        printf("SOURCE      IP: %u\n", ip->ip_src);
        printf("DESTINATION IP: %u\n", ip->ip_dst);



    }

    pcap_close(handle);
}

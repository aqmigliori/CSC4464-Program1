#include <stdio.h>
#include <pcap.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


/* Ethertypes */
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_ARP 0x0806

/* IP Protocol Numbers */




struct ethernetHeader {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
} __attribute__((packed)); //compiler removes all padding

struct arpHeader {
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t hardwareAddrLen;
    uint8_t protocolAddrLen;
    uint16_t opcode;
    uint8_t srcHardwareAddr[6];
    uint8_t srcProtocolAddr[4];
    uint8_t targetHardwareAddr[6];
    uint8_t targetProtocolAddr[4];
} __attribute__((packed));


uint16_t ethernetPrint(char *packet, struct pcap_pkthdr header, int packetNumber) {
    struct ethernetHeader *eth;
    eth = (struct ethernetHeader *) packet;
    uint16_t etherType = ntohs(eth->type);

    printf("\n");
    printf("Packet number: %d", packetNumber);

    printf("  Packet Len: %d\n\n\t", header.caplen);

    printf("Ethernet Header\n\t\t");

    printf("Dest MAC: %x:%x:%x:%x:%x:%x\n\t\t", eth->dest[0], eth->dest[1], eth->dest[2],
           eth->dest[3], eth->dest[4], eth->dest[5]);

    printf("Source MAC: %x:%x:%x:%x:%x:%x\n\t\t", eth->src[0], eth->src[1], eth->src[2],
           eth->src[3], eth->src[4], eth->src[5]);


    printf("Type: ");
    if (etherType == 0x0806) {
        printf("ARP\n");
    } else if (etherType == 0x0800) {
        printf("IP\n");
    } else {
        printf("Unknown\n");
    }
    return etherType;
}

void arpPrint() {

}

void ipPrint() {

}

int main(int argc, char *argv[]) {
    int packetNumber = 1;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <trace file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline(argv[1], errbuf); //Pointer to libpcap capture object
    if (handle == NULL) {
        fprintf(stderr, "Problem reading trace file: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    struct pcap_pkthdr header;
    const u_char *packet = pcap_next(handle, &header);
    while (packet != NULL) {
        uint16_t etherType = ethernetPrint((char*)packet, header, packetNumber);
        switch (etherType) {
            case ETH_TYPE_ARP: arpPrint(); break;
            case ETH_TYPE_IPV4: ipPrint(); break;
        }

        packetNumber++;
        packet = pcap_next(handle, &header); //increment packet
    }


    pcap_close(handle);
    return 0;
}
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

/* ARP */
#define ARP_REQUEST 1
#define ARP_REPLY 2

/* IP Protocol Numbers */


const char *arpOpcodeStr(uint16_t opcode) {
    switch (opcode) {
        case ARP_REQUEST: return "Request";
        case ARP_REPLY: return "Reply";
        default: return "Unknown";
    }
}

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


uint16_t ethernetPrint(const u_char *packet) {
    struct ethernetHeader *eth;
    eth = (struct ethernetHeader *) packet; //cast packet pointer to pointer to ethernet header struct (maps 1:1)
    uint16_t etherType = ntohs(eth->type);


    printf("\tEthernet Header\n");

    printf("\t\tDest MAC: %x:%x:%x:%x:%x:%x\n", eth->dest[0], eth->dest[1], eth->dest[2],
           eth->dest[3], eth->dest[4], eth->dest[5]);

    printf("\t\tSource MAC: %x:%x:%x:%x:%x:%x\n", eth->src[0], eth->src[1], eth->src[2],
           eth->src[3], eth->src[4], eth->src[5]);


    printf("\t\tType: ");
    if (etherType == 0x0806) {
        printf("ARP\n");
    } else if (etherType == 0x0800) {
        printf("IP\n");
    } else {
        printf("Unknown\n");
    }
    return etherType;
}

void arpPrint(const u_char *packet) {
    struct arpHeader *arp;
    arp = (struct arpHeader *) packet;
    printf("\n\tARP Header\n");
    printf("\t\tOpcode: %s\n", arpOpcodeStr(ntohs(arp->opcode)));
    printf("\t\tSender MAC: %x:%x:%x:%x:%x:%x\n", arp->srcHardwareAddr[0], arp->srcHardwareAddr[1],
           arp->srcHardwareAddr[2],
           arp->srcHardwareAddr[3], arp->srcHardwareAddr[4], arp->srcHardwareAddr[5]);
    printf("\t\tSender IP: %d.%d.%d.%d\n", arp->srcProtocolAddr[0], arp->srcProtocolAddr[1], arp->srcProtocolAddr[2],
           arp->srcProtocolAddr[3]);
    printf("\t\tTarget MAC: %x:%x:%x:%x:%x:%x\n", arp->targetHardwareAddr[0], arp->targetHardwareAddr[1],
           arp->targetHardwareAddr[2],
           arp->targetHardwareAddr[3], arp->targetHardwareAddr[4], arp->targetHardwareAddr[5]);
    printf("\t\tTarget IP: %d.%d.%d.%d\n", arp->targetProtocolAddr[0], arp->targetProtocolAddr[1],
           arp->targetProtocolAddr[2], arp->targetProtocolAddr[3]);
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
        printf("\n");
        printf("Packet number: %d", packetNumber);
        printf("  Packet Len: %d\n\n", header.len);
        uint16_t etherType = ethernetPrint(packet);
        switch (etherType) {
            case ETH_TYPE_ARP: arpPrint(packet + sizeof(struct ethernetHeader));
                break;
            case ETH_TYPE_IPV4: ipPrint();
                break;
        }

        packetNumber++;
        packet = pcap_next(handle, &header); //increment packet
    }


    pcap_close(handle);
    return 0;
}

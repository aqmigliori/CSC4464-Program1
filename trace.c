#include <stdio.h>
#include <pcap.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// ARP 0x0806
// IPv4 0x0800

struct ethernetHeader {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
} __attribute__((packed)); //compiler removes all padding


void ethernetPrint(char *packet, struct pcap_pkthdr header, int packetNumber) {
    struct ethernetHeader *ex;

    printf("\n");
    printf("Packet number: %d", packetNumber);
    ex = (struct ethernetHeader *) packet;

    printf("  Packet Len: %d\n\n\t", header.caplen);

    printf("Ethernet Header\n\t\t");

    printf("Dest MAC: %x:%x:%x:%x:%x:%x\n\t\t", ex->dest[0], ex->dest[1], ex->dest[2],
           ex->dest[3], ex->dest[4], ex->dest[5]);

    printf("Source MAC: %x:%x:%x:%x:%x:%x\n\t\t", ex->src[0], ex->src[1], ex->src[2],
           ex->src[3], ex->src[4], ex->src[5]);


    printf("Type: ");
    if (ntohs(ex->type) == 0x0806) {
        printf("ARP\n");
    } else if (ntohs(ex->type) == 0x0800) {
        printf("IP\n");
    } else {
        printf("Unknown\n");
    }
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
        perror("pcap_open_offline");
        exit(EXIT_FAILURE);
    }

    struct pcap_pkthdr header;
    const u_char *packet = pcap_next(handle, &header);

    while (packet != NULL) {
        ethernetPrint((char*)packet, header, packetNumber);
        packetNumber++;
        packet = pcap_next(handle, &header); //increment packet
    }


    pcap_close(handle);
    return 0;
}
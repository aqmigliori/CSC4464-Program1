#include <stdio.h>
#include <pcap.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes) {
    printf("Captured packet with length: %d\n", (int)header->caplen);

}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <trace file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline(argv[1], errbuf); //Pointer to libpcap capture object
    if (handle==NULL) {
        perror("pcap_open_offline");
        exit(EXIT_FAILURE);
    }
    // pcap_loop(handle, 0, packet_handler, NULL);
    struct pcap_pkthdr header;
    char *packet = pcap_next(handle, header);

    pcap_close(handle);

    return 0;
}
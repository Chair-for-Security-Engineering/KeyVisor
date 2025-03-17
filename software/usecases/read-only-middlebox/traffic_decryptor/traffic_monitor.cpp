#include "traffic_monitor.h"

#include <stdio.h>
#include <stdint.h>

#include <assert.h>

#include <pcap.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "sess_info_db.h"
#include "simple_tls12_header.hpp"
#include "traffic_decryptor.h"

//const uint16_t DEMO_CLIENT_PORT = <random>;
const char *DEMO_CLIENT_IP = "172.16.0.1"; // TODO: must be updated accordingly

const uint16_t DEMO_SERVER_PORT = 2703;
const char *DEMO_SERVER_IP = "172.16.0.2"; // TODO: might need to be updated

const int SNAP_BUFSIZ = 2048; // at least 1514 (full Ethernet frame)
const int ENABLE_PROMISCUOUS = 0;
const int CAPTURE_TIMEOUT_MS = 1000; // if 0, might have to wait till buffer is full

typedef struct cb_user_data {} cb_udata_t;

void packet_recv_cb(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet) {

    if (!header || !packet) {
        printf("Received incomplete packet\n");
        return;
    }

    assert(header->len == header->caplen);

    cb_udata_t *user_data = (cb_udata_t *) args;
    printf("*************************************\nNext packet has length: %u (present: %u)\n", header->len, header->caplen);

    // parse Ethernet, IP, and TCP headers
    struct ethhdr* eth_hdr = (struct ethhdr *) packet;
    struct iphdr* ip_hdr = (struct iphdr *) (packet + ETH_HLEN);
    
    uint16_t size_ip_hdr = ip_hdr->ihl * 4;
    if (size_ip_hdr < 20) {
        printf("Invalid length of IP header: %hu\n", size_ip_hdr);
        return;
    }

    // TODO: might happen for handshake certificate
    if (ip_hdr->frag_off & IP_MF) {
        printf("WARNING: this seems to be an IP fragment, with more to follow\n");
    }

    struct tcphdr* tcp_hdr = (struct tcphdr *) (packet + ETH_HLEN + size_ip_hdr);

    uint16_t size_tcp_hdr = tcp_hdr->doff * 4;
    printf("TCP header length: %hu\n", size_tcp_hdr);
    if (size_tcp_hdr < 20) {
        printf("Invalid length of TCP header\n", size_tcp_hdr);
        return;   
    }
    if ((header->len - ETH_HLEN - size_ip_hdr) < size_tcp_hdr) {
        printf("Packet cannot fit TCP header\n");
        return;
    }

    // look up handles via connection info
    //session_info_map
    printf("src IP: %s\n", inet_ntoa({.s_addr = ip_hdr->saddr}));
    printf("dst IP: %s\n", inet_ntoa({.s_addr = ip_hdr->daddr}));
    printf("src port: %hu\n", ntohs(tcp_hdr->th_sport));
    printf("dst port: %hu\n", ntohs(tcp_hdr->th_dport));

    // we just assume for the moment we only have 1 key of each type (which will be the case in almost any setting)

    // Client -> Server? (where "Client" is the entity that shared the keys)
    s_key_type_t key_type;
    std::deque<skbndl_entry_t> *handle_deque = NULL;
    session_handle_t *key_handle = NULL;
    try {
        connection_info_t conn_info = {
            .client_port = tcp_hdr->th_sport,
            .server_port = tcp_hdr->th_dport,
            .client_ip = ip_hdr->saddr,
            .server_ip = ip_hdr->daddr,
        };
        handle_deque = &session_info_map.at(conn_info);
        key_type = client_encrypt;

    } catch (std::exception &e) {
        try {
            // Server -> Client? (where "Client" is the entity that shared the keys)
            connection_info_t conn_info = {
                .client_port = tcp_hdr->th_dport,
                .server_port = tcp_hdr->th_sport,
                .client_ip = ip_hdr->daddr,
                .server_ip = ip_hdr->saddr,
            };
            handle_deque = &session_info_map.at(conn_info);
            key_type = server_encrypt;

        } catch (std::exception &e) {
            printf("Did not find any key handle entry for the connection\n");
            return;
        }
    }
    printf("Found key handle DB entry\n");
    if (key_type == client_encrypt) printf("Connection direction is from key-sharer --> peer\n");
    else if (key_type == server_encrypt) printf("Connection direction is from key-sharer <== peer\n");

    // grab handle entry
    assert(handle_deque->size() == 1); // assume 1 entry only
    for (skbndl_entry_t &kbndl : *handle_deque) {
        assert(kbndl.sess_handle_vec.size() == 2);
        // assumption idx 0 = client, idx 1 = server
        if (key_type == client_encrypt) {
            key_handle = &kbndl.sess_handle_vec.at(0);
            assert(key_handle);
            assert(key_handle->key_type == key_type);
        } else {
            key_handle = &kbndl.sess_handle_vec.at(1);
            assert(key_handle);
            assert(key_handle->key_type == key_type);
        }
        break;
    }

    // locate TLS packet and its length
    printf("ip_hdr->tot_len: %hu\n", ntohs(ip_hdr->tot_len));
    uint16_t size_tls = ntohs(ip_hdr->tot_len) - size_ip_hdr - size_tcp_hdr;
    printf("app-layer (TLS) data length: %hu\n", size_tls);
    uint16_t rem_packet_len = header->len - ETH_HLEN - size_ip_hdr - size_tcp_hdr;
    printf("remaining pcap packet length: %hu\n", rem_packet_len);

    if (rem_packet_len > size_tls) printf("warning: extra bytes in pcap packet (Ethernet 0-byte padding?)\n");

    if (!size_tls) {
        printf("No TCP payload\n");
        return;
    }

    const u_char *app_data = packet + ETH_HLEN + size_ip_hdr + size_tcp_hdr;


    // check if TLS application data message
    struct simple_tls12_app_data *tls_appdata = (struct simple_tls12_app_data *) app_data;

    switch (tls_appdata->type) {
        case APPLICATION_DATA: {
            break;
        }
        
        case CHANGE_CIPHER_SPEC:
        case ALERT:
        case HANDSHAKE: {
            printf("TLS packet is no application data packet (type: %hhu), so skip\n",
            tls_appdata->type);
            // increase TLS sequence number by 1 for this direction
            //key_handle->tls_seq_num++;
            return;
        }

        // TODO: seems to occur with handshake messages
        //      -- probably too long certificate messages being split into
        //      -- multiple fragments;
        default: {
            printf("ERROR: unknown TLS message type: %hhu! will not count as valid record\n", tls_appdata->type);
            return;
        }
    }

    if (tls_appdata->version.major != 0x03 || tls_appdata->version.minor != 0x03) {
        printf("No TLS 1.2 packet, so invalid/unsupported\n");
        key_handle->net_tls_seq_num++; //skip anyway?
        return;
    }

    printf("TLS 1.2 application data payload of length: %hu\n", ntohs(tls_appdata->net_length));
    assert ((sizeof(struct simple_tls12_app_data) + ntohs(tls_appdata->net_length)) == size_tls);

    printf("TLS application data payload message looks fine\n");

    
    // extract + calculate metadata required for decryption

    // checked format, is fine (fix_iv[4] || dyn_iv[8])
    // dyn_iv at begin of TLS msg's app data
    uint8_t gcm_iv[12];
    // implicit part from previous sharing
    memcpy(gcm_iv, key_handle->handshake_iv_tls12, 4);
    // explicit dynamic part
    memcpy(&gcm_iv[4], tls_appdata->encrypted_app_data, 8);


    // increase TLS sequence number by 1 for this direction
    printf("Using sequence number: %lu\n", key_handle->net_tls_seq_num);
    key_handle->net_tls_seq_num = htobe64(be64toh(key_handle->net_tls_seq_num)+1);


    // warning: len is not app data len, but cipher len
    // format: (seq_num || type || version[2] || cipher-len[2])
    uint8_t gcm_aad[8+1+2+2];
    memcpy(gcm_aad, &key_handle->net_tls_seq_num, 8);
    memcpy(&gcm_aad[8], tls_appdata, 1+2);

    size_t gcm_cipher_len = ntohs(tls_appdata->net_length) - 8 - 16; // - IV, - tag
    uint16_t net_clen = htons(gcm_cipher_len);
    memcpy(&gcm_aad[8+3], &net_clen, 2);

    uint8_t *gcm_cipher = &tls_appdata->encrypted_app_data[8]; // skip dyn. IV

    // at end of TLS msg's app data (behind iv||cipher)
    uint8_t gcm_tag[16];
    memcpy(gcm_tag, &tls_appdata->encrypted_app_data[ntohs(tls_appdata->net_length)-16], 16);


    // gcm-decrypt
#ifdef USE_OPENSSL_STUB_INSTEAD
    if (openssl_gcm_decrypt(key_handle, gcm_iv, gcm_tag, gcm_aad, sizeof(gcm_aad), gcm_cipher, gcm_cipher_len) != 0) {
#else
    if (keyvisor_gcm_decrypt(key_handle, gcm_iv, gcm_tag, gcm_aad, sizeof(gcm_aad), gcm_cipher, gcm_cipher_len) != 0) {
#endif
        printf("Attempt to decrypt failed\n");
    } else {
        printf("Successfully decrypt-verified TLS message\n");
    }
}

void monitor_tls_traffic(void) {
    /* deprecated API, TODO: switch to pcap_findalldevs() and use 1st list entry */
    char *sniff_target_dev = pcap_lookupdev(NULL);
	if (!sniff_target_dev) {
	    fprintf(stderr, "Couldn't find default network interface device\n");
	}

	printf("default device: %s\n", sniff_target_dev);

    bpf_u_int32 mask, net; // netmask and IP of sniffing device
    if (pcap_lookupnet(sniff_target_dev, &net, &mask, NULL) == -1) {
        fprintf(stderr, "Failed getting netmask and IP of device\n");
        mask = 0;
        net = 0;
    }
    printf("device (mask, net): (%#x, %#x)\n", mask, net);

    pcap_t *pcap_sess_handle;
    // if 3rd argument is true (instead of false), will enable promiscuous mode
    // pcap_open_live ( *device, snaplen, promisc, to_ms, *ebuf );
    // no promiscuous, no timeout
    pcap_sess_handle = pcap_open_live(sniff_target_dev, SNAP_BUFSIZ, ENABLE_PROMISCUOUS, CAPTURE_TIMEOUT_MS, NULL);
    if (!pcap_sess_handle) {
        fprintf(stderr, "Couldn't open sniff device\n");
        return;
    }

    char filter_exp[] = "ip and tcp port 2703";
    struct bpf_program bpf_filter;

    if (pcap_compile(pcap_sess_handle, &bpf_filter, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Failed parsing filter: %s\n", filter_exp);
        pcap_close(pcap_sess_handle);
        return;
    }

    if (pcap_setfilter(pcap_sess_handle, &bpf_filter) == -1) {
        fprintf(stderr, "Failed attaching our BPF filter\n");
        pcap_close(pcap_sess_handle);
        return;
    }

    printf("Entering packet sniffing loop\n");

    // use pcap_loop() -- allows for setting callback functions (note that dispatch is similar but only processes a batch)
    cb_udata_t placeholder;
    switch (pcap_loop(pcap_sess_handle, -1, packet_recv_cb, (u_char *) &placeholder)) {
        case 0: {
            printf("PCAP loop: no more packets\n");
            break;
        }
        default: {
            printf("PCAP read loop terminated\n");
            break;
        }
    }

    pcap_close(pcap_sess_handle);
}

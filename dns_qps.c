#include <pcap.h>  
#include <sys/time.h>  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#define TYPE_REQ 0
#define TYPE_RES 1

#define INTERVAL 2 

volatile unsigned int response_count;
volatile unsigned int request_count;

volatile unsigned int stat_incr = 0;
volatile unsigned int req_incr = 0;
volatile unsigned int res_incr = 0;


struct pcap_arg
{
    char dev[16];
    char arg[64];
    unsigned int count;
    char type;
};


void req_packet(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet){ 

    unsigned int *count = (unsigned int *)arg;
     ++ (* count);
    if ( req_incr != stat_incr)
    {
        req_incr = stat_incr;
        request_count = *count;
        *count = 0;
    }

}


void res_packet(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet){    

    unsigned int *count = (unsigned int *)arg;
    ++ (* count);
    if (res_incr != stat_incr)
    {
        res_incr = stat_incr;
        response_count = *count;
        *count = 0;
    }

}


void statistics(){
    struct timeval tv;
    unsigned int q_count =0, a_count = 0;
    while(1){
        sleep(INTERVAL);
        gettimeofday(&tv,NULL);
        if (stat_incr == req_incr)
            q_count = request_count;
        else
            q_count = 0 ;

        if (stat_incr == res_incr)
            a_count = response_count ;
        else
            a_count = 0;
        printf("%lu.%lu    Request:%u Response:%u\n",tv.tv_sec, tv.tv_usec/1000, q_count, a_count); 

        stat_incr ++ ;
    }
}


void pcap_process(struct pcap_arg *pcap_m){
    pcap_t * descr=NULL;
    bpf_u_int32 net=0 , mask=0 ;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;

    memset(errbuf, 0, sizeof(errbuf));
    memset(&filter, 0, sizeof(filter));
    descr = pcap_open_live(pcap_m->dev, 512, 1, 1000, errbuf);
    if (!descr){
        perror(errbuf);
        exit(1);
    }
    if(pcap_lookupnet(pcap_m->dev, &net, &mask, errbuf) == -1){
        perror(pcap_geterr(descr));
        exit(1);
    }
    if (pcap_compile(descr, &filter, pcap_m->arg, 1, net) == -1) {
        perror(pcap_geterr(descr));
        exit(1);
    };
    if (pcap_setfilter(descr, &filter) == -1){
        perror(pcap_geterr(descr));
        exit(1);
    }

    if (pcap_m->type == TYPE_REQ)
        pcap_loop(descr, -1, req_packet, (u_char *)(&(pcap_m->count)));
    else if (pcap_m->type == TYPE_RES)
        pcap_loop(descr, -1, res_packet, (u_char *)(&(pcap_m->count)));
}


void usage(){
    printf("%s\n", "dns_qps [interface] [server_ip] [server_port]" );
    printf("%s\n", "Example:\n   ./dns_qps any 127.0.0.1 53");
    exit(0);
}


int main(int argc, char const *argv[])
{
    pthread_t req_id, res_id;
    struct pcap_arg pcap_req, pcap_res;

    if (argc <= 1 || strcmp(argv[1], "-h") == 0){
        usage();
    }

    memset(&pcap_req, 0, sizeof(struct pcap_arg));
    memset(&pcap_res, 0, sizeof(struct pcap_arg));
    if (argc > 1){
        strcpy(pcap_req.dev, argv[1]);
        strcpy(pcap_res.dev, argv[1]);
    }else{
        strcpy(pcap_req.dev, "any");
        strcpy(pcap_res.dev, "any");
    }    
    if (argc > 3){
        sprintf(pcap_req.arg, "dst %s and dst port %s", argv[2], argv[3]);
        sprintf(pcap_res.arg, "src %s and src port %s", argv[2], argv[3]);
    }else if (argc > 2){
        sprintf(pcap_req.arg, "dst %s and dst port %s", argv[2], "53");
        sprintf(pcap_res.arg, "src %s and src port %s", argv[2], "53");
    }else{
        sprintf(pcap_req.arg, "dst port %s", "53");
        sprintf(pcap_res.arg, "src port %s", "53");
    }    
    pcap_req.type = TYPE_REQ;
    pcap_res.type = TYPE_RES;

    // pthread_create(&id, NULL, (void *)statistics, NULL);
    pthread_create(&req_id, NULL, (void *)pcap_process, &pcap_req);
    //Two threads to invoke the same callback function at the same time, sometimes cause abnormal data error
    // you can copy the callback function into two copies
    usleep(1000 * 100);
    pthread_create(&res_id, NULL, (void *)pcap_process, &pcap_res);

    statistics();

    return 0;
}

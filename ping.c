#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

//#include <netinet/ip_icmp.h>
#define BUFSIZE 1500

pid_t pid; 
u_char  usendbuf[BUFSIZE];
u_char  rsendbuf[BUFSIZE];

int icmp_sock;
unsigned int nSent=0;
unsigned long v=0, arrive_time=0;
struct sockaddr_in go_addr;


/*******************************function prototype**************************/
void unpack_packet (u_char* pbuffer);
u_int16_t in_cksum(const u_int16_t *addr, register int len, u_int16_t csum);
void dump_icmp_timestamp_info (struct icmp icmp_p);



void usage (void)
{
	
	printf("usage: myping [hostname] or [ip address]\n");

}


/*送出icmp timestamp request的函式, 並會將相關表頭的資訊設定給icmp封包*/
void send_timestamp_request()
{
	struct timeval tval;
	struct icmp*  icmp_h;
	int icmp_size;
	int sret;
	u_int16_t *pp;
	
	
	icmp_h = (struct icmp*) usendbuf;
		
	/************填入icmp相關的封包表頭資訊**************/
	icmp_h->icmp_type=ICMP_TIMESTAMP;
	icmp_h->icmp_code=0;
	icmp_h->icmp_cksum=0;
	icmp_h->icmp_id =pid;
	icmp_h->icmp_seq=++nSent;
	int j=0;	
 	/*將icmp 封包的長度設為20:表頭8bytes,3個timestamp為12bytes合計20個bytes*/
	icmp_size = 8+12;

	/*計算送出封包的時間並將他傳道original time的欄位裡面*/
	gettimeofday (&tval, NULL);
	v = htonl ((tval.tv_sec % 86400) * 1000 + tval.tv_usec / 1000);
	
	icmp_h->icmp_otime=v;
	icmp_h->icmp_rtime=0;
	icmp_h->icmp_ttime=0;
	
	/*計算icmp封包的cksum*/
	icmp_h->icmp_cksum=in_cksum((u_int16_t*)icmp_h, icmp_size, 0);
	
	pp = (u_int16_t*)usendbuf;
	
	/*印出icmp 封包timestamp的資訊*/
	dump_icmp_timestamp_info (*icmp_h);
	
	/*送出icmp的封包*/
 	sret = sendto (icmp_sock, usendbuf, BUFSIZE, 0, (struct sockaddr*)&go_addr, sizeof (struct sockaddr_in));
 	if (sret <= 0)
 		fprintf(stderr,"sock send data fail!!\n");
 	//printf("sret:%d\n", sret);
}

/*********************************計算cksum的函式*******************************************/
/*******************************************************************************************/
u_int16_t in_cksum(const u_int16_t *addr, register int len, u_int16_t csum)
{
	register int nleft = len;
	const u_int16_t *w = addr;
	register u_int16_t answer;
	register int sum = csum;

	
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += htons(*(u_char *)w << 8);

	
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}


void dump_icmp_timestamp_info (struct icmp icmp_p)
{
	printf("icmp_type=%d, icmp_code=%d\n", icmp_p.icmp_type, icmp_p.icmp_code);
	printf("Original time=%lu\n",ntohl(icmp_p.icmp_otime));
	printf("Recieve time=%lu\n",ntohl(icmp_p.icmp_rtime));
	printf("Transmit time=%lu\n",ntohl(icmp_p.icmp_ttime));
	
}

/********************************************處理收到的icmp封包*****************************/

void unpack_packet (u_char* pbuffer)
{
	struct ip* iph;
	struct icmp* icmp_h;
	int iphlen;
	unsigned int rtt;
	
	iph = (struct ip*)rsendbuf;
	
	/*計算ip header的長度*/
	iphlen = iph->ip_hl << 2;
	
	/*取得icmp的內容*/
	icmp_h = (struct icmp*)(rsendbuf+iphlen);
	printf("response icmp type:%d\n",icmp_h->icmp_type );
	switch (icmp_h->icmp_type)
	{
		case ICMP_TIMESTAMPREPLY:
			
			if (icmp_h->icmp_id == pid && icmp_h->icmp_seq == nSent)
			{
				printf("------------------------------------------------\n");			
				
				/*印出icmp 封包timestamp的資訊*/
				dump_icmp_timestamp_info (*icmp_h);
				
				printf("back time:%lu\n", arrive_time);
				
				/*計算rtt所需的時間*/
				rtt = (arrive_time - ntohl(icmp_h->icmp_ttime)) + (ntohl(icmp_h->icmp_rtime) - ntohl(icmp_h->icmp_otime));				
				printf("RTT:%lu\n", rtt);
				printf("------------------------------------------------\n");
		  }
			break;
		default:
			printf("the icmp type is not TimeStamp Reply!!\n");
	}
}




int main (int argc, char** argv)
{
	
	char* target;
	char* hostname;	
	struct sockaddr_in from;
	struct hostent *hp;
	u_int16_t *pp;
	u_int8_t tmp;
	time_t tm;	
	int sret, rret;
 	int addrlen;	
	struct timeval tval;
	int size=50*1024;
	
	/*將usendbuf,rsendbuf初始資料*/   
	memset(usendbuf, 0, sizeof(usendbuf));
	memset(rsendbuf, 0, sizeof(rsendbuf));
	
	if (argc != 2)
	{
		usage ();
		exit (1);
	}
	
	target = argv[1];
	

	bzero (&go_addr, sizeof(go_addr));//initial sockaddr_in data
	

	go_addr.sin_family = AF_INET;
	addrlen = sizeof(from);
	
	/****************對domain name作處理處理且取得相對應的ip位置****************/
	if (inet_aton (target, &go_addr.sin_addr) == 1)
	{
		hostname = target;
		inet_aton(hostname, &go_addr.sin_addr);
	}
	else
	{
		/*使用gethostbyname函式取得domain name相對應的ip address*/
		hp = gethostbyname2(target, AF_INET);
		if (!hp)
		{
			printf("unkown host name!!!!\n");
			
			exit (1);
			
		}
								
		hostname = strdup (hp->h_name);									
		
		/*將ip address複製進go_addr.sin_addr的資料結構裡*/
		memcpy (&go_addr.sin_addr, hp->h_addr, 4);						
	}
	/*******************************************************************/	
	
	icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (icmp_sock < 0)
	{
		perror ("create raw socket fail!!\n");
		exit (1);
	}
	setsockopt(icmp_sock,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size) );
	pid = getpid() & 0xffff;

	printf("hostname:%s, ip address:%s\n", hostname, inet_ntoa (go_addr.sin_addr));   
 
 
	/******************傳送具有timestamp request的icmp封包***********/
	send_timestamp_request();
  
	/*********************接收icmp的封包並作處理*********************/
	rret = recvfrom (icmp_sock,rsendbuf, BUFSIZE,0, (struct sockaddr*)&from, &addrlen);
	
	if (rret > 0)
	{			
		/*********************計算收到封包的時間***********************/
		gettimeofday (&tval, NULL);			
		arrive_time = (tval.tv_sec % 86400) * 1000 + tval.tv_usec / 1000;
		/**************************************************************/
		
		
		/*處理icmp的封包*/
		unpack_packet (rsendbuf);
	}

	return 0;
}


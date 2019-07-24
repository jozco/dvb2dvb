/*
 
dvb2dvb - combine multiple SPTS to a MPTS
Copyright (C) 2014 Dave Chapman
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <curl/curl.h>

#include "dvb2dvb.h"
#include "psi_read.h"
#include "psi_create.h"
#include "crc32.h"
#include "parse_config.h"

/////////////////////////////////////////////////
// tcudpreceive integration from OpenCaster
/////////////////////////////////////////////////
#define MULTICAST

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define UDP_MAXIMUM_SIZE 65535 /* theoretical maximum size */
/////////////////////////////////////////////////
// tcudpsend integration from OpenCaster
/////////////////////////////////////////////////
#define TS_PACKET_SIZE 188

long long int usecDiff(struct timespec *time_stop, struct timespec *time_start)
{
  long long int temp = 0;
  long long int utemp = 0;

  if (time_stop && time_start)
  {
    if (time_stop->tv_nsec >= time_start->tv_nsec)
    {
      utemp = time_stop->tv_nsec - time_start->tv_nsec;
      temp = time_stop->tv_sec - time_start->tv_sec;
    }
    else
    {
      utemp = time_stop->tv_nsec + 1000000000 - time_start->tv_nsec;
      temp = time_stop->tv_sec - 1 - time_start->tv_sec;
    }
    if (temp >= 0 && utemp >= 0)
    {
      temp = (temp * 1000000000) + utemp;
    }
    else
    {
      fprintf(stderr, "start time %ld.%ld is after stop time %ld.%ld\n", time_start->tv_sec, time_start->tv_nsec, time_stop->tv_sec, time_stop->tv_nsec);
      temp = -1;
    }
  }
  else
  {
    fprintf(stderr, "memory is garbaged?\n");
    temp = -1;
  }
  return temp / 1000;
}
/////////////////////////////////////////////////
static uint8_t null_packet[188] = {
    0x47, 0x1f, 0xff, 0x10, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff};

void dump_service(struct service_t *services, int i)
{
  fprintf(stderr, "Service %d:\n", i);
  fprintf(stderr, "  URL: %s\n", services[i].url);
  fprintf(stderr, "  service_id: OLD=%d NEW=%d\n", services[i].service_id, services[i].new_service_id);
  fprintf(stderr, "  name: %s\n", services[i].name);
  fprintf(stderr, "  pmt_pid: OLD=%d NEW=%d\n", services[i].pmt_pid, services[i].new_pmt_pid);
  fprintf(stderr, "  pcr_pid: OLD=%d NEW=%d\n", services[i].pcr_pid, services[i].pid_map[services[i].pcr_pid]);
  fprintf(stderr, "  lcn: %d\n", services[i].lcn);
}

void check_cc(char *msg, int service, uint8_t *my_cc, uint8_t *buf)
{
  if (buf[0] != 0x47)
  {
    fprintf(stderr, "%s: Service %d, NO SYNC BYTE: 0x%02x 0x%02x 0x%02x 0x%02x\n", msg, service, buf[0], buf[1], buf[2], buf[3]);
    return;
  }

  int pid = (((buf[1] & 0x1f) << 8) | buf[2]);
  int discontinuity_indicator = (buf[5] & 0x80) >> 7;
  int adaption_field_control = (buf[3] & 0x30) >> 4;
  if (my_cc[pid] == 0xff)
  {
    my_cc[pid] = buf[3] & 0x0f;
    // fprintf(stderr, "CC >>>>>>> pid = %d, my_cc[pid] = buf[3] & 0x0f = %d\n", pid, my_cc[pid]);
  }
  else
  {
    if ((adaption_field_control != 0) && (adaption_field_control != 2))
    {
      my_cc[pid]++;
      my_cc[pid] %= 16;
      // fprintf(stderr, "CC >>>>>>> pid = %d, my_cc[pid] = %d\n", pid, my_cc[pid]);
    }
  }

  if ((discontinuity_indicator == 0) && (my_cc[pid] != (buf[3] & 0x0f)))
  {
    fprintf(stderr, "%s: Service %d, PID %d - packet incontinuity - expected %02x, found %02x\n", msg, service, pid, my_cc[pid], buf[3] & 0x0f);
    my_cc[pid] = buf[3] & 0x0f;
    // fprintf(stderr, "CC >>>>>>> pid = %d, my_cc[pid] = buf[3] & 0x0f = %d\n", pid, my_cc[pid]);
  }
}

static size_t
curl_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
  struct service_t *sv = userp;
  int count = size * nmemb;

  // Check input stream for CC errors
  int needed = 188 - sv->curl_bytes;
  int bytes_left = count;
  //fprintf(stderr, "Processing %d bytes, needed=%d\n", count, needed);
  uint8_t *p = contents;
  while (bytes_left >= needed)
  {
    memcpy(&sv->curl_buf[sv->curl_bytes], p, needed);
    bytes_left -= needed;
    sv->curl_bytes = 0;
    p += needed;
    //check_cc("curl", sv->id, &sv->curl_cc[0], &sv->curl_buf[0]);
    needed = 188;
  }
  if (bytes_left)
  {
    sv->curl_bytes = bytes_left;
    memcpy(&sv->curl_buf[0], p, sv->curl_bytes);
  }
  //fprintf(stderr, "End of processing, %d bytes, byte_left=%d\n", count, bytes_left);

  int n = rb_write(&sv->inbuf, contents, count);

  if (n < count)
  {
    fprintf(stderr, "\nERROR: Stream %d, Input buffer full, dropping %d bytes\n", sv->id, (count)-n);
  }

  /* Confirm there are bytes in the buffer */
  sv->status = 1;

  // fprintf(stderr, "curl_callback, stream=%s, size=%d, written=%d\n", sv->name, (int)count, n); // commented
  return count;                                                                                /* Pretend we've consumed all */
}
/* statistics definition */
int total_bytes[4];
time_t last_time, now;
int setstats(void)
{
  for (int i = 0; i < 4; i++)
  {
    total_bytes[i] = 0;
  }
  time(&last_time);
}
int updatestats(int len, int id)
{
  total_bytes[id] += len;
  time(&now);
}
void *stathread(void)
{
  while (1)
  {
    // fprintf(stderr, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
    // if (last_time < now)
    // {
    //   time(&last_time);
    //   for (int i = 0; i < 4; i++)
    //   {
    //     fprintf(stderr, "ID: %d READ: %d kbbp | ", i, (total_bytes[i] * 8) / 1000);
    //     total_bytes[i] = 0;
    //   }
    //   fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
    // }
  }
}
/* end of statistics definition */

static void *curl_thread(void *userp)
{
  struct service_t *sv = userp;

  CURL *curl;

  rb_init(&sv->inbuf);

  if(sv->source == 0) {
  /* CURL */
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, sv->url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)sv);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "dvb2dvb/git-master");
    curl_easy_perform(curl); /* ignores error */
    curl_easy_cleanup(curl);
  /* CURL END */
  }

  if(sv->source == 1) {
    FILE * pFile;
    size_t result;
    uint8_t *contents;

    pFile = fopen ( sv->file , "rb" );
    if (pFile==NULL) {
      fputs ("File error",stderr); 
      exit (1);
    }

    // allocate memory to contain the whole file:
    int size = 188; contents = (uint8_t*) malloc (size);
    if (contents == NULL) {fputs ("Memory error",stderr); exit (2);}

    while((result = fread (contents, 1, size, pFile))>0) {
      curl_callback(contents, 1, result, (void *)sv);
      //fprintf(stderr, "Result: %d\n", result);
    };

    fclose (pFile);
  }

  if(sv->source == 2) {
  /////////////////////////////////////////////////////////
  // url port parse from https://stackoverflow.com/questions/726122/best-ways-of-parsing-a-url-using-c
  /////////////////////////////////////////////////////////
  char ip[100];
  int port = 80;
  sscanf(sv->mcast, "%99[^:]:%99d", ip, &port);
  /////////////////////////////////////////////////////////
  // tcudpreceive integration from OpenCaster
  /////////////////////////////////////////////////////////
  int sockfd;
  struct sockaddr_in addr;
#ifdef ip_mreqn
  struct ip_mreqn mgroup;
  XXX
#else
  /* according to
          http://lists.freebsd.org/pipermail/freebsd-current/2007-December/081080.html
        in bsd it is also possible to simply use ip_mreq instead of ip_mreqn
        (same as in Linux), so we are using this instead
     */
  struct ip_mreq mgroup;
#endif
      int reuse;
  unsigned int addrlen;
  int len;
  unsigned char udp_packet[UDP_MAXIMUM_SIZE];

  memset((char *)&mgroup, 0, sizeof(mgroup));
  mgroup.imr_multiaddr.s_addr = inet_addr(ip); // argv[1]
#ifdef ip_mreqn
  mgroup.imr_address.s_addr = INADDR_ANY;
#else
  /* this is called 'interface' here */
  mgroup.imr_interface.s_addr = INADDR_ANY;
#endif
  memset((char *)&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);          // argv[2]
  addr.sin_addr.s_addr = inet_addr(ip); // argv[1]
  addrlen = sizeof(addr);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
  {
    perror("socket(): error ");
    return 0;
  }

  reuse = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0)
  {
    perror("setsockopt() SO_REUSEADDR: error ");
  }

  if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    perror("bind(): error");
    close(sockfd);
    return 0;
  }

  if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mgroup, sizeof(mgroup)) < 0)
  {
    perror("setsockopt() IPPROTO_IP: error ");
    close(sockfd);
    return 0;
  }

  setstats();
  while (1)
  {
    len = recvfrom(sockfd, udp_packet, UDP_MAXIMUM_SIZE, 0, (struct sockaddr *)&addr, &addrlen);
    //fprintf(stderr,"Read %d from %d\n",len,sv->id);
    //updatestats(len,sv->id);

    if (len < 0)
    {
      perror("recvfrom(): error ");
    }
    else
    {
      curl_callback((uint8_t *)udp_packet, 1, len, (void *)sv);
    }
  }
  /////////////////////////////////////////////////////
  }

  return NULL;
}

/* Read PAT/PMT/SDT from stream and stop at first packet with PCR */
int init_service(struct service_t *sv)
{
  uint8_t buf[188];
  int n;
  int pid;
  int i = 0;

  // First find the PAT, to identify the service_id and pmt_pid
  while (1)
  {
    n = rb_read(&sv->inbuf, buf, 188);
    check_cc("rb_read0", sv->id, &sv->my_cc[0], buf);
    (void)n;
    i++;
    pid = (((buf[1] & 0x1f) << 8) | buf[2]);

    // fprintf(stderr, "Searching for PAT, pid=%d %02x %02x %02x %02x\n", pid, buf[0], buf[1], buf[2], buf[3]); // commented
    if (pid == 0)
    {
      process_pat(sv, buf);
      break;
    }
  }

  // Now process the other tables, in any order
  //  PMT: sv->pmt_pid
  //  SDT:
  while ((!sv->pmt.length) || (!sv->sdt.length))
  {
    n = rb_read(&sv->inbuf, buf, 188);
    check_cc("rb_read1", sv->id, &sv->my_cc[0], buf);
    i++;
    pid = (((buf[1] & 0x1f) << 8) | buf[2]);
    if (pid == sv->pmt_pid)
    {
      process_section(&sv->next_pmt, &sv->pmt, buf, 0x02);
    }
    else if (pid == 17)
    {
      process_section(&sv->next_sdt, &sv->sdt, buf, 0x42);
      if (sv->sdt.length)
      {
        process_sdt(sv);
      }
    }
  }

  process_pmt(sv);

  // fprintf(stderr, "Read SDT (%d bytes) and PMT (%d bytes)\n", sv->sdt.length, sv->pmt.length); // commented

  // Read until we find a packet with a PCR
  // TODO: Merge this into the loop above, so we are always using the latest PMT/PAT when we have found a PCR.

  // fprintf(stderr, "Searching for PCR...\n"); // commented

  // Create our new PMT section, removing unused streams and references to CA descriptors
  create_pmt(sv);

  if (sv->ait_pid)
  {
    create_ait(sv);
  }
  return 0;
}

void read_to_next_pcr(struct mux_t *mux, struct service_t *sv)
{
  int found = 0;
  uint8_t *buf = (uint8_t *)(&sv->buf) + 188 * sv->packets_in_buf;

  while (!found)
  {
    int n = rb_read(&sv->inbuf, buf, 188);
    check_cc("rb_read2", sv->id, &sv->my_cc[0], buf);
    (void)n;
    int pid = (((buf[1] & 0x1f) << 8) | buf[2]);
    if (pid == sv->pcr_pid)
    {
      if (((buf[3] & 0x20) == 0x20) && (buf[4] > 5) && (buf[5] & 0x10))
      {
        sv->first_pcr = sv->second_pcr;
        sv->second_pcr = (uint64_t)buf[6] << 25;
        sv->second_pcr |= (uint64_t)buf[7] << 17;
        sv->second_pcr |= (uint64_t)buf[8] << 9;
        sv->second_pcr |= (uint64_t)buf[9] << 1;
        sv->second_pcr |= ((uint64_t)buf[10] >> 7) & 0x01;
        sv->second_pcr *= 300;
        sv->second_pcr += ((buf[10] & 0x01) << 8) | buf[11];

        if (sv->second_pcr < sv->first_pcr)
        {
          fprintf(stderr, "WARNING: PCR wraparound - first_pcr=%s", pts2hmsu(sv->first_pcr, '.'));
          fprintf(stderr, ", second_pcr=%s", pts2hmsu(sv->second_pcr, '.'));
        }
        found = 1;
      }
    }

    if (pid == 0x12)
    {
      process_section(&sv->next_eit, &sv->eit, buf, 0x4e); // EITpf, actual TS
      if (sv->eit.length)
      {
        struct section_t new_eit;
        if (rewrite_eit(&new_eit, &sv->eit, sv->service_id, sv->new_service_id, sv->onid, mux) == 0)
        { // This is for this service
          int npackets = copy_section(buf, &new_eit, 0x12);
          sv->packets_in_buf += npackets;
          buf += npackets * 188;
        }
        sv->eit.length = 0; // Clear section, we are done with it.
      }
    }

    if (sv->pid_map[pid])
    {
      // Change PID
      buf[1] = (buf[1] & ~0x1f) | ((sv->pid_map[pid] & 0x1f00) >> 8);
      buf[2] = sv->pid_map[pid] & 0x00ff;

      sv->packets_in_buf++;
      buf += 188;
    }
  }
}

void sync_to_pcr(struct service_t *sv)
{
  int n;
  int pid;
  uint8_t buf[188];

  while (1)
  {
    n = rb_read(&sv->inbuf, buf, 188);
    check_cc("rb_read3", sv->id, &sv->my_cc[0], buf);
    (void)n;
    pid = (((buf[1] & 0x1f) << 8) | buf[2]);
    if (pid == sv->pmt_pid)
    {
      process_section(&sv->next_pmt, &sv->pmt, buf, 0x02);
    }
    else if (pid == 17)
    {
      process_section(&sv->next_sdt, &sv->sdt, buf, 0x42);
    }
    else if (pid == sv->pcr_pid)
    {
      // e.g. 4709 0320 b7 10 ff5b d09c 00ab
      if (((buf[3] & 0x20) == 0x20) && (buf[4] > 5) && (buf[5] & 0x10))
      {
        sv->start_pcr = (uint64_t)buf[6] << 25;
        sv->start_pcr |= (uint64_t)buf[7] << 17;
        sv->start_pcr |= (uint64_t)buf[8] << 9;
        sv->start_pcr |= (uint64_t)buf[9] << 1;
        sv->start_pcr |= ((uint64_t)buf[10] >> 7) & 0x01;
        sv->start_pcr *= 300;
        sv->start_pcr += ((buf[10] & 0x01) << 8) | buf[11];
        sv->second_pcr = sv->start_pcr;
        fprintf(stderr, "Service %d, pid=%d, start_pcr=%lld (%s)\n", sv->id, pid, sv->start_pcr, pts2hmsu(sv->start_pcr, '.'));
        memcpy(&sv->buf, buf, 188);
        sv->packets_in_buf = 1;
        return;
      }
    }
  }
}

/* Function based on code in the tsrfsend.c application by Avalpa
   Digital Engineering srl */
static int calc_channel_capacity(struct dvb_modulator_parameters *params)
{
  uint64_t channel_capacity;
  int temp;

  switch (params->constellation)
  {
  case QPSK:
    temp = 0;
    break;
  case QAM_16:
    temp = 1;
    break;
  case QAM_64:
    temp = 2;
    break;
  default:
    fprintf(stderr, "Invalid constellation, aborting\n");
    exit(1);
  }
  channel_capacity = params->bandwidth_hz * 1000;
  channel_capacity = channel_capacity * (temp * 2 + 2);

  switch (params->guard_interval)
  {
  case GUARD_INTERVAL_1_32:
    channel_capacity = channel_capacity * 32 / 33;
    break;
  case GUARD_INTERVAL_1_16:
    channel_capacity = channel_capacity * 16 / 17;
    break;
  case GUARD_INTERVAL_1_8:
    channel_capacity = channel_capacity * 8 / 9;
    break;
  case GUARD_INTERVAL_1_4:
    channel_capacity = channel_capacity * 4 / 5;
    break;
  default:
    fprintf(stderr, "Invalid guard interval, aborting\n");
    exit(1);
  }
  switch (params->code_rate_HP)
  {
  case FEC_1_2:
    channel_capacity = channel_capacity * 1 / 2;
    break;
  case FEC_2_3:
    channel_capacity = channel_capacity * 2 / 3;
    break;
  case FEC_3_4:
    channel_capacity = channel_capacity * 3 / 4;
    break;
  case FEC_5_6:
    channel_capacity = channel_capacity * 5 / 6;
    break;
  case FEC_7_8:
    channel_capacity = channel_capacity * 7 / 8;
    break;
  default:
    fprintf(stderr, "Invalid coderate, aborting\n");
    exit(1);
  }

  return channel_capacity / 544 * 423;
}

int explode(char ***arr_ptr, char *str, char delimiter) /* https://www.it.uu.se/katalog/larme597/explode */
{
  char *src = str, *end, *dst;
  char **arr;
  int size = 1, i;

  // Find number of strings
  while ((end = strchr(src, delimiter)) != NULL)
  {
    ++size;
    src = end + 1;
  }

  arr = malloc(size * sizeof(char *) + (strlen(str) + 1) * sizeof(char));

  src = str;
  dst = (char *)arr + size * sizeof(char *);
  for (i = 0; i < size; ++i)
  {
    if ((end = strchr(src, delimiter)) == NULL)
      end = src + strlen(src);
    arr[i] = dst;
    strncpy(dst, src, end - src);
    dst[end - src] = '\0';
    dst += end - src + 1;
    src = end + 1;
  }
  *arr_ptr = arr;

  return size;
}

static void *output_thread(void *userp)
{
  struct mux_t *m = userp;

  /* argv argc creation */
  char **argv; //, *str = "@ @ 239.9.12.1 1234 27709884 7 10";
  int argc;

  argc = explode(&argv, m->device, ' ');

  /* -----------------------------  tsudpsend start  */
  // int sockfd;
  // int len;
  // int sent;
  // int ret;
  // int is_multicast;
  // // int transport_fd;
  // unsigned char option_ttl;
  // char start_addr[4];
  // struct sockaddr_in addr;
  // unsigned long int packet_size;
  // char *tsfile;
  // unsigned char *send_buf;
  // unsigned int bitrate;
  // unsigned long long int packet_time;
  // unsigned long long int real_time;
  // struct timespec time_start;
  // struct timespec time_stop;
  // struct timespec nano_sleep_packet;

  // memset(&addr, 0, sizeof(addr));
  // memset(&time_start, 0, sizeof(time_start));
  // memset(&time_stop, 0, sizeof(time_stop));
  // memset(&nano_sleep_packet, 0, sizeof(nano_sleep_packet));

  // if (argc < 5)
  // {
  //   fprintf(stderr, "Usage: %s file.ts ipaddr port bitrate [ts_packet_per_ip_packet] [udp_packet_ttl]\n", argv[0]);
  //   fprintf(stderr, "ts_packet_per_ip_packet default is 7\n");
  //   fprintf(stderr, "bit rate refers to transport stream bit rate\n");
  //   fprintf(stderr, "zero bitrate is 100.000.000 bps\n");
  //   return 0;
  // }
  // else
  // {
  //   tsfile = argv[1];
  //   addr.sin_family = AF_INET;
  //   addr.sin_addr.s_addr = inet_addr(argv[2]);
  //   addr.sin_port = htons(atoi(argv[3]));
  //   bitrate = atoi(argv[4]);
  //   if (bitrate <= 0)
  //   {
  //     bitrate = 100000000;
  //   }
  //   if (argc >= 6)
  //   {
  //     packet_size = strtoul(argv[5], 0, 0) * TS_PACKET_SIZE;
  //   }
  //   else
  //   {
  //     packet_size = 7 * TS_PACKET_SIZE;
  //   }
  // }

  // sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  // if (sockfd < 0)
  // {
  //   perror("socket(): error ");
  //   return 0;
  // }

  // if (argc >= 7)
  // {
  //   option_ttl = atoi(argv[6]);
  //   is_multicast = 0;
  //   memcpy(start_addr, argv[2], 3);
  //   start_addr[3] = 0;
  //   is_multicast = atoi(start_addr);
  //   is_multicast = (is_multicast >= 224) || (is_multicast <= 239);
  //   if (is_multicast)
  //   {
  //     ret = setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &option_ttl, sizeof(option_ttl));
  //   }
  //   else
  //   {
  //     ret = setsockopt(sockfd, IPPROTO_IP, IP_TTL, &option_ttl, sizeof(option_ttl));
  //   }

  //   if (ret < 0)
  //   {
  //     perror("ttl configuration fail");
  //   }
  // }

  // // transport_fd = open(tsfile, O_RDONLY);
  // // transport_fd = fmemopen(&m->outbuf, packet_size, "r");
  // // if (transport_fd < 0)
  // // {
  // //   fprintf(stderr, "can't open file %s\n", tsfile);
  // //   close(sockfd);
  // //   return 0;
  // // }

  // int completed = 0;
  // send_buf = malloc(packet_size);
  // packet_time = 0;
  // real_time = 0;

  // nano_sleep_packet.tv_nsec = 665778; /* 1 packet at 100mbps*/

  // clock_gettime(CLOCK_MONOTONIC, &time_start);
  /* ----------------------------- tsudpsend end */

  int mod_fd; // declaration for Opening device
  int result;
  int channel_capacity;
  int gain;

  /* Open Device */
  if ((mod_fd = open("pipe-out.ts", O_RDWR)) < 0) {
    fprintf(stderr,"Failed to open device.\n");
    return;
  }
  /* end of open device */

  m->dvbmod_params.cell_id = 0;
  result = ioctl(mod_fd, DVBMOD_SET_PARAMETERS, &m->dvbmod_params);

  struct dvb_modulator_gain_range gain_range;
  gain_range.frequency_khz = m->dvbmod_params.frequency_khz;
  result = ioctl(mod_fd, DVBMOD_GET_RF_GAIN_RANGE, &gain_range);
  fprintf(stderr, "Gain range: %d to %d\n", gain_range.min_gain, gain_range.max_gain);

  result = ioctl(mod_fd, DVBMOD_SET_RF_GAIN, &m->gain);
  fprintf(stderr, "Gain set to %d\n", m->gain);

  /* Wait for 4MB in the ringbuffer */
  while (rb_get_bytes_used(&m->outbuf) < 10 * 1024 * 1024)
  {
    usleep(50000);
  }

  /* ------------------------------ tsudpsend start */
  // while (!completed)
  // {

  //   clock_gettime(CLOCK_MONOTONIC, &time_stop);
  //   real_time = usecDiff(&time_stop, &time_start);
  //   while (real_time * bitrate > packet_time * 1000000 && !completed)
  //   {                                                   /* theorical bits against sent bits */
  //     len = rb_read(&m->outbuf, send_buf, packet_size); /* from original */
  //     //len = read(transport_fd, send_buf, packet_size);  //transport_fd
  //     if (len < 0)
  //     {
  //       fprintf(stderr, "ts file read error \n");
  //       completed = 1;
  //     }
  //     else if (len == 0)
  //     {
  //       fprintf(stderr, "ts sent done\n");
  //       completed = 1;
  //     }
  //     else
  //     {
  //       sent = sendto(sockfd, send_buf, len, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
  //       //fprintf(stderr, "sent = %d, len = %d\n", sent, len); // thisno
  //       if (sent <= 0)
  //       {
  //         perror("send(): error ");
  //         completed = 1;
  //       }
  //       else
  //       {
  //         packet_time += packet_size * 8;
  //       }
  //     }
  //   }
  //   nanosleep(&nano_sleep_packet, 0); // ???
  // }

  // //close(transport_fd);
  // close(sockfd);
  // free(send_buf);
  /* -------------------------------- tsudpsend end */

  FILE * pFile;

  /* The main transfer loop */
  unsigned char buf[188*200];
  int n;
  unsigned long long bytes_sent = 0;
  while(1) {
  
    n = rb_read(&m->outbuf,buf,sizeof(buf));
    if (n == 0) { break; }

    int to_write = n;
    int bytes_done = 0;
    while (bytes_done < to_write) {
      n = write(mod_fd,buf+bytes_done,to_write-bytes_done);

      pFile = fopen ("output.ts","a+");
      if (pFile!=NULL)
      {
        n = fwrite(buf+bytes_done, sizeof(char), to_write-bytes_done, pFile);
        fclose (pFile);
      }

      if (n == 0) {
        /* This shouldn't happen */
        fprintf(stderr,"Zero write\n");
        usleep(500);
      } else if (n <= 0) {
        fprintf(stderr,"Write error %d: ",n);
        perror("Write error: ");
      } else {
        //if (n < sizeof(buf)) { fprintf(stderr,"Short write - %d bytes\n",n); }
        //fprintf(stderr,"Wrote %d\n",n);
        bytes_sent += n;
        bytes_done += n;
        fprintf(stderr,"Bytes sent: %llu\r",bytes_sent);
      }
    }
  }

  close(mod_fd);
  /* End of main transfer loop */
  return;
}

static int ms_to_bits(int channel_capacity, int ms)
{
  return ((int64_t)(((int64_t)channel_capacity * (int64_t)(ms)) / 1000));
}

/* The main thread for each mux */
static void *mux_thread(void *userp)
{
  struct mux_t *m = userp;
  int i, j;

  /* Calculate target bitrate */
  m->channel_capacity = calc_channel_capacity(&m->dvbmod_params);
  fprintf(stderr, "Channel capacity = %dbps\n", m->channel_capacity);

  // SI table frequencies, in bits based on above bitrate
  m->pat_freq_in_bits = ms_to_bits(m->channel_capacity, 200);
  m->pmt_freq_in_bits = ms_to_bits(m->channel_capacity, 200);
  m->sdt_freq_in_bits = ms_to_bits(m->channel_capacity, 1000);
  m->nit_freq_in_bits = ms_to_bits(m->channel_capacity, 1000);
  m->ait_freq_in_bits = ms_to_bits(m->channel_capacity, 500);

  /* Initialise output ringbuffer */
  rb_init(&m->outbuf);

  /* Start output thread */
  fprintf(stderr, "Creating output thread\n");
  int error = pthread_create(&m->output_threadid,
                             NULL, /* default attributes please */
                             output_thread,
                             (void *)m);
  if (error)
  {
    fprintf(stderr, "Couldn't create output thread - errno %d\n", error);
    return;
  }

  for (i = 0; i < m->nservices; i++)
  {
    m->services[i].id = i;
    m->services[i].new_pmt_pid = (i + 1) * 100;
    for (j = 0; j < 8192; j++)
    {
      m->services[i].my_cc[j] = 0xff;
    }
    for (j = 0; j < 8192; j++)
    {
      m->services[i].curl_cc[j] = 0xff;
    }

    fprintf(stderr, "Creating thread %d\n", i);
    int error = pthread_create(&m->services[i].curl_threadid, // curl_threadid
                               NULL,                          /* default attributes please */
                               curl_thread,
                               (void *)&m->services[i]);

    if (error)
    {
      fprintf(stderr, "Couldn't run thread number %d, errno %d\n", i, error);
    }
    else
    {
      fprintf(stderr, "Thread %d, gets %s\n", i, m->services[i].url);
    }
  }

  /* statistics thread */
  // int ret;
  // pthread_t test1;

  // ret = pthread_create(&test1, NULL, &stathread, NULL);
  // if (ret == 0)
  // {
  //   printf("\n successin opening thread \n");
  // }
  /* stat thread end  */

  for (i = 0; i < m->nservices; i++)
  {
    int res = init_service(&m->services[i]);
    if (res < 0)
    {
      fprintf(stderr, "Error opening service %d (%s), aborting\n", i, m->services[i].url);
      return;
    }

    dump_service(m->services, i);
  }

  int active_services = 0;
  while (active_services < m->nservices)
  {
    for (i = 0; i < m->nservices; i++)
    {
      if (m->services[i].status)
      {
        active_services++;
      }
    }
    fprintf(stderr, "Waiting for services - %d started\r", active_services);
  }

#if 0
  /* Flush the input buffers */  
  for (i=0;i<m->nservices;i++) {
    int to_skip = (rb_get_bytes_used(&m->services[i].inbuf)/188) * 188;
    rb_skip(&m->services[i].inbuf, to_skip);
    fprintf(stderr,"Skipped %d bytes from service %d\n",to_skip,i);
    // Reset CC counters
    for (j=0;j<8192;j++) { m->services[i].my_cc[j] = 0xff; }
  }
#endif

  for (i = 0; i < m->nservices; i++)
  {
    sync_to_pcr(&m->services[i]);
  }

  // fprintf(stderr, "Creating PAT - nservices=%d\n", nservices); // commented

  create_pat(&m->pat, m);
  create_sdt(&m->sdt, m);
  create_nit(&m->nit, m);

  int64_t output_bitpos = 0;
  int64_t next_pat_bitpos = 0;
  int64_t next_pmt_bitpos = 0;
  int64_t next_sdt_bitpos = 0;
  int64_t next_nit_bitpos = 0;
  int64_t next_ait_bitpos = 0;

  // The main output loop.  We output one TS packet (either real or padding) in each iteration.
  int x = 1;
  int64_t padding_bits = 0;
  int eit_cc = 0;
  while (1)
  {
    // Ensure we have enough data for every service.
    for (i = 0; i < m->nservices; i++)
    {
      if (m->services[i].packets_in_buf - m->services[i].packets_written == 1)
      { // Will contain a PCR.
        struct service_t *sv = &m->services[i];

        // Move last packet to start of buffer
        sv->first_pcr = sv->second_pcr;
        memcpy(&sv->buf, (uint8_t *)(&sv->buf) + (188 * (sv->packets_in_buf - 1)), 188);
        sv->packets_written = 0;
        sv->packets_in_buf = 1;

        read_to_next_pcr(m, sv);

        int64_t pcr_diff = sv->second_pcr - sv->first_pcr;
        int npackets = sv->packets_in_buf;
        // double packet_duration = pcr_diff / (double)npackets;                                                                               // commented
        // fprintf(stderr, "Stream %d: pcr_diff = %lld, npackets=%lld, packet duration=%.8g ticks\n", i, pcr_diff, npackets, packet_duration); // commented

        // Now calculate the output position for each packet, in terms of total bits written so far.
        for (j = 0; j < sv->packets_in_buf; j++)
        {
          int64_t packet_pcr = sv->first_pcr + ((j * pcr_diff) / (npackets - 1)) - sv->start_pcr;
          sv->bitpos[j] = (packet_pcr * m->channel_capacity) / 27000000;
          // fprintf(stderr, "Stream %d, packet %d, packet_pcr = %lld, bitpos %lld\n", i, j, packet_pcr, sv->bitpos[j]); // commented
        }
      }
    }

    // Find the service with the most urgent packet (i.e. earliest bitpos)
    struct service_t *sv = &m->services[0];
    for (i = 1; i < m->nservices; i++)
    {
      if (m->services[i].bitpos[m->services[i].packets_written] < sv->bitpos[sv->packets_written])
      {
        sv = &m->services[i];
      }
    }

    // fprintf(stderr, "output_bitpos=%d, sv->bitpos[sv->packets_written]=%d\n", output_bitpos, sv->bitpos[sv->packets_written]); // commented

#if 0
    fprintf(stderr,"output_bitpos  next_pat   next_pmt   next_sdt   next_nit");
    for (i=0;i<m->nservices;i++) { fprintf(stderr,"  service_%d",i); }
    fprintf(stderr,"\n");
    fprintf(stderr,"%lld %lld %lld %lld %lld",output_bitpos,next_pat_bitpos,next_pmt_bitpos,next_sdt_bitpos,next_sdt_bitpos);
    for (i=0;i<m->nservices;i++) { fprintf(stderr," %lld",m->services[i].bitpos[m->services[i].packets_written]); }
    fprintf(stderr,"\n");
//    return 0;
#endif

    /* Now check for PSI packets */
    int next_psi = 0;
    int64_t next_bitpos = sv->bitpos[sv->packets_written];
    if (next_pat_bitpos <= next_bitpos)
    {
      next_psi = 1;
      next_bitpos = next_pat_bitpos;
    }
    if (next_pmt_bitpos <= next_bitpos)
    {
      next_psi = 2;
      next_bitpos = next_pmt_bitpos;
    }
    if (next_sdt_bitpos <= next_bitpos)
    {
      next_psi = 3;
      next_bitpos = next_sdt_bitpos;
    }
    if (next_nit_bitpos <= next_bitpos)
    {
      next_psi = 4;
      next_bitpos = next_nit_bitpos;
    }
    if ((m->services[0].ait_pid) && (next_ait_bitpos <= next_bitpos))
    {
      next_psi = 5;
      next_bitpos = next_ait_bitpos;
    }

    /* Output NULL packets until we reach next_bitpos */
    while (next_bitpos > output_bitpos)
    {
      // fprintf(stderr, "next_bitpos=%lld, output_bitpos=%lld            \n", next_bitpos, output_bitpos); // commented
      rb_write(&m->outbuf, null_packet, 188);
      padding_bits += 188 * 8;
      output_bitpos += 188 * 8;
    }

    /* Now output whichever packet is next */
    int n, res;
    uint8_t *buf;
    int pid;
    switch (next_psi)
    {
    case 0:
      buf = &sv->buf[188 * sv->packets_written];
      pid = (((buf[1] & 0x1f) << 8) | buf[2]);
      if (pid == 0x12)
      { // EIT - fix CC
        buf[3] = 0x10 | eit_cc;
        eit_cc = (eit_cc + 1) % 16;
      }
      res = rb_write(&m->outbuf, &sv->buf[188 * sv->packets_written], 188);
      if (res != 188)
      {
        fprintf(stderr, "Write error - res=%d\n", res);
      }
      n = 1;
      sv->packets_written++;
      break;

    case 1: // PAT
      n = write_section(&m->outbuf, &m->pat, 0);
      next_pat_bitpos += m->pat_freq_in_bits;
      break;

    case 2: // PMT
      n = 0;
      for (i = 0; i < m->nservices; i++)
      {
        n += write_section(&m->outbuf, &m->services[i].new_pmt, m->services[i].new_pmt_pid);
      }
      next_pmt_bitpos += m->pmt_freq_in_bits;
      break;

    case 3: // SDT
      n = write_section(&m->outbuf, &m->sdt, 0x11);
      next_sdt_bitpos += m->sdt_freq_in_bits;
      break;

    case 4: // NIT
      n = write_section(&m->outbuf, &m->nit, 0x10);
      next_nit_bitpos += m->nit_freq_in_bits;
      break;

    case 5: // AIT
      n = write_section(&m->outbuf, &m->services[0].ait, m->services[0].ait_pid);
      next_ait_bitpos += m->ait_freq_in_bits;
      break;
    }
    output_bitpos += n * 188 * 8;

    if (x == 1000)
    {
      x = 0;
      for (i = 0; i < m->nservices; i++)
      {
        fprintf(stderr, "%10d  ", rb_get_bytes_used(&m->services[i].inbuf));
      }
      fprintf(stderr, "Average capacity used: %.3g%%  Outbuf = %10d               \r", 100.0 * (double)(output_bitpos - padding_bits) / (double)output_bitpos, rb_get_bytes_used(&m->outbuf));
    }
    x++;
  }
}

int main(int argc, char *argv[])
{
  int nmuxes;
  struct mux_t *muxes;

  if (argc != 2)
  {
    fprintf(stderr, "Usage: dvb2dvb config.json\n");
    return 1;
  }

  nmuxes = parse_config(argv[1], &muxes);

  if (nmuxes < 0)
  {
    fprintf(stderr, "[JSON] Error reading config file\n");
    return 1;
  }

  if (nmuxes != 1)
  {
    fprintf(stderr, "[JSON] Error - only 1 mux supported for now\n");
    return 1;
  }

  /* Must initialize libcurl before any threads are started */
  curl_global_init(CURL_GLOBAL_ALL);

  /* TODO: Do this for each mux */

  fprintf(stderr, "Creating mux processing thread 0\n");
  int error = pthread_create(&muxes[0].threadid,
                             NULL, /* default attributes please */
                             mux_thread,
                             (void *)muxes);

  fprintf(stderr, "Created mux thread - error=%d\n", error);
  fprintf(stderr, "Waiting for mux thread to terminate...\n");

  pthread_join(muxes[0].threadid, NULL);

  fprintf(stderr, "Mux thread terminated.\n");

  return 0;
}
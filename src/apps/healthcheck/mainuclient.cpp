/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause/
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "session.h"
#include "uclient.h"

#include "apputils.h"
#include "ns_turn_utils.h"

#if defined(_MSC_VER)
  #include <getopt.h>
#else
  #include <unistd.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

/////////////// extern definitions /////////////////////

int clmessage_length = 100;
bool c2c = false;
int clnet_verbose = TURN_VERBOSE_NONE;
ioa_addr peer_addr;
bool no_rtcp = false;
int default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT;
bool dont_fragment = false;
uint8_t g_uname[STUN_MAX_USERNAME_SIZE + 1];
password_t g_upwd;
char g_auth_secret[1025] = "\0";
bool g_use_auth_secret_with_timestamp = false;
unsigned char client_ifname[1025] = "";
bool mandatory_channel_padding = false;

SHATYPE shatype = SHATYPE_DEFAULT;

char origin[STUN_MAX_ORIGIN_SIZE + 1] = "\0";

band_limit_t bps = 0;

bool dual_allocation = false;

//////////////// local definitions /////////////////

static char Usage[] =
    "Usage: uclient [flags] [options] turn-server-ip-address\n"
    "Flags:\n"
    "	-v	Verbose.\n"
    "	-y	Use client-to-client connections.\n"
    "	-c	No rtcp connections.\n"
    "	-x	IPv6 relay address requested.\n"
    "	-X	IPv4 relay address explicitly requested.\n"
    "	-g	Include DONT_FRAGMENT option.\n"
    "	-D	Mandatory channel padding (like in pjnath).\n"
    "	-Z	Dual allocation (implies -c).\n"
    "Options:\n"
    "	-l	Message length (Default: 100 Bytes).\n"
    "	-p	TURN server port (Default: 3478 unsecure, 5349 secure).\n"
    "	-n	Number of messages to send (Default: 5).\n"
    "	-d	Local interface device (optional).\n"
    "	-L	Local address.\n"
    "	-m	Number of clients (default is 1).\n"
    "	-e	Peer address.\n"
    "	-r	Peer port (default 3480).\n"
    "	-z	Per-session packet interval in milliseconds (default is 20 ms).\n"
    "	-u	STUN/TURN user name.\n"
    "	-w	STUN/TURN user password.\n"
    "	-W	TURN REST API \"plain text\" secret.\n"
    "	-C	TURN REST API timestamp/username separator symbol (character). The default value is ':'.\n"
    "	-o	<origin> - the ORIGIN STUN attribute value.\n"
    "	-a	<bytes-per-second> Bandwidth for the bandwidth request in ALLOCATE. The default value is zero.\n";

//////////////////////////////////////////////////

int main(int argc, char **argv) {
  int port = 0;
  int messagenumber = 5;
  char local_addr[256];
  int c;
  int mclient = 1;
  char peer_address[129] = "\0";
  int peer_port = PEER_DEFAULT_PORT;

  char rest_api_separator = ':';

#if defined(WINDOWS)

  WORD wVersionRequested;
  WSADATA wsaData;
  int err;

  /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
  wVersionRequested = MAKEWORD(2, 2);

  err = WSAStartup(wVersionRequested, &wsaData);
  if (err != 0) {
    /* Tell the user that we could not find a usable */
    /* Winsock DLL.                                  */
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "WSAStartup failed with error: %d\n", err);
    return 1;
  }
#endif

  set_logfile("stdout");
  set_no_stdout_log(1);

  set_execdir();

  set_system_parameters(0);

  memset(local_addr, 0, sizeof(local_addr));

  while ((c = getopt(argc, argv, "a:d:p:l:n:L:m:e:r:u:w:z:W:C:E:o:ZvsycxXgAD")) != -1) {
    switch (c) {
    case 'a':
      bps = (band_limit_t)strtoul(optarg, nullptr, 10);
      break;
    case 'o':
      STRCPY(origin, optarg);
      break;
    case 'C':
      rest_api_separator = *optarg;
      break;
    case 'D':
      mandatory_channel_padding = true;
      break;
    case 'z':
      RTP_PACKET_INTERVAL = atoi(optarg);
      break;
    case 'Z':
      dual_allocation = true;
      break;
    case 'u':
      STRCPY(g_uname, optarg);
      break;
    case 'w':
      STRCPY(g_upwd, optarg);
      break;
    case 'g':
      dont_fragment = true;
      break;
    case 'd':
      STRCPY(client_ifname, optarg);
      break;
    case 'x':
      default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
      break;
    case 'X':
      default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4;
      break;
    case 'l':
      clmessage_length = atoi(optarg);
      break;
    case 'n':
      messagenumber = atoi(optarg);
      break;
    case 'p':
      port = atoi(optarg);
      break;
    case 'L':
      STRCPY(local_addr, optarg);
      break;
    case 'e':
      STRCPY(peer_address, optarg);
      break;
    case 'r':
      peer_port = atoi(optarg);
      break;
    case 'v':
      clnet_verbose = TURN_VERBOSE_NORMAL;
      break;
    case 'c':
      no_rtcp = true;
      break;
    case 'm':
      mclient = atoi(optarg);
      break;
    case 'y':
      c2c = true;
      break;
    case 'W':
      g_use_auth_secret_with_timestamp = true;
      STRCPY(g_auth_secret, optarg);
      break;
    default:
      fprintf(stderr, "%s\n", Usage);
      exit(1);
    }
  }

  if (dual_allocation) {
    no_rtcp = true;
  }

  if (g_use_auth_secret_with_timestamp) {

    {
      char new_uname[1025];
      const unsigned long exp_time = 3600UL * 24UL; /* one day */
      if (g_uname[0] != 0) {
        snprintf(new_uname, sizeof(new_uname), "%lu%c%s", (unsigned long)time(nullptr) + exp_time, rest_api_separator,
                 (char *)g_uname);
      } else {
        snprintf(new_uname, sizeof(new_uname), "%lu", (unsigned long)time(nullptr) + exp_time);
      }
      STRCPY(g_uname, new_uname);
    }
    {
      uint8_t hmac[MAXSHASIZE];
      unsigned int hmac_len;

      switch (shatype) {
      case SHATYPE_SHA256:
        hmac_len = SHA256SIZEBYTES;
        break;
      case SHATYPE_SHA384:
        hmac_len = SHA384SIZEBYTES;
        break;
      case SHATYPE_SHA512:
        hmac_len = SHA512SIZEBYTES;
        break;
      default:
        hmac_len = SHA1SIZEBYTES;
      };

      hmac[0] = 0;

      if (stun_calculate_hmac(g_uname, strlen((char *)g_uname), (uint8_t *)g_auth_secret, strlen(g_auth_secret), hmac,
                              &hmac_len, shatype) >= 0) {
        size_t pwd_length = 0;
        char *pwd = base64_encode(hmac, hmac_len, &pwd_length);

        if (pwd != nullptr) {
          if (pwd_length > 0) {
            memcpy(g_upwd, pwd, pwd_length);
            g_upwd[pwd_length] = 0;
          }
        }
        free(pwd);
      }
    }
  }

  if (port == 0) {
    port = DEFAULT_STUN_PORT;
  }

  if (clmessage_length < (int)sizeof(message_info))
    clmessage_length = (int)sizeof(message_info);

  const int max_header = 100;
  if (clmessage_length > (int)(STUN_BUFFER_SIZE - max_header)) {
    fprintf(stderr, "Message length was corrected to %d\n", (STUN_BUFFER_SIZE - max_header));
    clmessage_length = (int)(STUN_BUFFER_SIZE - max_header);
  }

  if (optind >= argc) {
    fprintf(stderr, "%s\n", Usage);
    exit(-1);
  }

  if (!c2c) {
    if (peer_address[0] != '\0') {
      fprintf(stderr, "Either -e peer_address or -y must be specified\n");
      return -1;
    }

    if (make_ioa_addr((const uint8_t *)peer_address, peer_port, &peer_addr) < 0) {
      return -1;
    }

    if (peer_addr.ss.sa_family == AF_INET6) {
      default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
    } else if (peer_addr.ss.sa_family == AF_INET) {
      default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4;
    }
  }

  start_mclient(argv[optind], port, client_ifname, local_addr, messagenumber, mclient);

  return 0;
}

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
#include "startuclient.h"
#include "apputils.h"
#include "ns_turn_msg.h"
#include "ns_turn_utils.h"
#include "session.h"
#include "uclient.h"

#if defined(__linux__)
  #include <unistd.h>
#endif

/////////////////////////////////////////

static constexpr auto MAX_CONNECT_EFFORTS = 77;
static constexpr auto DTLS_MAX_CONNECT_TIMEOUT = 30;
static constexpr auto MAX_TLS_CYCLES = 32;
static constexpr auto EXTRA_CREATE_PERMS = 25;

static uint64_t current_reservation_token = 0;
static bool allocate_rtcp = false;
static const bool never_allocate_rtcp = false;

/////////////////////////////////////////

static int get_allocate_address_family(ioa_addr *relay_addr) {
  if (relay_addr->ss.sa_family == AF_INET)
    return STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT;
  else if (relay_addr->ss.sa_family == AF_INET6)
    return STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
  else
    return STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_INVALID;
}

/////////////////////////////////////////

int socket_connect(evutil_socket_t clnet_fd, ioa_addr *remote_addr, int *connect_err) {
  if (addr_connect(clnet_fd, remote_addr, connect_err) < 0) {
    if (*connect_err == EINPROGRESS)
      return 0;
    if (*connect_err == EADDRINUSE)
      return +1;
    perror("connect");
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: cannot connect to remote addr: %d\n", __FUNCTION__, *connect_err);
    exit(-1);
  }

  return 0;
}

static int clnet_connect(uint16_t clnet_remote_port, const char *remote_address, const unsigned char *ifname,
                         const char *local_address, int verbose, app_ur_conn_info *clnet_info) {

  ioa_addr local_addr;
  int connect_cycle = 0;

  ioa_addr remote_addr;

start_socket:
  memset(&remote_addr, 0, sizeof(ioa_addr));
  if (make_ioa_addr((const uint8_t *)remote_address, clnet_remote_port, &remote_addr) < 0)
    return -1;

  memset(&local_addr, 0, sizeof(ioa_addr));

  evutil_socket_t clnet_fd = socket(remote_addr.ss.sa_family, CLIENT_DGRAM_SOCKET_TYPE, CLIENT_DGRAM_SOCKET_PROTOCOL);
  if (clnet_fd < 0) {
    perror("socket");
    exit(-1);
  }

  if (sock_bind_to_device(clnet_fd, ifname) < 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Cannot bind client socket to device %s\n", ifname);
  }

  set_sock_buf_size(clnet_fd, UR_CLIENT_SOCK_BUF_SIZE);

  set_raw_socket_tos(clnet_fd, remote_addr.ss.sa_family, 0x22);
  set_raw_socket_ttl(clnet_fd, remote_addr.ss.sa_family, 47);

  if (clnet_info->is_peer && (*local_address == 0)) {

    if (remote_addr.ss.sa_family == AF_INET6) {
      if (make_ioa_addr((const uint8_t *)"::1", 0, &local_addr) < 0) {
        socket_closesocket(clnet_fd);
        return -1;
      }
    } else {
      if (make_ioa_addr((const uint8_t *)"127.0.0.1", 0, &local_addr) < 0) {
        socket_closesocket(clnet_fd);
        return -1;
      }
    }

    addr_bind(clnet_fd, &local_addr, 0, 1, UDP_SOCKET);

  } else if (strlen(local_address) > 0) {

    if (make_ioa_addr((const uint8_t *)local_address, 0, &local_addr) < 0) {
      socket_closesocket(clnet_fd);
      return -1;
    }

    addr_bind(clnet_fd, &local_addr, 0, 1, UDP_SOCKET);
  }

  int connect_err = 0;
  if (clnet_info->is_peer) {
    ;
  } else if (socket_connect(clnet_fd, &remote_addr, &connect_err) > 0)
    goto start_socket;

  if (clnet_info) {
    addr_cpy(&(clnet_info->remote_addr), &remote_addr);
    addr_cpy(&(clnet_info->local_addr), &local_addr);
    clnet_info->fd = clnet_fd;
    addr_get_from_sock(clnet_fd, &(clnet_info->local_addr));
    STRCPY(clnet_info->lsaddr, local_address);
    STRCPY(clnet_info->rsaddr, remote_address);
    STRCPY(clnet_info->ifname, (const char *)ifname);
  }

  if (verbose && clnet_info) {
    addr_debug_print(verbose, &(clnet_info->local_addr), "Connected from");
    addr_debug_print(verbose, &remote_addr, "Connected to");
  }

  usleep(500);

  return 0;
}

void add_origin(stun_buffer *message) {
  if (message && origin[0]) {
    stun_attr_add(message, STUN_ATTRIBUTE_ORIGIN, origin, strlen(origin));
  }
}

static int clnet_allocate(int verbose, app_ur_conn_info *clnet_info, ioa_addr *relay_addr, int af, char *turn_addr,
                          uint16_t *turn_port) {

  int af_cycle = 0;
  int reopen_socket = 0;

  int allocate_finished;

  stun_buffer request_message, response_message;

beg_allocate:

  allocate_finished = 0;

  while (!allocate_finished && af_cycle++ < 32) {

    int allocate_sent = 0;

    if (reopen_socket) {
      socket_closesocket(clnet_info->fd);
      clnet_info->fd = -1;
      if (clnet_connect(addr_get_port(&(clnet_info->remote_addr)), clnet_info->rsaddr, (uint8_t *)clnet_info->ifname,
                        clnet_info->lsaddr, verbose, clnet_info) < 0) {
        exit(-1);
      }
      reopen_socket = 0;
    }

    int af4 = dual_allocation || (af == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4);
    int af6 = dual_allocation || (af == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6);

    uint64_t reservation_token = 0;
    char *rt = nullptr;
    int ep = !no_rtcp && !dual_allocation;

    if (!no_rtcp) {
      if (!never_allocate_rtcp && allocate_rtcp) {
        reservation_token = ioa_ntoh64(current_reservation_token);
        rt = (char *)(&reservation_token);
      }
    }

    if (rt) {
      ep = -1;
    } else if (!ep) {
      ep = (((uint8_t)turn_random()) % 2);
      ep = ep - 1;
    }

    stun_set_allocate_request(&request_message, UCLIENT_SESSION_LIFETIME, af4, af6, STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE, 0, rt, ep);

    if (bps)
      stun_attr_add_bandwidth_str(request_message.buf, (size_t *)(&(request_message.len)), bps);

    if (dont_fragment)
      stun_attr_add(&request_message, STUN_ATTRIBUTE_DONT_FRAGMENT, nullptr, 0);

    add_origin(&request_message);

    if (add_integrity(clnet_info, &request_message) < 0)
      return -1;

    stun_attr_add_fingerprint_str(request_message.buf, (size_t *)&(request_message.len));


    ////////////<<==allocate send
    while (!allocate_sent) {

      int len = send_buffer(clnet_info, &request_message);

      if (len > 0) {
        if (verbose) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "allocate sent\n");
        }
        allocate_sent = 1;
      } else {
        perror("send");
        exit(1);
      }
    }


    ////////allocate response==>>
    {
      int allocate_received = 0;
      while (!allocate_received) {

        int len = recv_buffer(clnet_info, &response_message, 1, &request_message);

        if (len > 0) {
          if (verbose) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "allocate response received: \n");
          }
          response_message.len = len;
          int err_code = 0;
          uint8_t err_msg[129];
          if (stun_is_success_response(&response_message)) {
            allocate_received = 1;
            allocate_finished = 1;

            if (clnet_info->nonce[0]) {
              if (check_integrity(clnet_info, &response_message) < 0)
                return -1;
            }

            if (verbose) {
              TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success\n");
            }
            {
              int found = 0;

              stun_attr_ref sar = stun_attr_get_first(&response_message);
              while (sar) {

                int attr_type = stun_attr_get_type(sar);
                if (attr_type == STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS) {

                  if (stun_attr_get_addr(&response_message, sar, relay_addr, nullptr) < 0) {
                    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: !!!: relay addr cannot be received (1)\n", __FUNCTION__);
                    return -1;
                  } else {
                    if (verbose) {
                      ioa_addr raddr;
                      memcpy(&raddr, relay_addr, sizeof(ioa_addr));
                      addr_debug_print(verbose, &raddr, "Received relay addr");
                    }

                    if (!addr_any(relay_addr)) {
                      if (relay_addr->ss.sa_family == AF_INET) {
                        if (default_address_family != STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6) {
                          found = 1;
                          addr_cpy(&(clnet_info->relay_addr), relay_addr);
                          break;
                        }
                      }
                      if (relay_addr->ss.sa_family == AF_INET6) {
                        if (default_address_family == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6) {
                          found = 1;
                          addr_cpy(&(clnet_info->relay_addr), relay_addr);
                          break;
                        }
                      }
                    }
                  }
                }

                sar = stun_attr_get_next(&response_message, sar);
              }

              if (!found) {
                TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: !!!: relay addr cannot be received (2)\n", __FUNCTION__);
                return -1;
              }
            }

            stun_attr_ref rt_sar = stun_attr_get_first_by_type(&response_message, STUN_ATTRIBUTE_RESERVATION_TOKEN);
            uint64_t rtv = stun_attr_get_reservation_token_value(rt_sar);
            current_reservation_token = rtv;
            if (verbose)
              TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: rtv=%llu\n", __FUNCTION__, (long long unsigned int)rtv);

          } else if (stun_is_error_response(&response_message, &err_code, err_msg, sizeof(err_msg))) {

            allocate_received = 1;

            if (err_code == 300) {

              if (clnet_info->nonce[0]) {
                if (check_integrity(clnet_info, &response_message) < 0)
                  return -1;
              }

              ioa_addr alternate_server;
              if (stun_attr_get_first_addr(&response_message, STUN_ATTRIBUTE_ALTERNATE_SERVER, &alternate_server,
                                           nullptr) == -1) {
                // error
              } else if (turn_addr && turn_port) {
                addr_to_string_no_port(&alternate_server, (uint8_t *)turn_addr);
                *turn_port = (uint16_t)addr_get_port(&alternate_server);
              }
            }

            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "error %d (%s)\n", err_code, (char *)err_msg);
            if (err_code != 437) {
              allocate_finished = 1;
              current_reservation_token = 0;
              return -1;
            } else {
              TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "trying allocate again %d...\n", err_code);
              sleep(1);
              reopen_socket = 1;
            }
          } else {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "unknown allocate response\n");
            /* Try again ? */
          }
        } else {
          perror("recv");
          exit(-1);
          break;
        }
      }
    }
  }
  ////////////<<== allocate response received

  if (!allocate_finished) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot complete Allocation\n");
    exit(-1);
  }

  allocate_rtcp = !allocate_rtcp;

  if (1) {

    af_cycle = 0;
  beg_refresh:

    if (af_cycle++ > 32) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot complete Refresh\n");
      exit(-1);
    }

    //==>>refresh request, for an example only:
    {
      int refresh_sent = 0;

      stun_init_request(STUN_METHOD_REFRESH, &request_message);
      uint32_t lt = htonl(UCLIENT_SESSION_LIFETIME);
      stun_attr_add(&request_message, STUN_ATTRIBUTE_LIFETIME, (const char *)&lt, 4);

      if (dual_allocation) {
        int t = ((uint8_t)turn_random()) % 3;
        if (t) {
          uint8_t field[4];
          field[0] = (t == 1) ? (uint8_t)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4
                              : (uint8_t)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
          field[1] = 0;
          field[2] = 0;
          field[3] = 0;
          stun_attr_add(&request_message, STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY, (const char *)field, 4);
        }
      }

      add_origin(&request_message);

      if (add_integrity(clnet_info, &request_message) < 0)
        return -1;

      stun_attr_add_fingerprint_str(request_message.buf, (size_t *)&(request_message.len));

      while (!refresh_sent) {

        int len = send_buffer(clnet_info, &request_message);

        if (len > 0) {
          if (verbose) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "refresh sent\n");
          }
          refresh_sent = 1;
        } else {
          perror("send");
          exit(1);
        }
      }
    }

    ////////refresh response==>>
    {
      int refresh_received = 0;
      while (!refresh_received) {

        int len = recv_buffer(clnet_info, &response_message, 1, &request_message);

        if (len > 0) {
          if (verbose) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "refresh response received: \n");
          }
          response_message.len = len;
          int err_code = 0;
          uint8_t err_msg[129];
          if (stun_is_success_response(&response_message)) {
            refresh_received = 1;
            if (verbose) {
              TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success\n");
            }
          } else if (stun_is_error_response(&response_message, &err_code, err_msg, sizeof(err_msg))) {
            refresh_received = 1;
            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "error %d (%s)\n", err_code, (char *)err_msg);
            return -1;
          } else {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "unknown refresh response\n");
            /* Try again ? */
          }
        } else {
          perror("recv");
          exit(-1);
          break;
        }
      }
    }
  }

  return 0;
}

static int turn_channel_bind(int verbose, uint16_t *chn, app_ur_conn_info *clnet_info, ioa_addr *peer_addr) {

  stun_buffer request_message, response_message;

beg_bind :

{
  int cb_sent = 0;

  *chn = stun_set_channel_bind_request(&request_message, peer_addr, *chn);

  add_origin(&request_message);

  if (add_integrity(clnet_info, &request_message) < 0)
    return -1;

  stun_attr_add_fingerprint_str(request_message.buf, (size_t *)&(request_message.len));

  ////////////<<==channel bind send

  while (!cb_sent) {

    int len = send_buffer(clnet_info, &request_message);
    if (len > 0) {
      if (verbose) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "channel bind sent\n");
      }
      cb_sent = 1;
    } else {
      perror("send");
      exit(1);
    }
  }
}

  ////////channel bind response==>>

  {
    int cb_received = 0;
    while (!cb_received) {

      int len = recv_buffer(clnet_info, &response_message, 1, &request_message);
      if (len > 0) {
        if (verbose) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "cb response received: \n");
        }
        int err_code = 0;
        uint8_t err_msg[129];
        if (stun_is_success_response(&response_message)) {

          cb_received = 1;

          if (clnet_info->nonce[0]) {
            if (check_integrity(clnet_info, &response_message) < 0)
              return -1;
          }

          if (verbose) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success: 0x%x\n", (int)(*chn));
          }
        } else if (stun_is_error_response(&response_message, &err_code, err_msg, sizeof(err_msg))) {
          cb_received = 1;
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "channel bind: error %d (%s)\n", err_code, (char *)err_msg);
          return -1;
        } else {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "unknown channel bind response\n");
          /* Try again ? */
        }
      } else {
        perror("recv");
        exit(-1);
        break;
      }
    }
  }

  return 0;
}

static int turn_create_permission(int verbose, app_ur_conn_info *clnet_info, ioa_addr *peer_addr, int addrnum) {

  if (addrnum < 1)
    return 0;

  char saddr[129] = "\0";
  if (verbose) {
    addr_to_string(peer_addr, (uint8_t *)saddr);
  }

  stun_buffer request_message, response_message;

beg_cp :
  stun_init_request(STUN_METHOD_CREATE_PERMISSION, &request_message);
  {
    int addrindex;
    for (addrindex = 0; addrindex < addrnum; ++addrindex) {
      stun_attr_add_addr(&request_message, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, peer_addr + addrindex);
    }
  }

  add_origin(&request_message);

  if (add_integrity(clnet_info, &request_message) < 0)
    return -1;

  stun_attr_add_fingerprint_str(request_message.buf, (size_t *)&(request_message.len));

  ////////////<<==create permission send
  int cp_sent = 0;
  while (!cp_sent) {

    int len = send_buffer(clnet_info, &request_message);

    if (len > 0) {
      if (verbose) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "create perm sent: %s\n", saddr);
      }
      cp_sent = 1;
    } else {
      perror("send");
      exit(1);
    }
  }

  ////////create permission response==>>
  {
    int cp_received = 0;
    while (!cp_received) {

      int len = recv_buffer(clnet_info, &response_message, 1, &request_message);
      if (len > 0) {
        if (verbose) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "cp response received: \n");
        }
        int err_code = 0;
        uint8_t err_msg[129];
        if (stun_is_success_response(&response_message)) {

          cp_received = 1;

          if (clnet_info->nonce[0]) {
            if (check_integrity(clnet_info, &response_message) < 0)
              return -1;
          }

          if (verbose) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success\n");
          }
        } else if (stun_is_error_response(&response_message, &err_code, err_msg, sizeof(err_msg))) {
          cp_received = 1;
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "create permission error %d (%s)\n", err_code, (char *)err_msg);
          return -1;
        } else {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "unknown create permission response\n");
          /* Try again ? */
        }
      } else {
        perror("recv");
        exit(-1);
      }
    }
  }

  return 0;
}

int start_connection(uint16_t clnet_remote_port0, const char *remote_address0, const unsigned char *ifname,
                     const char *local_address, int verbose, app_ur_conn_info *clnet_info_probe,
                     app_ur_conn_info *clnet_info, uint16_t *chn, app_ur_conn_info *clnet_info_rtcp,
                     uint16_t *chn_rtcp) {

  ioa_addr relay_addr;
  ioa_addr relay_addr_rtcp;
  ioa_addr peer_addr_rtcp;

  addr_cpy(&peer_addr_rtcp, &peer_addr);
  addr_set_port(&peer_addr_rtcp, addr_get_port(&peer_addr_rtcp) + 1);

  /* Probe: */

  if (clnet_connect(clnet_remote_port0, remote_address0, ifname, local_address, verbose, clnet_info_probe) < 0) {
    exit(-1);
  }

  uint16_t clnet_remote_port = clnet_remote_port0;
  char remote_address[1025];
  STRCPY(remote_address, remote_address0);

  clnet_allocate(verbose, clnet_info_probe, &relay_addr, default_address_family, remote_address, &clnet_remote_port);

  /* Real: */

  *chn = 0;
  if (chn_rtcp)
    *chn_rtcp = 0;

  if (clnet_connect(clnet_remote_port, remote_address, ifname, local_address, verbose, clnet_info) < 0) {
    exit(-1);
  }

  if (!no_rtcp) {
    if (clnet_connect(clnet_remote_port, remote_address, ifname, local_address, verbose, clnet_info_rtcp) < 0) {
      exit(-1);
    }
  }

  int af = default_address_family ? default_address_family : get_allocate_address_family(&peer_addr);
  if (clnet_allocate(verbose, clnet_info, &relay_addr, af, nullptr, nullptr) < 0) {
    exit(-1);
  }

  if (!no_rtcp) {
    af = default_address_family ? default_address_family : get_allocate_address_family(&peer_addr_rtcp);
    if (clnet_allocate(verbose, clnet_info_rtcp, &relay_addr_rtcp, af, nullptr, nullptr) < 0) {
      exit(-1);
    }
  }

  /* These multiple "channel bind" requests are here only because
   * we are playing with the TURN server trying to screw it */
  if (turn_channel_bind(verbose, chn, clnet_info, &peer_addr_rtcp) < 0) {
    exit(-1);
  }

  if (turn_channel_bind(verbose, chn, clnet_info, &peer_addr_rtcp) < 0) {
    exit(-1);
  }
  *chn = 0;
  if (turn_channel_bind(verbose, chn, clnet_info, &peer_addr) < 0) {
    exit(-1);
  }

  if (turn_channel_bind(verbose, chn, clnet_info, &peer_addr) < 0) {
    exit(-1);
  }

  if (!no_rtcp) {
    if (turn_channel_bind(verbose, chn_rtcp, clnet_info_rtcp, &peer_addr_rtcp) < 0) {
      exit(-1);
    }
  }

  addr_cpy(&(clnet_info->peer_addr), &peer_addr);
  if (!no_rtcp)
    addr_cpy(&(clnet_info_rtcp->peer_addr), &peer_addr_rtcp);

  return 0;
}

int start_c2c_connection(uint16_t clnet_remote_port0, const char *remote_address0, const unsigned char *ifname,
                         const char *local_address, int verbose, app_ur_conn_info *clnet_info_probe,
                         app_ur_conn_info *clnet_info1, uint16_t *chn1, app_ur_conn_info *clnet_info1_rtcp,
                         uint16_t *chn1_rtcp, app_ur_conn_info *clnet_info2, uint16_t *chn2,
                         app_ur_conn_info *clnet_info2_rtcp, uint16_t *chn2_rtcp) {

  ioa_addr relay_addr1;
  ioa_addr relay_addr1_rtcp;

  ioa_addr relay_addr2;
  ioa_addr relay_addr2_rtcp;

  *chn1 = 0;
  *chn2 = 0;
  if (chn1_rtcp)
    *chn1_rtcp = 0;
  if (chn2_rtcp)
    *chn2_rtcp = 0;

  /* Probe: */

  if (clnet_connect(clnet_remote_port0, remote_address0, ifname, local_address, verbose, clnet_info_probe) < 0) {
    exit(-1);
  }

  uint16_t clnet_remote_port = clnet_remote_port0;
  char remote_address[1025];
  STRCPY(remote_address, remote_address0);

  clnet_allocate(verbose, clnet_info_probe, &relay_addr1, default_address_family, remote_address, &clnet_remote_port);

  /* Real: */

  if (clnet_connect(clnet_remote_port, remote_address, ifname, local_address, verbose, clnet_info1) < 0) {
    exit(-1);
  }

  if (!no_rtcp)
    if (clnet_connect(clnet_remote_port, remote_address, ifname, local_address, verbose, clnet_info1_rtcp) < 0) {
      exit(-1);
    }

  if (clnet_connect(clnet_remote_port, remote_address, ifname, local_address, verbose, clnet_info2) < 0) {
    exit(-1);
  }

  if (!no_rtcp)
    if (clnet_connect(clnet_remote_port, remote_address, ifname, local_address, verbose, clnet_info2_rtcp) < 0) {
      exit(-1);
    }

  if (!no_rtcp) {

    if (clnet_allocate(verbose, clnet_info1, &relay_addr1, default_address_family, nullptr, nullptr) < 0) {
      exit(-1);
    }

    if (clnet_allocate(verbose, clnet_info1_rtcp, &relay_addr1_rtcp, default_address_family, nullptr, nullptr) < 0) {
      exit(-1);
    }

    if (clnet_allocate(verbose, clnet_info2, &relay_addr2, default_address_family, nullptr, nullptr) < 0) {
      exit(-1);
    }

    if (clnet_allocate(verbose, clnet_info2_rtcp, &relay_addr2_rtcp, default_address_family, nullptr, nullptr) < 0) {
      exit(-1);
    }
  } else {

    if (clnet_allocate(verbose, clnet_info1, &relay_addr1, default_address_family, nullptr, nullptr) < 0) {
      exit(-1);
    }
    if (!(clnet_info2->is_peer)) {
      if (clnet_allocate(verbose, clnet_info2, &relay_addr2, default_address_family, nullptr, nullptr) < 0) {
        exit(-1);
      }
    } else {
      addr_cpy(&(clnet_info2->remote_addr), &relay_addr1);
      addr_cpy(&relay_addr2, &(clnet_info2->local_addr));
    }
  }

  if (turn_create_permission(verbose, clnet_info1, &relay_addr2, 1) < 0) {
    exit(-1);
  }

  if (!no_rtcp)
    if (turn_create_permission(verbose, clnet_info1_rtcp, &relay_addr2_rtcp, 1) < 0) {
      exit(-1);
    }
  if (!(clnet_info2->is_peer)) {
    if (turn_create_permission(verbose, clnet_info2, &relay_addr1, 1) < 0) {
      exit(-1);
    }
  }
  if (!no_rtcp)
    if (turn_create_permission(verbose, clnet_info2_rtcp, &relay_addr1_rtcp, 1) < 0) {
      exit(-1);
    }

  if (turn_channel_bind(verbose, chn1, clnet_info1, &relay_addr2) < 0) {
      exit(-1);
    }

  if (!no_rtcp)
    if (turn_channel_bind(verbose, chn1_rtcp, clnet_info1_rtcp, &relay_addr2_rtcp) < 0) {
      exit(-1);
    }
  if (turn_channel_bind(verbose, chn2, clnet_info2, &relay_addr1) < 0) {
    exit(-1);
  }
  if (!no_rtcp)
    if (turn_channel_bind(verbose, chn2_rtcp, clnet_info2_rtcp, &relay_addr1_rtcp) < 0) {
      exit(-1);
    }

  addr_cpy(&(clnet_info1->peer_addr), &relay_addr2);
  if (!no_rtcp)
    addr_cpy(&(clnet_info1_rtcp->peer_addr), &relay_addr2_rtcp);
  addr_cpy(&(clnet_info2->peer_addr), &relay_addr1);
  if (!no_rtcp)
    addr_cpy(&(clnet_info2_rtcp->peer_addr), &relay_addr1_rtcp);

  return 0;
}

/////////////////////////////////////////////////

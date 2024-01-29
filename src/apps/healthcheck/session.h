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
#ifndef TURNUTILS_HEALTHCHECK_SESSION_H_AF215CC1_CCA5_4426_B265_2A85A31EECB1
#define TURNUTILS_HEALTHCHECK_SESSION_H_AF215CC1_CCA5_4426_B265_2A85A31EECB1

#include <event2/bufferevent.h>
#include <event2/event.h>

#include "ns_turn_ioaddr.h"

#include "apputils.h"
#include "stun_buffer.h"

///////// types ////////////

enum UR_STATE { UR_STATE_UNKNOWN = 0, UR_STATE_READY, UR_STATE_DONE };

//////////////// session info //////////////////////

struct app_ur_conn_info {
  ioa_addr local_addr;
  char lsaddr[129];
  ioa_addr remote_addr;
  char rsaddr[129];
  char ifname[129];
  ioa_addr peer_addr;
  ioa_addr relay_addr;
  ioa_socket_raw fd;
  bool broken;
  uint8_t nonce[STUN_MAX_NONCE_SIZE + 1];
  uint8_t realm[STUN_MAX_REALM_SIZE + 1];
  bool is_peer;
};

struct app_ur_session {
  app_ur_conn_info pinfo;
  UR_STATE state;
  unsigned int ctime;
  uint16_t chnum;
  int wait_cycles;
  int timer_cycle;
  int completed;
  struct event *input_ev;
  struct event *input_tcp_data_ev;
  stun_buffer in_buffer;
  stun_buffer out_buffer;
  uint32_t refresh_time;
  uint32_t finished_time;
  // Msg counters:
  int tot_msgnum;
  int wmsgnum;
  int rmsgnum;
  int recvmsgnum;
  uint32_t recvtimems;
  uint32_t to_send_timems;
  // Statistics:
  size_t loss;
  uint64_t latency;
  uint64_t jitter;
};

///////////////////////////////////////////////////////

struct message_info {
  int msgnum;
  uint64_t mstime;
};

#endif // TURNUTILS_HEALTHCHECK_SESSION_H_AF215CC1_CCA5_4426_B265_2A85A31EECB1

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
#ifndef TURNUTILS_HEALTHCHECK_UCLIENT_H_0479359B_C1E6_4A0E_B0CF_B0A64B805789
#define TURNUTILS_HEALTHCHECK_UCLIENT_H_0479359B_C1E6_4A0E_B0CF_B0A64B805789

#include "session.h"
#include "stun_buffer.h"

//////////////////////////////////////////////

#define STOPPING_TIME (10)
#define STARTING_TCP_RELAY_TIME (30)

extern int clmessage_length;
extern int clnet_verbose;
extern bool c2c;
extern ioa_addr peer_addr;
extern bool no_rtcp;
extern int default_address_family;
extern bool dont_fragment;
extern uint8_t g_uname[STUN_MAX_USERNAME_SIZE + 1];
extern password_t g_upwd;
extern char g_auth_secret[1025];
extern bool g_use_auth_secret_with_timestamp;
extern int RTP_PACKET_INTERVAL;
extern unsigned char client_ifname[1025];
extern struct event_base *client_event_base;
extern bool mandatory_channel_padding;
extern SHATYPE shatype;
extern band_limit_t bps;
extern bool dual_allocation;

extern char origin[STUN_MAX_ORIGIN_SIZE + 1];

constexpr auto UCLIENT_SESSION_LIFETIME = 777;

void start_mclient(const char *remote_address, int port, const unsigned char *ifname, const char *local_address,
                   int messagenumber, int mclient);

int send_buffer(app_ur_conn_info *clnet_info, stun_buffer *message);
int recv_buffer(app_ur_conn_info *clnet_info, stun_buffer *message, int sync, stun_buffer *request_message);

void client_input_handler(evutil_socket_t fd, short what, void *arg);

turn_credential_type get_turn_credentials_type(void);

int add_integrity(app_ur_conn_info *clnet_info, stun_buffer *message);
int check_integrity(app_ur_conn_info *clnet_info, stun_buffer *message);

#endif // TURNUTILS_HEALTHCHECK_UCLIENT_H_0479359B_C1E6_4A0E_B0CF_B0A64B805789

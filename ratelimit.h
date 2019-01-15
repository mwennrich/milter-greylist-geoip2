/* $Id: ratelimit.h,v 1.3 2013/01/19 16:01:15 manu Exp $ */

/*
 * Copyright (c) 2010 Emmanuel Dreyfus
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by Emmanuel Dreyfus
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,  
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _RATELIMIT_H_
#define _RATELIMIT_H_

#include "config.h"
#if defined(HAVE_OLD_QUEUE_H) || !defined(HAVE_SYS_QUEUE_H)
#include "queue.h"
#else 
#include <sys/queue.h>
#endif

#include <stdio.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "milter-greylist.h"

enum ratelimit_type { RL_SESS, RL_RCPT, RL_DATA };

#ifndef RATELIMIT_SAMPLES
#define RATELIMIT_SAMPLES 10
#endif

struct ratelimit_conf {
        char rc_name[QSTRLEN + 1];
	enum ratelimit_type rc_type;	
	size_t rc_limit;
	time_t rc_time;
	char rc_key[QSTRLEN + 1];
	LIST_ENTRY(ratelimit_conf) rc_list;
};

struct ratelimitacct_bucket { 
	TAILQ_HEAD(, ratelimit_acct) b_ratelimitacct_head;
};    


void ratelimit_init(void);
void ratelimit_conf_add(char *, enum ratelimit_type, size_t, time_t, char *);  
void ratelimit_clear(void);
struct ratelimit_conf *ratelimit_byname(char *);
int ratelimit_validate(acl_data_t *, acl_stage_t, 
		       struct acl_param *, struct mlfi_priv *);

#endif /* _RATELIMIT_H_ */

#include "config.h"

/*
 * Copyright (c) 2009 Emmanuel Dreyfus
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

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id: store.c,v 1.5 2013/01/19 16:01:15 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>
#include <sysexits.h>

#if defined(HAVE_OLD_QUEUE_H) || !defined(HAVE_SYS_QUEUE_H) 
#include "queue.h"
#else 
#include <sys/queue.h>
#endif

#include "dump.h"
#include "pending.h"
#include "store.h"
#include "conf.h"
#include "sync.h"

#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif


void pending_init(void);
tuple_t pending_check(struct sockaddr *, socklen_t, char *, char *, 
    time_t *, time_t *, char *, time_t, time_t);
time_t pending_tarpitted(struct sockaddr *, socklen_t, char *, char *);
void pending_update(struct sockaddr *, socklen_t, char *, char *, 
    time_t, tuple_update_type_t);
void pending_del_addr(struct sockaddr *, socklen_t, char *, int);


/* 
 * Initialize storage backend. No lock needed 
 */
void mg_init(void) {
	pending_init();
	dump_reload();		/* Reload a saved greylist */

	return;
}

/* 
 * Start storage thread 
 */
void mg_start(void)	{
	/*
	 * Start the dumper thread
	 */
	dumper_start();

	/*
	 * Run the peer MX greylist sync threads
	 */
	sync_master_restart();
	sync_sender_start();

	return;
}

/* 
 * Check pending list for tuple, and update to autowhite if found
 */
tuple_t mg_tuple_check(tuple)
	struct tuple_fields *tuple;
{
	return pending_check(tuple->sa, tuple->salen,
	    tuple->from, tuple->rcpt, tuple->remaining, tuple->elapsed,
	    tuple->queueid, tuple->gldelay, tuple->autowhite);
}

/* 
 * Check pending list for tarpit entry
 */
time_t mg_tarpit_check(tuple)
	struct tuple_fields *tuple;
{
	return pending_tarpitted(tuple->sa, tuple->salen,
	    tuple->from, tuple->rcpt);
}


/* 
 * Update pending entry
 */
void mg_tuple_update(tuple)
	struct tuple_fields *tuple;
{
	pending_update(tuple->sa, tuple->salen,
	    tuple->from, tuple->rcpt, tuple->autowhite,
	    tuple->updatetype);
}


/* 
 * Remove pending entry
 */
void mg_tuple_remove(tuple)
	struct tuple_fields *tuple;
{
	pending_del_addr(tuple->sa, tuple->salen,
	    tuple->queueid, tuple->acl_line);
}

/* 
 * stop storage background threads 
 */
void mg_tuple_stop(void) {
	dumper_stop();
	return;
}

/* 
 * close storage backend 
 */
void mg_tuple_close(void) {
	return;
}

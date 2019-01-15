/* $Id: ratelimit.c,v 1.6 2013/01/19 16:01:15 manu Exp $ */

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

#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: ratelimit.c,v 1.6 2013/01/19 16:01:15 manu Exp $");
#endif
#endif

#if defined(HAVE_OLD_QUEUE_H) || !defined(HAVE_SYS_QUEUE_H) 
#include "queue.h"
#else
#include <sys/queue.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <sysexits.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "sync.h"
#include "dump.h"
#include "conf.h"
#include "spf.h"
#include "acl.h"
#include "ratelimit.h"
#include "milter-greylist.h"

#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif

#define RATELIMIT_BUCKETS 8192

LIST_HEAD(ratelimitconflist, ratelimit_conf);

struct ratelimitacct_bucket *ratelimitacct_buckets; /* notyet */
struct ratelimitconflist ratelimitconf_head;

LIST_HEAD(ratelimitacctlist, ratelimit_acct); 
 
struct ratelimit_acct {
	char ra_key[QSTRLEN + 1];
	enum ratelimit_type ra_type;
	time_t ra_time;	/* timestamp for oldest period */
	size_t ra_samples[RATELIMIT_SAMPLES];
        LIST_ENTRY(ratelimit_acct) ra_list;
}; 

struct ratelimitacctlist ratelimitacct_head;

/* protects ratelimitacct_head and ratelimitacct_buckets */
pthread_mutex_t ratelimit_lock = PTHREAD_MUTEX_INITIALIZER;
#define RATELIMIT_LOCK pthread_mutex_lock(&ratelimit_lock);
#define RATELIMIT_UNLOCK pthread_mutex_unlock(&ratelimit_lock);

void
ratelimit_init(void) {
	LIST_INIT(&ratelimitconf_head);

#ifdef notyet
	if ((ratelimitacct_buckets = calloc(RATELIMIT_BUCKETS,
	    sizeof(*ratelimitacct_buckets))) == NULL) {
		mg_log(LOG_ERR, 
		    "Unable to allocate reatelimit buckets: %s",
		    strerror(errno));
		exit(EX_OSERR);
	}

	for(i = 0; i < RATELIMIT_BUCKETS; i++) 
		TAILQ_INIT(&ratelimitacct_buckets[i].b_ratelimitacct_head);
#endif /* notyet */

	return;
}

struct ratelimit_conf *
ratelimit_byname(ratelimit)	/* acllist must be read locked */
	char *ratelimit;
{
	struct ratelimit_conf *rc;	

	LIST_FOREACH(rc, &ratelimitconf_head, rc_list) {
		if (strcmp(rc->rc_name, ratelimit) == 0)
			break;
	}

	return rc;
}

void
ratelimit_conf_add(name, type, limit, time, key)
	char *name;
	enum ratelimit_type type;
	size_t limit;
	time_t time;
	char *key;
{
	struct ratelimit_conf *rc;

	if (ratelimit_byname(name) != NULL) {
		mg_log(LOG_ERR, 
		    "ratelimit class \"%s\" specified twice at line %d",
		    name,  conf_line - 1);
		exit(EX_DATAERR);
	}

	if ((rc = malloc(sizeof(*rc))) == NULL) {
		mg_log(LOG_ERR, 
		    "Unable to allocate ratelimit class: %s", 
		    strerror(errno));
		exit(EX_OSERR);
	}

	strncpy(rc->rc_name, name, sizeof(rc->rc_name));
	rc->rc_type = type;
	rc->rc_limit = limit;
	rc->rc_time = time;
	if (key == NULL) 
		key = "%i";
	strncpy(rc->rc_key, key, sizeof(rc->rc_key));

	LIST_INSERT_HEAD(&ratelimitconf_head, rc, rc_list);

	return;
}

void
ratelimit_clear(void)	/* acllist must be write locked */
{
	struct ratelimit_conf *rc;

	while(!LIST_EMPTY(&ratelimitconf_head)) {
		rc = LIST_FIRST(&ratelimitconf_head);
		LIST_REMOVE(rc, rc_list);
		free(rc);
	}

#ifdef notyet
	free(ratelimitacct_buckets);
#endif /* notyet */

	ratelimit_init();

	return;
}


int	
ratelimit_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	struct ratelimit_conf *rc;
	struct ratelimit_acct *ra;
	struct ratelimit_acct *ra_next;
	char *key;
	struct timeval now;
	time_t slot_len;
	int i, old_index, new_index;
	size_t total = 0;
	int retval = 0;
	char *typestr;

	rc = ad->ratelimit_conf;
	(void)gettimeofday(&now, NULL);
	key = fstring_expand(priv, priv->priv_cur_rcpt, rc->rc_key, NULL);

	RATELIMIT_LOCK;

	/* 
	 * Lookup existing accounting for this key
	 */
	for (ra = LIST_FIRST(&ratelimitacct_head); ra; ra = ra_next) {
		ra_next = LIST_NEXT(ra, ra_list);

		/* 
		 * Remove obsolete accounting
		 */
		if (ra->ra_time + rc->rc_time < now.tv_sec) {
			LIST_REMOVE(ra, ra_list);
			free(ra);
			continue;
		}

		if ((strcmp(ra->ra_key, key) == 0) && 
		    (ra->ra_type == rc->rc_type))
			break;
	}

	/* 
	 * No match, create a new one
	 */
	if (ra == NULL) {
		int i;

		if ((ra = malloc(sizeof(*ra))) == NULL) {
			mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		strncpy(ra->ra_key, key, sizeof(ra->ra_key));
		ra->ra_type = rc->rc_type;
		ra->ra_time = now.tv_sec;
		for (i = 0; i < RATELIMIT_SAMPLES; i++)
			ra->ra_samples[i] = 0;

		LIST_INSERT_HEAD(&ratelimitacct_head, ra, ra_list);
	}

	/*
	 * Compute the index to use in samples
	 */
	slot_len = rc->rc_time / RATELIMIT_SAMPLES;
	old_index = (ra->ra_time / slot_len) % RATELIMIT_SAMPLES;
	new_index = (now.tv_sec / slot_len) % RATELIMIT_SAMPLES;

	/*
	 * If some slots were missed, fill them with zeros.
	 */
#ifdef CONF_DEBUG
	mg_log(LOG_DEBUG, "ratelimit \"%s\" key \"%s\"", rc->rc_name, key);
	mg_log(LOG_DEBUG, "index: old = %d, new = %d", old_index, new_index);
#endif /* CONF_DEBUG */
	if (old_index < new_index) {
		for (i = old_index + 1; i <= new_index; i++) 
			ra->ra_samples[i] = 0;
	} else if (old_index > new_index) {
		for (i = old_index + 1; i < RATELIMIT_SAMPLES; i++) 
			ra->ra_samples[i] = 0;
		for (i = 0; i <= new_index; i++) 
			ra->ra_samples[i] = 0;
	}

	/*
	 * Set latest sample
	 */
	ra->ra_time = now.tv_sec;

	switch (ra->ra_type) {
	case RL_SESS:
		typestr = "sessions";
		if (priv->priv_rcptcount == 0) /* First encounter */
			ra->ra_samples[new_index]++;
		break;
	case RL_RCPT:
		typestr = "recipients";
		if (stage == AS_RCPT)
			ra->ra_samples[new_index]++;
		else /* stage == AS_DATA */
			ra->ra_samples[new_index] += priv->priv_rcptcount;
		break;
	case RL_DATA:
		typestr = "bytes";
		ra->ra_samples[new_index] += priv->priv_msgcount;
		break;
	default:
		mg_log(LOG_ERR, 
		    "internal error: ra->ra_type = %d", 
		    ra->ra_type);
		exit(EX_SOFTWARE);
		break;
	}

		
	/* 
	 * Check total
	 */
	total = 0;
	for (i = 0; i < RATELIMIT_SAMPLES; i++)
		total += ra->ra_samples[i];

#ifdef CONF_DEBUG
	for (i = 0; i < RATELIMIT_SAMPLES; i++)
		mg_log(LOG_DEBUG, "sample[%d] = %d ", i, ra->ra_samples[i]);
	mg_log(LOG_DEBUG, "total = %d", total);
#endif /* CONF_DEBUG */
	if (total > rc->rc_limit) {
		mg_log(LOG_WARNING, 
		       "ratelimit overflow for class %s: %d, "
		       "limit is %d %s / %d sec, key = \"%s\"", 
		       rc->rc_name, total, rc->rc_limit, typestr,
		       rc->rc_time, key);
		retval = 1;
	}

	RATELIMIT_UNLOCK;
	free(key);

	return retval;
}

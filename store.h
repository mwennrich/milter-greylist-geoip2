#ifndef _STORE_H_
#define _STORE_H_

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

struct tuple_fields {
	struct sockaddr *sa;
	socklen_t salen;
        char    *from;
        char    *rcpt;
	time_t	*remaining;	/* report back remaining 
				   time before activation */
	time_t	*elapsed;	/* report back elapsed time 
				   since first encounter */
	char	*queueid;	/* for logging purposes */
	time_t	gldelay;	/* delay time for new greylist entry */
	time_t	autowhite;	/* time-out for autowhite entry */
	int	count;		/* count for ratelimit */
	tuple_update_type_t	/* update to autowhite or tarpit? */
		updatetype;
	int	acl_line;	/* acl line number */
};

/* 
 * initialize storage backend 
 */
void mg_init();		

/* 
 * start storage background threads 
 */
void mg_start();

/* 
 * check tuple status, add and update if necessary 
 */
tuple_t mg_tuple_check(struct tuple_fields *);

/* 
 * Remove pending entry
 */
void mg_tuple_remove(struct tuple_fields *);

/* 
 * Check pending list for tarpit entry
 */
time_t mg_tarpit_check(struct tuple_fields *);

/* 
 * update tuple status 
 */
void mg_tuple_update(struct tuple_fields *);

/* 
 * in case backend needs cleaning up 
 */
int mg_tuple_vacuum();

/* 
 * stop storage background threads 
 */
void mg_tuple_stop();

/* 
 * safely close storage backend 
 */
void mg_tuple_close();                       

#endif /* _STORE_H_ */

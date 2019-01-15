/* $Id: p0f.c,v 1.18 2013/08/13 12:42:25 manu Exp $ */

/*
 * Copyright (c) 2008-2012 Emmanuel Dreyfus
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

/*
 * NOTE: This is a client half for the p0f (passive-fingerprinter) daemon
 * by Michal Zalewski, source code to which may currently be found at:
 *    http://lcamtuf.coredump.cx/p0f3/
 * This separate program must be built, installed and run alongside
 * milter-greylist in order to use the relevant "p0f" ACL rules.
 */

#include "config.h"

#ifdef USE_P0F

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: p0f.c,v 1.18 2013/08/13 12:42:25 manu Exp $");
#endif
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <arpa/inet.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <errno.h>
#include <sysexits.h>
#include <syslog.h>


#include "conf.h"
#include "spf.h"
#include "acl.h"
#include "milter-greylist.h"
#include "p0f.h"

#ifndef HAVE_STRCASESTR
#include <ctype.h>
/* 
* strcasestr(): case-insensitive version of strstr() - find substring NEEDLE in
* the string HAYSTACK and return pointer to it, or NULL if not found
* Details: http://linux.die.net/man/3/strcasestr
* Source taken from an internet forum:
* http://www.sunhelp.ru/forum/viewtopic.php?p=8374&sid=0fd2c2501a0234c5267efc2a610a79c9
*/
char * 
strcasestr ( haystack, needle )
	char *haystack;
	const char *needle;
{ 
	char *h; 
	const char *n; 

	h = haystack; 
	n = needle; 
	while (*haystack) { 
		if (tolower ((unsigned char)*h) == tolower ((unsigned char)*n)) { 
			h++; 
			n++; 
			if (!*n) 
				return haystack; 
			} else { 
				h = ++haystack; 
				n = needle; 
			}
		}
	return NULL; 
}
#endif /* HAVE_STRCASESTR */

#ifndef HAVE_P0F3
#ifdef P0F_QUERY_FROM_P0F_DIST
#include <p0f-query.h>
#else /* P0F_QUERY_FROM_P0F_DIST */
/* This is from p0f/p0f-query.h */
#define QUERY_MAGIC		0x0defaced
#define QTYPE_FINGERPRINT	1
#define RESP_BADQUERY		1
#define RESP_NOMATCH		2

struct p0f_query {
	u_int32_t	magic;
	u_int8_t	type;
	u_int32_t	id;
	u_int32_t	src_ad,dst_ad;
	u_int16_t	src_port,dst_port;
};
struct p0f_response {
	u_int32_t	magic;
	u_int32_t	id;
	u_int8_t 	type;
	u_int8_t	genre[20];
	u_int8_t	detail[40];
	int8_t		dist;
	u_int8_t	link[30];
	u_int8_t	tos[30];
	u_int8_t	fw,nat;
	u_int8_t	real;
	int16_t		score;
	u_int16_t	mflags;
	int32_t		uptime;
};
/* End of stuff borrowed from p0f/p0f-query.h */
#endif /* P0F_QUERY_FROM_P0F_DIST */
#else /* HAVE_P0F3 */
#ifdef P0F_QUERY_FROM_P0F_DIST
#include <api.h>
#else /* P0F_QUERY_FROM_P0F_DIST */
#ifdef HAVE_P0F306
#define PACKED __attribute__((packed))
#else
#define PACKED
#endif
/* Begin of stuff borrowed from p0f/api.h */
#define	P0F_QUERY_MAGIC 	0x50304601
#define	P0F_RESP_MAGIC		0x50304602
#define	P0F_STATUS_BADQUERY	0x00
#define	P0F_STATUS_OK		0x10
#define	P0F_STATUS_NOMATCH	0x20
#define	P0F_ADDR_IPV4		0x04
#define	P0F_ADDR_IPV6		0x06
#define	P0F_STR_MAX		31
#define	P0F_MATCH_FUZZY		0x01
#define	P0F_MATCH_GENERIC	0x02

struct p0f_api_query {
	uint32_t magic;
	uint8_t addr_type;
	uint8_t addr[16];
} PACKED;

struct p0f_api_response {
	uint32_t magic;
	uint32_t status;
	uint32_t first_seen;
	uint32_t last_seen;
	uint32_t total_conn;
	uint32_t uptime_min;
	uint32_t up_mod_days;
	uint32_t last_nat;
	uint32_t last_chg;
	int16_t distance;
	uint8_t  bad_sw;
	uint8_t  os_match_q;
	uint8_t  os_name[P0F_STR_MAX + 1];
	uint8_t  os_flavor[P0F_STR_MAX + 1];
	uint8_t  http_name[P0F_STR_MAX + 1];
	uint8_t  http_flavor[P0F_STR_MAX + 1];
	uint8_t  link_type[P0F_STR_MAX + 1];
	uint8_t  language[P0F_STR_MAX + 1];
} PACKED;
/* End of stuff borrowed from p0f/api.h */
#endif /* P0F_QUERY_FROM_P0F_DIST */
#endif /* HAVE_P0F3 */

static int p0f_connect(void);

int
p0f_cmp(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	char *data;

       if (priv->priv_p0f == NULL)
               return 0;

	data = (char *)ad->string;
	if (strcasestr(priv->priv_p0f, data) != NULL)
		return 1;
	return 0;
}

int
p0f_regexec(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
       if (priv->priv_p0f == NULL)
               return 0;

	if (myregexec(priv, ad, ap, priv->priv_helo) == 0)
		return 1;
	return 0;
}

#ifndef HAVE_P0F3
int
p0f_lookup(priv)
	struct mlfi_priv *priv;
{
	struct p0f_query req;
	struct p0f_response rep;
	struct timeval tv;
	char *daddr;
	char *dport;
	size_t len;
	char sastr[IPADDRSTRLEN + 1];
	char dastr[IPADDRSTRLEN + 1];
	char dpstr[IPADDRSTRLEN + 1];
	int p0fsock;

	/*
	 * The p0f query interface semms to only support IPv4
	 */
	if (SA(&priv->priv_addr)->sa_family != AF_INET)
		return -1;

	daddr = local_ipstr(priv);

	if ((dport = smfi_getsymval(priv->priv_ctx, "{daemon_port}")) == NULL) {
		struct servent *s;

		mg_log(LOG_WARNING, "smfi_getsymval failed for {daemon_port}, "
				    "using default smtp port");
		if ((s = getservbyname("smtp", "tcp")) == NULL) {
			mg_log(LOG_ERR,
			       "getservbyname(\"smtp\", \"tcp\") failed");
			exit (EX_OSFILE);
		}

		(void)snprintf(dpstr, sizeof(dpstr), "%d", s->s_port);
		dport = dpstr;
	}

	memset(&req, 0, sizeof(req));
	memset(&rep, 0, sizeof(rep));
	(void)gettimeofday(&tv, NULL);

	req.magic = QUERY_MAGIC;
	req.id = tv.tv_usec;
	req.type = QTYPE_FINGERPRINT;
	req.src_ad = SADDR4(&priv->priv_addr)->s_addr;
	req.src_port = ntohs(SA4(&priv->priv_addr)->sin_port);
	req.dst_ad = inet_addr(daddr);
	req.dst_port = atoi(dport);

	if (conf.c_debug)
		 mg_log(LOG_DEBUG, "p0f_lookup: %s[%d] -> %s[%d]",
			inet_ntop(AF_INET, &req.src_ad, sastr, IPADDRSTRLEN), 
			req.src_port,
			inet_ntop(AF_INET, &req.dst_ad, dastr, IPADDRSTRLEN),
			req.dst_port);

	p0fsock = p0f_connect();
	if (p0fsock < 0)
		return -1;

	if (write(p0fsock, &req ,sizeof(req)) != sizeof(req)) {
		mg_log(LOG_ERR, "writing to \"%s\" failed", conf.c_p0fsock);
		close(p0fsock);
		return -1;
	}

	if (read(p0fsock, &rep, sizeof(rep)) != sizeof(rep)) {
		mg_log(LOG_ERR, "reading from \"%s\" failed", conf.c_p0fsock);
		close(p0fsock);
		return -1;
	}

	close(p0fsock);

	if (rep.id != req.id) {
		mg_log(LOG_ERR, "p0f reply id mismatch %x expected %x",
		       rep.id, req.id);
		return -1;
	}

	if (rep.magic != QUERY_MAGIC) {
		mg_log(LOG_ERR, "Unexpected p0f magic = %d", rep.magic);
		return -1;
	}

	switch(rep.type) {
	case RESP_BADQUERY:
		mg_log(LOG_INFO, "p0f rejected query");
		return -1;
		
		break;
	case RESP_NOMATCH:
		mg_log(LOG_INFO, "p0f cache miss");
		priv->priv_p0f = strdup("unknown");
		return 0;
		break;
	default:
		break;
	}

	/* +2 for space and trailing \0 */
	len = strlen((char *)rep.genre) + strlen((char *)rep.detail) + 2;
	if ((priv->priv_p0f = malloc(len)) == NULL) {
		mg_log(LOG_ERR, "malloc(%d) failed: %s", len, strerror(errno));
		exit(EX_OSERR);
	}

	(void)sprintf(priv->priv_p0f, "%s %s", rep.genre, rep.detail);
	if (conf.c_debug)
		mg_log(LOG_DEBUG, "p0f identified \"%s\"", priv->priv_p0f);
	
	return 0;
}
#else /* HAVE_P0F3 */
int
p0f_lookup(priv)
	struct mlfi_priv *priv;
{
	struct p0f_api_query req;
	struct p0f_api_response rep;
	size_t len;
	static int p0fsock = -1;
	static int log_disconnect = 1;

	memset(&req, 0, sizeof(req));
	memset(&rep, 0, sizeof(rep));

	req.magic = P0F_QUERY_MAGIC;
	switch (SA(&priv->priv_addr)->sa_family) {
	case AF_INET:
		req.addr_type = P0F_ADDR_IPV4;
		memcpy(&req.addr, SADDR4(&priv->priv_addr), 
		       sizeof(SADDR4(&priv->priv_addr)));
		break;
#ifdef AF_INET6
	case AF_INET6:
		req.addr_type = P0F_ADDR_IPV6;
		memcpy(&req.addr, SADDR6(&priv->priv_addr),
		       sizeof(SADDR6(&priv->priv_addr)));
		break;
#endif /* AF_INET6 */
	default:
		mg_log(LOG_ERR,
		       "unexpected sender address family %d, skipping p0f",
		       SA(&priv->priv_addr)->sa_family);
		return -1;
	}

	if (p0fsock == -1)
		p0fsock = p0f_connect();
	if (p0fsock == -1) {
		if (log_disconnect)
			mg_log(LOG_ERR,
			       "can't connect to p0f socket \"%s\", "
			       "skipping p0f", conf.c_p0fsock);
		log_disconnect = 0;
		return -1;
	}
	log_disconnect = 1;

	if (write(p0fsock, &req ,sizeof(req)) != sizeof(req)) {
		mg_log(LOG_ERR, "writing to \"%s\" failed", conf.c_p0fsock);
		goto bad;
	}

	if (read(p0fsock, &rep, sizeof(rep)) != sizeof(rep)) {
		mg_log(LOG_ERR, "reading from \"%s\" failed", conf.c_p0fsock);
		goto bad;
	}

	if (rep.magic != P0F_RESP_MAGIC) {
		mg_log(LOG_ERR, "Unexpected p0f magic = %d", rep.magic);
		goto bad;
	}

	switch(rep.status) {
	case P0F_STATUS_BADQUERY:
		mg_log(LOG_INFO, "p0f rejected query");
		goto bad;
		break;
	case P0F_STATUS_NOMATCH:
		mg_log(LOG_INFO, "p0f cache miss");
		priv->priv_p0f = strdup("unknown");
		return 0;
		break;
	case P0F_STATUS_OK:
		break;
	default:
		mg_log(LOG_INFO, "Unexpected p0f status %d", rep.status);
		goto bad;
		break;
	}

	/* +2 for space and trailing \0 */
	len = strlen((char *)rep.os_name) + strlen((char *)rep.os_flavor) + 2;
	if (len == 2) {
	if (conf.c_debug)
		mg_log(LOG_DEBUG, "unknown OS for p0f");
		return -1;
	}

	if ((priv->priv_p0f = malloc(len)) == NULL) {
		mg_log(LOG_ERR, "malloc(%d) failed: %s", len, strerror(errno));
		exit(EX_OSERR);
	}

	(void)sprintf(priv->priv_p0f, "%s %s", rep.os_name, rep.os_flavor);
	if (conf.c_debug)
		mg_log(LOG_DEBUG, "p0f identified \"%s\"", priv->priv_p0f);
	
	return 0;

bad:
	close(p0fsock);
	p0fsock = -1;
	return -1;
}
#endif /* HAVE_P0F3 */


void
p0f_sock_set(sock)
	char *sock;
{
	(void)strncpy(conf.c_p0fsock, sock, sizeof(conf.c_p0fsock));
	return;
}

static int
p0f_connect(void)
{
	struct sockaddr_un s_un;
	int p0fsock = -1;

	if (!conf.c_p0fsock[0])
		return -1;

	if ((p0fsock = socket(PF_UNIX,SOCK_STREAM,0)) == -1) {
		mg_log(LOG_ERR, "socket(PF_UNIX, SOCK_STREAM, 0) failed");
		exit(EX_OSERR);
	}

	if (p0fsock == -1) {
		mg_log(LOG_ERR, "p0f socket not initialized");
		exit(EX_SOFTWARE);
	}

	SET_CLOEXEC(p0fsock);

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "using p0f socket \"%s\"", conf.c_p0fsock);		
	(void)memset(&s_un, 0, sizeof(s_un));
	s_un.sun_family = AF_UNIX;
	strncpy(s_un.sun_path, conf.c_p0fsock, sizeof(s_un.sun_path));

	if (connect(p0fsock, (struct sockaddr *)&s_un, sizeof(s_un)) != 0) {
		mg_log(LOG_ERR, "Cannot connect to p0f socket \"%s\"",
		      conf.c_p0fsock);	
		close(p0fsock);
		return -1;
	}

	return p0fsock;
}

#endif /* USE_P0F */

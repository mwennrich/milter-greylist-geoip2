/* $Id: nsupdate.c,v 1.4 2016/01/31 05:35:38 manu Exp $ */

/*
 * Copyright (c) 2013 Emmanuel Dreyfus
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

#ifdef USE_NSUPDATE

#ifdef HAVE_SYS_CDEFS_H 
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id: nsupdate.c,v 1.4 2016/01/31 05:35:38 manu Exp $");
#endif
#endif

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sysexits.h>
#if defined(HAVE_OLD_QUEUE_H) || !defined(HAVE_SYS_QUEUE_H)
#include "queue.h"
#else 
#include <sys/queue.h>
#endif
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <res_update.h>

#include "spf.h"
#include "acl.h"
#include "store.h"

LIST_HEAD(tsig_head, tsig_entry) tsig_head =
    LIST_HEAD_INITIALIZER(tsig_head);
LIST_HEAD(nsupdate_head, nsupdate_entry) nsupdate_head =
    LIST_HEAD_INITIALIZER(nsupdate_head);

static struct nsupdate_entry g_nse;

void
nsupdate_init(void)
{
	(void)memset(&g_nse, 0, sizeof(g_nse));

	g_nse.nse_ttl = -1;
	g_nse.nse_class = -1;
	g_nse.nse_type = -1;

	return;
}

static const char const base64_translate[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1,  0, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

static int
base64_decode(str)
	char *str;
{
	int i;
	uint32_t res;
	char *cp;

	res = 0;
	cp = str;
	for (i = 0; str[i]; i++) {
		int translated;

		if ((translated = base64_translate[(int)(str[i])]) == -1)
			return -1;

		res |= (char)translated << (18 - (6 * (i % 4)));
		if (((i + 1) % 4) == 0) {
			*cp++ = (char)(res >> 16);
			*cp++ = (char)(res >> 8);
			*cp++ = (char)(res >> 0);
			res = 0;
		}
	} 

	if ((i % 4) != 0)
		return -1;

	return i * 3 / 4;
}

static void
nameserver_load(nse_res, nameservers)
	res_state nse_res;
	char *nameservers;
{
	union res_sockaddr_union servers[MAXNS];
	int servers_count = 0;
	char *lasts = NULL;
	char *s;

	for (s = strtok_r(nameservers, ",", &lasts);
	     s != NULL;
	     s = strtok_r(NULL, ",", &lasts)) {
#ifdef HAVE_GETADDRINFO
		struct addrinfo *ai;
		struct addrinfo *aip;
		struct addrinfo hint;
		int i, new;

		(void)memset(&hint, 0, sizeof(hint));
		hint.ai_socktype = SOCK_DGRAM;
	
		if (getaddrinfo(s, NULL, &hint, &ai) != 0) {
			mg_log(LOG_ERR, "getaddrinfo failed");
			exit(EX_OSERR);
		}

		for (aip = ai; aip; aip = aip->ai_next) {
			if (servers_count >= MAXNS)
				break;

			switch (ai->ai_family) {
			case AF_INET:
#ifdef AF_INET6
			case AF_INET6: /* FALLTHROUGH */
#endif /* AF_INET6 */
				if (aip->ai_addrlen > sizeof(*servers)) {
					mg_log(LOG_ERR, "socket len %d > %d",
					       aip->ai_addrlen,
					       sizeof(*servers));
					exit(EX_SOFTWARE);
				}

				new = 1;
				for (i = 0; i < servers_count; i++) {
					if (memcmp(&servers[i].sin,
						   aip->ai_addr,
						   aip->ai_addrlen) == 0) {
						new = 0;
						break;
					}
				}

				if (new)
					memcpy(&servers[servers_count++].sin,
					       aip->ai_addr, aip->ai_addrlen);
				break;
			default:
				break;
			}
		}

		freeaddrinfo(ai);

#else /* HAVE_GETADDRINFO */
		if (servers_count >= MAXNS)
			break;

		/* IPv4 numeric address only */
		if (inet_aton(s, &servers[servers_count].sin.sin_addr) == 1) {
			servers[servers_count].sin.sin_family = AF_INET;
			servers[servers_count].sin.sin_port = NS_DEFAULTPORT;
#ifdef HAVE_SA_LEN
			servers[servers_count].sin.sin_len =
			    sizeof(servers[servers_count].sin);
#endif
			servers_count++;
		}
#endif /* HAVE_GETADDRINFO */
	}

	if (servers_count > 0) {
		res_setservers(nse_res, servers, servers_count);
	} else {
		mg_log(LOG_ERR, "Could not load server list \"%s\"",
		       nameservers);
		exit(EX_DATAERR);
	}
	
	return;
}


int
tsig_add(name, alg, key)
	char *name;
	char *alg;
	char *key;
{
	struct tsig_entry *tse;
	int keylen;

	if (tsig_byname(name) != NULL) {
		mg_log(LOG_ERR, "tsig \"%s\" specified twice", name);
		return -1;
	}

	if ((tse = malloc(sizeof(*tse))) == NULL) {
		mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	(void)strncpy(tse->tse_tsig.name, name, sizeof(tse->tse_tsig.name));

	if (strcmp(alg, "hmac-md5") == 0)
		alg = NS_TSIG_ALG_HMAC_MD5;
	(void)strncpy(tse->tse_tsig.alg, alg, sizeof(tse->tse_tsig.alg));

	if ((keylen = base64_decode(key)) == -1) {
		mg_log(LOG_ERR, "base64 tsig data is corrupted, ignoring");
		free(tse);
		return -1;
	}

	if ((tse->tse_tsig.data = malloc(keylen)) == NULL) {
		mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	(void)memcpy(tse->tse_tsig.data, key, keylen);
	tse->tse_tsig.len = keylen;

	LIST_INSERT_HEAD(&tsig_head, tse, tse_list);

	return 0;
}

struct ns_tsig_key *
tsig_byname(name)
	char *name;
{
	struct tsig_entry *tse;

	LIST_FOREACH(tse, &tsig_head, tse_list)
		if (strcmp(tse->tse_tsig.name, name) == 0)
			break;

	return &tse->tse_tsig;
}

void
tsig_clear(void)
{
	struct tsig_entry *tse;

	while ((tse = LIST_FIRST(&tsig_head)) != NULL) {
		free(tse->tse_tsig.data);
		free(tse);
		LIST_REMOVE(tse, tse_list);
	}
}


int
nsupdate_add_servers(servers)
	char *servers;
{
	if (g_nse.nse_servers) {
		mg_log(LOG_ERR, "nsupdate servers already specified");
		return -1;
	}

	if ((g_nse.nse_servers = strdup(servers)) == NULL) {
		mg_log(LOG_ERR, "strdup failed");
		return -1;
	}

	return 0;
}

int
nsupdate_add_rname(rname)
	char *rname;
{
	if (g_nse.nse_rname) {
		mg_log(LOG_ERR, "nsupdate rname already specified");
		return -1;
	}

	if ((g_nse.nse_rname = strdup(rname)) == NULL) {
		mg_log(LOG_ERR, "strdup failed");
		return -1;
	}

	return 0;
}

int
nsupdate_add_rvalue(rvalue)
	char *rvalue;
{
	if (g_nse.nse_rvalue) {
		mg_log(LOG_ERR, "nsupdate rvalue already specified");
		return -1;
	}

	if ((g_nse.nse_rvalue = strdup(rvalue)) == NULL) {
		mg_log(LOG_ERR, "strdup failed");
		return -1;
	}

	return 0;
}

int
nsupdate_add_ttl(ttl)
	int ttl;
{
	if (g_nse.nse_ttl != -1) {
		mg_log(LOG_ERR, "nsupdate ttl already specified");
		return -1;
	}

	g_nse.nse_ttl = ttl;

	return 0;
}

int
nsupdate_add_class(class)
	int class;
{
	if (g_nse.nse_class != -1) {
		mg_log(LOG_ERR, "nsupdate class already specified");
		return -1;
	}

	g_nse.nse_class = class;

	return 0;
}

int
nsupdate_add_type(type)
	int type;
{
	if (g_nse.nse_type != -1) {
		mg_log(LOG_ERR, "nsupdate type already specified");
		return -1;
	}

	g_nse.nse_type = type;

	return 0;
}


int
nsupdate_add_tsig(tsig)
	char *tsig;
{
	if (g_nse.nse_tsig) {
		mg_log(LOG_ERR, "nsupdate tsig already specified");
		return -1;
	}

	if ((g_nse.nse_tsig = tsig_byname(tsig)) == NULL) {
		mg_log(LOG_ERR, "nsupdate tsig \"%s\" not found", tsig);
		return -1;
	}

	return 0;
};

int
nsupdate_add(name)
	char *name;
{
	struct nsupdate_entry *nse;

	if (nsupdate_byname(name) != NULL) {
		mg_log(LOG_ERR, "nsupdate \"%s\" specified twice", name);
		return -1;
	}

	if ((g_nse.nse_rname == NULL) || (g_nse.nse_rvalue == NULL)) {
		mg_log(LOG_ERR, "nsupdate needs at least rname and rvalue");	
		return -1;
	}

	if (g_nse.nse_ttl == -1)
		g_nse.nse_ttl = 0;

	if (g_nse.nse_class == -1)
		g_nse.nse_class = ns_c_in;

	if (g_nse.nse_type == -1)
		g_nse.nse_type = ns_t_a;

	if ((nse = malloc(sizeof(*nse))) == NULL) {
		mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if ((nse->nse_res = calloc(sizeof(*nse->nse_res), 1)) == NULL) {
		mg_log(LOG_ERR, "calloc() failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if (res_ninit(nse->nse_res) != 0) {
		mg_log(LOG_ERR, "res_ninit() failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if ((nse->nse_name = strdup(name)) == NULL) {
		mg_log(LOG_ERR, "strdup() failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	nse->nse_rname = g_nse.nse_rname;
	nse->nse_rvalue = g_nse.nse_rvalue;
	nse->nse_ttl = g_nse.nse_ttl;
	nse->nse_class = g_nse.nse_class;
	nse->nse_type = g_nse.nse_type;
	nse->nse_tsig = g_nse.nse_tsig;;

	/* If unspecified, defaults from /etc/resolv.conf are used */
	if (g_nse.nse_servers) {
		nameserver_load(nse->nse_res, g_nse.nse_servers);
		free(g_nse.nse_servers);
		g_nse.nse_servers = NULL;
	}

	LIST_INSERT_HEAD(&nsupdate_head, nse, nse_list);

	nsupdate_init();

	return 0;
}

int 
nsupdate_filter(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	struct nsupdate_entry *nse;
	struct ns_updrec updrec;
 
        nse = ad->nsupdate;

	(void)memset(&updrec, 0, sizeof(updrec));

	updrec.r_section = S_UPDATE;
	updrec.r_dname = fstring_expand(priv, NULL, nse->nse_rname, NULL);
	updrec.r_class = nse->nse_class;
	updrec.r_type = nse->nse_type;
	updrec.r_ttl = nse->nse_ttl;
	updrec.r_data = 
	    (unsigned char *)fstring_expand(priv, NULL, nse->nse_rvalue, NULL);
	updrec.r_size = strlen((char *)updrec.r_data);
	updrec.r_opcode = ADD; 
	
	if (res_nupdate(nse->nse_res, &updrec, nse->nse_tsig) == -1)
		mg_log(LOG_ERR, "nsnupdate \"%s\" failed \"%s\" -> \"%s\"",
		       updrec.r_dname, updrec.r_data);
	
	free(updrec.r_dname);
	free(updrec.r_data);

	/* always match */
	return 1; 
}


struct nsupdate_entry *
nsupdate_byname(name)
	char *name;
{
	struct nsupdate_entry *nse;

	LIST_FOREACH(nse, &nsupdate_head, nse_list)
		if (strcmp(nse->nse_name, name) == 0)
			break;

	return nse;
}

void
nsupdate_clear(void)
{
	struct nsupdate_entry *nse;

	while ((nse = LIST_FIRST(&nsupdate_head)) != NULL) {
		res_ndestroy(nse->nse_res);
		free(nse->nse_res);
		free(nse->nse_name);
		free(nse->nse_rname);
		free(nse->nse_rvalue);
		if (nse->nse_servers)
			free(nse->nse_servers);
		free(nse);
		LIST_REMOVE(nse, nse_list);
	}
}

#endif /* USE_NSUPDATE */

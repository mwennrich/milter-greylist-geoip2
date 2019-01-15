#include "config.h"

#ifdef USE_MX

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID

#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>            /* bzero, ... */
#endif
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
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#ifndef NS_MAXMSG
#define NS_MAXMSG	65535
#endif

#ifdef HAVE_RES_NINIT
#ifndef HAVE_RES_NDESTROY
#define res_ndestroy(res)	res_nclose(res)
#endif
#else
#define	res_ninit(res) \
	((_res.options & RES_INIT) == 0 && res_init())
#define res_nquery(res, req, class, type, ans, anslen)	\
	res_query(req, class, type, ans, anslen)
#define res_ndestroy(res)
#endif

#include "milter-greylist.h"
#include "pending.h"
#include "conf.h"
#include "mx.h"

#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif

/* 
 * locking is done through the same lock as acllist: both are static 
 * configuration, which are read or changed at the same times.
 */

int
mx_check(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{


	struct sockaddr *sa;
	socklen_t salen;
#ifdef HAVE_RES_NINIT
	struct __res_state res;
#endif
	char req[NS_MAXDNAME + 1];
/*	unsigned char *ans = NULL; */
	int anslen;
	ns_msg handle, handle2;
	ns_rr rr, rr2;
	int qtype, i, j;
	int mxcidr;
/*	struct sockaddr *blacklisted; */
	struct sockaddr_storage result, result2;
	int retval = 0;
	char *from, *fromdomain, *fd;
	uint32_t *mxaddr, *saaddr;
	size_t len;
	ipaddr m_mask;
	struct timeval tv1, tv2, tv3;
	char str[INET_ADDRSTRLEN];
	unsigned char ans[NS_MAXMSG + 1];
	unsigned char ans2[NS_MAXMSG + 1];


	sa = SA(&priv->priv_addr);
	salen = priv->priv_addrlen;
	from = priv->priv_from;
	mxcidr = ad->mx_cidr;


	switch (sa->sa_family) {
	case AF_INET:
		qtype = T_A;
		len = sizeof(*SADDR4(sa));
		saaddr = (uint32_t *)&(SADDR4(&result2)->s_addr);
		memcpy(saaddr, SADDR4(sa), len);
		prefix2mask4(mxcidr, &m_mask.in4);
		*saaddr &= m_mask.in4.s_addr;
		break;
#ifdef AF_INET6
	case AF_INET6:
		qtype = T_AAAA;
		len = sizeof(*SADDR6(sa));
		saaddr = (uint32_t *)&(SADDR6(&result2)->s6_addr);
		memcpy(saaddr, SADDR6(sa), len);
		prefix2mask6(mxcidr, &m_mask.in6);
		for (i = 0; i < 16; i += 4)
			saaddr[i] &= *(uint32_t *)&m_mask.in6.s6_addr[i];
		break;
#endif
	default:
		mg_log(LOG_ERR, "unexpected address family %d", sa->sa_family);
		exit(EX_SOFTWARE);
		break;
	}


#ifdef HAVE_RES_NINIT
	bzero(&res, sizeof(res));
#endif
	if (res_ninit(&res) != 0) {
		mg_log(LOG_DEBUG, "res_ninit failed: %s", strerror(errno));
		return 0;
	}


	/* strip through '@' in 'from' address, skipping leading '<'s and
	   trailing '>'s						  */
	for (fromdomain = from;
	     *fromdomain != '@' && *fromdomain != '\0'; fromdomain++);
	if (*fromdomain++ == '\0') {
		mg_log(LOG_WARNING, "not a valid email address: %s", from);
		goto end;
	}
        for (fd = fromdomain; *fd != '>' && *fd != '\0'; fd++);
	*fd = '\0';

	if (conf.c_debug)
	gettimeofday(&tv1, NULL);

	/* Get domain names for each MX record */
	anslen =
		res_nquery(&res, fromdomain, C_IN, T_MX, ans, NS_MAXMSG + 1);

	if (conf.c_debug) {
	gettimeofday(&tv2, NULL);
	timersub(&tv2, &tv1, &tv3);
	mg_log(LOG_DEBUG, "MX lookup for domain %s performed in %ld.%06lds",
	       fromdomain, tv3.tv_sec, tv3.tv_usec);
	}

	if (anslen == -1)
		goto end;

	if (ns_initparse(ans, anslen, &handle) < 0) {
		mg_log(LOG_DEBUG, "ns_initparse failed: %s", strerror(errno));
		goto end;
	}

	for (i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
		if ((ns_parserr(&handle, ns_s_an, i, &rr)) != 0) {
			mg_log(LOG_DEBUG, "ns_parserr failed: %s", strerror(errno));
			goto end;
		}
		if (ns_rr_type(rr) != T_MX)
			continue;


		/* Uncompress the received mx server's domain name */
		if (ns_name_uncompress(ns_msg_base(handle),     /* Start of the message */
				       ns_msg_end(handle),      /* End of the message   */
				       ns_rr_rdata(rr) + 2,     /* Position in the message, skip prio # */
				       req,                     /* Result                       */
				       NS_MAXDNAME)             /* Size of nsList buffer    */
		    < 0) {                                      /* Negative: error      */
			mg_log(LOG_WARNING, "ns_name_uncompress failed: %s", strerror(errno));
			goto end;
		}

	/* Now look for the IP addresses that go with each mx host name */
	if (conf.c_debug)
		gettimeofday(&tv1, NULL);

		anslen =
			res_nquery(&res, req, C_IN, qtype, ans2,
				   NS_MAXMSG + 1);

		if (conf.c_debug) {
		gettimeofday(&tv2, NULL);
		timersub(&tv2, &tv1, &tv3);
		mg_log(LOG_DEBUG, "MX host lookup %s performed in %ld.%06lds",
		       req, tv3.tv_sec, tv3.tv_usec);
		}

		if (anslen == -1)
			continue;

		if (ns_initparse(ans2, anslen, &handle2) < 0) {
			mg_log(LOG_ERR, "ns_initparse failed: %s", strerror(errno));
			goto end;
		}

		for (j = 0; j < ns_msg_count(handle2, ns_s_an); j++) {
			if ((ns_parserr(&handle2, ns_s_an, j, &rr2)) != 0) {
				mg_log(LOG_ERR, "ns_parserr failed: %s",
				       strerror(errno));
				goto end;
			}


			if (ns_rr_rdlen(rr2) != len) {
				printf
				("ignored MX answer with unexpected length");
				continue;
			}

			switch (sa->sa_family) {
			case AF_INET:
				if (ns_rr_type(rr2) != T_A)
					continue;
				mxaddr =
					(uint32_t *)&(SADDR4(&result)->
						      s_addr);
				memcpy(mxaddr, ns_rr_rdata(rr2), len);

				inet_ntop(AF_INET, mxaddr, str,
					  INET_ADDRSTRLEN);
				if (conf.c_debug)
					mg_log(LOG_DEBUG, "found MX server %s (%s)", req,
					       str);

				*mxaddr &= m_mask.in4.s_addr;
				break;
#ifdef AF_INET6
			case AF_INET6:
				if (ns_rr_type(rr2) != T_AAAA)
					continue;
				mxaddr =
					(uint32_t *)&(SADDR6(&result)->
						      s6_addr);
				memcpy(mxaddr, ns_rr_rdata(rr2), len);

				inet_ntop(AF_INET6, mxaddr, str,
					  INET_ADDRSTRLEN);
				if (conf.c_debug)
					mg_log(LOG_DEBUG, "found MX server %s (%s)", req,
					       str);

				for (i = 0; i < 16; i += 4)
					mxaddr[i] &=
						*(uint32_t *)&m_mask.in6.
						s6_addr[i];
				break;
#endif
			default:
				mg_log(LOG_ERR, "unexpected sa_family");
				exit(EX_SOFTWARE);
				break;
			}

			if (memcmp(saaddr, mxaddr, len) == 0) {
				retval = 1;
				goto end;
			}
		}	// end for each hostname loop
	}	// end for each mx record loop
 end:
	if (retval == 1) {
		if (conf.c_debug) {
		char addrstr[NS_MAXDNAME + 1];

		iptostring(sa, salen, addrstr, sizeof(addrstr));
		mg_log(LOG_DEBUG,"connecting host %s matches MX record %s (%s/%d)",
		 addrstr, req, str, mxcidr);
		}
	}

	res_ndestroy(&res);
	return retval;
}

#endif /* USE_MX */

/* $Id: geoip.c,v 1.7 2016/11/24 04:11:37 manu Exp $ */

/*
 * Copyright (c) 2007 Emmanuel Dreyfus
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

#ifdef USE_GEOIP

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id");
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sysexits.h>
#include <sys/param.h>

#include <GeoIP.h>

#include "milter-greylist.h"
#include "conf.h"
#include "geoip.h"

#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif

static GeoIP *geoip_handle = NULL;
static GeoIP *geoip_handle_v6 = NULL;
static char geoip_database[MAXPATHLEN + 1];
static char geoip_database_v6[MAXPATHLEN + 1];
static pthread_rwlock_t geoip_lock;

void
geoip_init(void)
{
	int error;

	if ((error = pthread_rwlock_init(&geoip_lock, NULL)) != 0) {
		mg_log(LOG_ERR, "pthread_rwlock_init failed: %s", 
		    strerror(error));
		exit(EX_OSERR);
	}

	return;
}

void
geoip_set_db(name)
	char *name;
{
	if (geoip_handle != NULL) {
		GeoIP_delete(geoip_handle);
		geoip_handle = NULL;
	}
	
	strncpy(geoip_database, name, MAXPATHLEN);
	geoip_database[MAXPATHLEN] = '\0';

	geoip_handle = GeoIP_open(geoip_database, GEOIP_STANDARD);
	if (geoip_handle == NULL) {
		mg_log(LOG_WARNING, 
		    "GeoIP databade \"%s\" cannot be used",
		    geoip_database);
		return;
	}
}

void
geoip_set_db_v6(name)
	char *name;
{
	if (geoip_handle_v6 != NULL) {
		GeoIP_delete(geoip_handle_v6);
		geoip_handle_v6 = NULL;
	}

	strncpy(geoip_database_v6, name, MAXPATHLEN);
	geoip_database_v6[MAXPATHLEN] = '\0';

	geoip_handle_v6 = GeoIP_open(geoip_database_v6, GEOIP_STANDARD);
	if (geoip_handle_v6 == NULL) {
		mg_log(LOG_WARNING,
		    "GeoIPv6 databade \"%s\" cannot be used",
		    geoip_database_v6);
		return;
	}
}

int
geoip_filter(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	char *ccode = ad->string;

	if (priv->priv_ccode == NULL)
		return 0;

	if (strcmp(ccode, priv->priv_ccode) == 0)
		return 1;
	else
		return 0;
}

void
geoip_set_ccode(priv)
	struct mlfi_priv *priv;
{
	GEOIP_API const char *(*country_code_by_addr)(GeoIP *, const char *);
	GeoIP *handle;
	char ipstr[IPADDRSTRLEN];

	switch (SA(&priv->priv_addr)->sa_family) {
	case AF_INET:
		country_code_by_addr = GeoIP_country_code_by_addr;
		handle = geoip_handle;
		break;
#ifdef AF_INET6
	case AF_INET6:
		country_code_by_addr = GeoIP_country_code_by_addr_v6;
		handle = geoip_handle_v6;
		break;
#endif
	default:
		mg_log(LOG_DEBUG, "GeoIP not supported address family");
		priv->priv_ccode = NULL;
		return;
	}

	if (geoip_handle == NULL) {
		mg_log(LOG_DEBUG, "GeoIP is not available");
		priv->priv_ccode = NULL;
		return;
	}

	if (iptostring(SA(&priv->priv_addr),
	    priv->priv_addrlen, ipstr, sizeof(ipstr)) == NULL) {
		mg_log(LOG_DEBUG, "GeoIP iptostring failed");
		priv->priv_ccode = NULL;
		return;
	}

	WRLOCK(geoip_lock);
	priv->priv_ccode = country_code_by_addr(handle, ipstr);
	UNLOCK(geoip_lock);

	if (priv->priv_ccode == NULL)
		priv->priv_ccode = "ZZ";

	return;
}

#endif /* USE_GEOIP */

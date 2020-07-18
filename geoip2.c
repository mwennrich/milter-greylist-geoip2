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

#ifdef USE_GEOIP2

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

#include "milter-greylist.h"
#include "conf.h"
#include "geoip2.h"

#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif

#include <maxminddb.h>

static MMDB_s mmdb;
static MMDB_s *geoip2_handle = &mmdb;
static char geoip2_database[MAXPATHLEN + 1];
static pthread_rwlock_t geoip2_lock;

void
geoip2_init(void)
{
	int error;

	if ((error = pthread_rwlock_init(&geoip2_lock, NULL)) != 0) {
		mg_log(LOG_ERR, "pthread_rwlock_init failed: %s", 
		    strerror(error));
		exit(EX_OSERR);
	}

	return;
}

void
geoip2_set_db(name)
	char *name;
{
	if (geoip2_handle != NULL) {
		MMDB_close(geoip2_handle);
	}
	
	strncpy(geoip2_database, name, MAXPATHLEN);
	geoip2_database[MAXPATHLEN] = '\0';

	int status = MMDB_open(geoip2_database, MMDB_MODE_MMAP, geoip2_handle);
	if (status != MMDB_SUCCESS) {
		mg_log(LOG_WARNING, 
		    "Geoip2 database \"%s\" cannot be used",
		    geoip2_database);
		return;
	}
}

int
geoip2_filter(ad, stage, ap, priv)
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
geoip2_set_ccode(priv)
	struct mlfi_priv *priv;
{
	char ipstr[IPADDRSTRLEN];
        int gai_error, mmdb_error;

	if (iptostring(SA(&priv->priv_addr),
	    priv->priv_addrlen, ipstr, sizeof(ipstr)) == NULL) {
		mg_log(LOG_DEBUG, "Geoip2 iptostring failed");
		priv->priv_ccode = NULL;
		return;
	}

	WRLOCK(geoip2_lock);
	MMDB_lookup_result_s result = MMDB_lookup_string(geoip2_handle, ipstr, &gai_error, &mmdb_error);
	if (gai_error == 0) {
		if (mmdb_error == MMDB_SUCCESS) {
			MMDB_entry_data_s entry_data;
			int status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
			if (status == MMDB_SUCCESS) {
				if (entry_data.has_data) {
					priv->priv_ccode = strndup(entry_data.utf8_string, entry_data.data_size);
				}
			}
		}
        }

	UNLOCK(geoip2_lock);

	if (priv->priv_ccode == NULL)
		priv->priv_ccode = "ZZ";

	return;
}

#endif /* USE_GEOIP2 */

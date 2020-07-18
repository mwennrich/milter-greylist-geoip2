/* $Id: milter-greylist.c,v 1.283 2016/11/24 03:59:40 manu Exp $ */

/*
 * Copyright (c) 2004-2012 Emmanuel Dreyfus
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
__RCSID("$Id: milter-greylist.c,v 1.283 2016/11/24 03:59:40 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <string.h>
#include <libgen.h>

/* On IRIX, <unistd.h> defines a EX_OK that clashes with <sysexits.h> */
#ifdef EX_OK
#undef EX_OK
#endif
#include <sysexits.h>

#if HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#ifdef USE_DRAC
#ifdef USE_DB185_EMULATION
#include <db_185.h>
#else
#include <db.h>
#endif
static int check_drac(char *dotted_ip);
#endif

#include <libmilter/mfapi.h>

#include "dump.h"
#include "spf.h"
#include "acl.h"
#include "list.h"
#include "conf.h"
#include "pending.h"
#include "sync.h"
#include "store.h"
#include "stat.h"
#include "milter-greylist.h"
#include "brokenmfapi.h"
#ifdef USE_DNSRBL
#include "dnsrbl.h"
#endif
#ifdef USE_CURL
#include "urlcheck.h"
#endif
#ifdef USE_LDAP
#include "ldapcheck.h"
#endif
#ifdef USE_DKIM
#include "dkimcheck.h"
#endif
#include "prop.h"
#ifdef USE_GEOIP
#include "geoip.h"
#endif
#ifdef USE_GEOIP2
#include "geoip2.h"
#endif
#ifdef USE_P0F
#include "p0f.h"
#endif
#include "macro.h"
#include "ratelimit.h"
#ifdef USE_NSUPDATE
#include "nsupdate.h"
#endif

#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif

#ifndef PACKAGE_URL
#define PACKAGE_URL ""
#endif

static char *gmtoffset(time_t *, char *, size_t);
static void writepid(char *);
static void log_and_report_greylisting(SMFICTX *, struct mlfi_priv *, char *);
static void reset_acl_values(struct mlfi_priv *);
static void smtp_reply_init(struct smtp_reply *);
static void smtp_reply_free(struct smtp_reply *);
static void add_recipient(struct mlfi_priv *, char *);
static void set_sr_defaults(struct mlfi_priv *, char *, char *, char *);
static sfsistat tarpit_reentry(struct mlfi_priv *);
static sfsistat stat_from_code(char *);
static void cleanup_pidfile(char *);
static void cleanup_sock(char *);
static int mg_setreply(SMFICTX *, struct mlfi_priv *, char *);
static int resolve_bracketed(char *addr);
static sfsistat real_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat real_helo(SMFICTX *, char *);
static sfsistat real_envfrom(SMFICTX *, char **);
static sfsistat real_envrcpt(SMFICTX *, char **);
static sfsistat real_header(SMFICTX *, char *, char *);
static sfsistat real_eoh(SMFICTX *);
static sfsistat real_body(SMFICTX *, unsigned char *, size_t);
static sfsistat real_eom(SMFICTX *);
static sfsistat real_abort(SMFICTX *);
static sfsistat real_close(SMFICTX *);
#ifdef HAVE_DATA_CALLBACK
static sfsistat real_data(SMFICTX *);
#endif

struct smfiDesc smfilter =
{
	"greylist",	/* filter name */
	SMFI_VERSION,	/* version code */
	SMFIF_CHGHDRS|SMFIF_ADDHDRS|SMFIF_CHGBODY,	/* flags */
	mlfi_connect,	/* connection info filter */
	mlfi_helo,	/* SMTP HELO command filter */
	mlfi_envfrom,	/* envelope sender filter */
	mlfi_envrcpt,	/* envelope recipient filter */
	mlfi_header,	/* header filter */
	mlfi_eoh,	/* end of header */
	mlfi_body,	/* body block filter */
	mlfi_eom,	/* end of message */
	mlfi_abort,	/* message aborted */
	mlfi_close,	/* connection cleanup */
#ifdef HAVE_DATA_CALLBACK
	NULL,		/* any unrecognized or unimplemented command filter */
	mlfi_data,	/* SMTP DATA command filter */
#endif
};

static int nodetach = 0;

sfsistat
mlfi_connect(ctx, hostname, addr)
	SMFICTX *ctx;
	char *hostname;
	_SOCK_ADDR *addr;
{
	sfsistat r;

	conf_retain();
	r = real_connect(ctx, hostname, addr);
	conf_release();
	return r;
}

sfsistat
mlfi_helo(ctx, helostr)
	SMFICTX *ctx;
	char *helostr;
{
	sfsistat r;

	conf_retain();
	r = real_helo(ctx, helostr);
	conf_release();
	return r;
}

sfsistat
mlfi_envfrom(ctx, envfrom)
	SMFICTX *ctx;
	char **envfrom;
{
	sfsistat r;

	/*
	 * Reload the config file if it has been touched
	 */
	conf_update();
	conf_retain();
	r = real_envfrom(ctx, envfrom);
	conf_release();
	return r;
}

sfsistat
mlfi_envrcpt(ctx, envrcpt)
	SMFICTX *ctx;
	char **envrcpt;
{
	sfsistat r;

	conf_retain();
	r = real_envrcpt(ctx, envrcpt);
	conf_release();
	return r;
}

sfsistat
mlfi_header(ctx, header, value)
	SMFICTX *ctx;
	char *header;
	char *value;
{
	sfsistat r;

	conf_retain();
	r = real_header(ctx, header, value);
	conf_release();
	return r;
}

sfsistat
mlfi_eoh(ctx)
	SMFICTX *ctx;
{
	sfsistat r;

	conf_retain();
	r = real_eoh(ctx);
	conf_release();
	return r;
}

sfsistat
mlfi_body(ctx, chunk, size)
	SMFICTX *ctx;
	unsigned char *chunk;
	size_t size;
{
	sfsistat r;

	conf_retain();
	r = real_body(ctx, chunk, size);
	conf_release();
	return r;
}

sfsistat
mlfi_eom(ctx)
	SMFICTX *ctx;
{
	sfsistat r;

	conf_retain();
	r = real_eom(ctx);
	conf_release();
	return r;
}

sfsistat
mlfi_abort(ctx)
	SMFICTX *ctx;
{
	sfsistat r;

	conf_retain();
	r = real_abort(ctx);
	conf_release();
	return r;
}

sfsistat
mlfi_close(ctx)
	SMFICTX *ctx;
{
	sfsistat r;

	conf_retain();
	r = real_close(ctx);
	conf_release();
	return r;
}

#ifdef HAVE_DATA_CALLBACK
sfsistat
mlfi_data(ctx)
	SMFICTX *ctx;
{
	sfsistat r;

	conf_retain();
	r = real_data(ctx);
	conf_release();
	return r;
}
#endif

static sfsistat
tarpit_reentry(priv)
	struct mlfi_priv *priv;
{
	struct tuple_fields tuple;

	sfsistat stat = SMFIS_CONTINUE;

	if (!(priv->priv_sr.sr_whitelist & EXF_TARPIT))
		return stat;

	if (priv->priv_sr.sr_whitelist & EXF_WHITELIST) {

		tuple.sa = SA(&priv->priv_addr);
		tuple.salen = priv->priv_addrlen;
		tuple.from = priv->priv_from;
		tuple.rcpt = priv->priv_rcpt.lh_first->r_addr;
		tuple.autowhite = 0;
		tuple.updatetype = TU_AUTOWHITE;

		mg_tuple_update(&tuple);

	} else if (priv->priv_sr.sr_whitelist & EXF_GREYLIST) {
		stat = SMFIS_TEMPFAIL;
	}

	return stat;
}

static sfsistat
real_connect(ctx, hostname, addr)
	SMFICTX *ctx;
	char *hostname;
	_SOCK_ADDR *addr;
{
	struct mlfi_priv *priv;

	if ((priv = malloc(sizeof(*priv))) == NULL) {
		mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
		return SMFIS_TEMPFAIL;	
	}

	smfi_setpriv(ctx, priv);
	bzero((void *)priv, sizeof(*priv));
	priv->priv_ctx = ctx;
	smtp_reply_init(&priv->priv_sr);
	LIST_INIT(&priv->priv_rcpt);
	priv->priv_cur_rcpt[0] = '\0';
	priv->priv_rcptcount = 0;
	TAILQ_INIT(&priv->priv_header);
	TAILQ_INIT(&priv->priv_body);
	priv->priv_maxpeek = conf.c_maxpeek;
	priv->priv_msgcount = 0;
	priv->priv_peekcount = 0;
	priv->priv_peekdone = 0;
	priv->priv_buf = NULL;
	priv->priv_buflen = 0;
	priv->priv_max_elapsed = 0;
	priv->priv_last_whitelist = EXF_NONE;

	strncpy(priv->priv_hostname, hostname, ADDRLEN);
	priv->priv_hostname[ADDRLEN] = '\0';

	if ((priv->priv_hostname[0] == '[') && conf.c_unbracket)
		(void)resolve_bracketed(priv->priv_hostname);

	if (addr != NULL) {
		switch (addr->sa_family) {
		case AF_INET:
			priv->priv_addrlen = sizeof(struct sockaddr_in);
			memcpy(&priv->priv_addr, addr, priv->priv_addrlen);
#ifdef HAVE_SA_LEN
			/* XXX: sendmail doesn't set sa_len */
			SA4(&priv->priv_addr)->sin_len = priv->priv_addrlen;
#endif
			break;
#ifdef AF_INET6
		case AF_INET6:
			priv->priv_addrlen = sizeof(struct sockaddr_in6);
			memcpy(&priv->priv_addr, addr, priv->priv_addrlen);
#ifdef SIN6_LEN
			/* XXX: sendmail doesn't set sa_len */
			SA6(&priv->priv_addr)->sin6_len = priv->priv_addrlen;
#endif
			unmappedaddr(SA(&priv->priv_addr),
			    &priv->priv_addrlen);
			break;
#endif
		default:
			priv->priv_sr.sr_elapsed = 0;
			priv->priv_sr.sr_whitelist = 
			    EXF_WHITELIST | EXF_NONIP;
			break;
		}
	} else {
		priv->priv_sr.sr_elapsed = 0;
		priv->priv_sr.sr_whitelist = EXF_WHITELIST | EXF_NONIP;
	}

#ifdef USE_GEOIP
	geoip_set_ccode(priv);
#endif
#ifdef USE_GEOIP2
	geoip2_set_ccode(priv);
#endif
#ifdef HAVE_SPF2
	priv->priv_spf_header = NULL;
#endif
#if (defined(HAVE_SPF) || defined(HAVE_SPF_ALT) || \
     defined(HAVE_SPF2_10) || defined(HAVE_SPF2))
	priv->priv_spf_result[0] = '\0';
#endif
#ifdef USE_DKIM
	priv->priv_dkim = NULL;
	priv->priv_dkimstat = DKIM_STAT_OK;
	priv->priv_dkim_result[0] = '\0';
#endif
#ifdef USE_P0F
	priv->priv_p0f = NULL;
	p0f_lookup(priv);
#endif
	LIST_INIT(&priv->priv_prop);
	priv->priv_prop_match = NULL;
	priv->priv_max_tarpitted = 0;
	priv->priv_total_tarpitted = 0;

	return SMFIS_CONTINUE;
}

static sfsistat
real_helo(ctx, helostr)
	SMFICTX *ctx;
	char *helostr;
{
	struct mlfi_priv *priv;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

	strncpy_rmsp(priv->priv_helo, helostr, ADDRLEN);
	priv->priv_helo[ADDRLEN] = '\0';

	return SMFIS_CONTINUE;
}


static sfsistat
real_envfrom(ctx, envfrom)
	SMFICTX *ctx;
	char **envfrom;
{
	char tmpfrom[ADDRLEN + 1];
	char *idx;
	struct mlfi_priv *priv;
	char *auth_authen;
	char *verify;
	char *cert_subject;
	struct rcpt *r;
	struct line *l;

	if ((priv = (struct mlfi_priv *) smfi_getpriv(ctx)) == NULL) {
		mg_log(LOG_ERR, "Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

	/* 
	 * First cleanup anything we still know about a previous
	 * message we received in the same SMTP session.
	 */
	reset_acl_values(priv);

	while ((r = LIST_FIRST(&priv->priv_rcpt)) != NULL) {
		LIST_REMOVE(r, r_list);
		free(r);
	}
	while ((l = TAILQ_FIRST(&priv->priv_header)) != NULL) {
		free(l->l_line);
		TAILQ_REMOVE(&priv->priv_header, l, l_list);
		free(l);
	}
	while ((l = TAILQ_FIRST(&priv->priv_body)) != NULL) {
		free(l->l_line);
		TAILQ_REMOVE(&priv->priv_body, l, l_list);
		free(l);
	}
	if (priv->priv_buf)
		free(priv->priv_buf);
	priv->priv_msgcount = 0;
	priv->priv_peekcount = 0;
	priv->priv_peekdone = 0;

#ifdef USE_SPAMD
	priv->priv_spamd_flags = 0;
#endif

	/*
	 * Save unchanged from address for rawfrom ACL clauses.
	 */
	strncpy(priv->priv_rawfrom, *envfrom, ADDRLEN);
	priv->priv_rawfrom[ADDRLEN] = '\0';

	/*
	 * Strip spaces from the source address
	 */
	strncpy_rmsp(tmpfrom, *envfrom, ADDRLEN);
	tmpfrom[ADDRLEN] = '\0';

	/* 
	 * Strip anything before the last '=' in the
	 * source address. This avoid problems with
	 * mailing lists using a unique sender address
	 * for each retry.
	 */
	if ((idx = rindex(tmpfrom, '=')) == NULL)
		idx = tmpfrom;

	strncpy(priv->priv_from, idx, ADDRLEN);
	priv->priv_from[ADDRLEN] = '\0';

	/*
	 * If we stripped bytes prior '=' then we
	 * need to restore the leading '<'
	 */
	if (idx != tmpfrom)
		priv->priv_from[0] = '<';
	
	/*
	 * Is the sender non-IP?
	 */
	if (priv->priv_sr.sr_whitelist & EXF_NONIP)
		return SMFIS_CONTINUE;

	/*
	 * Is the user authenticated?
	 */
	if ((conf.c_noauth == 0) &&
	    ((auth_authen = smfi_getsymval(ctx, "{auth_authen}")) != NULL)) {
		mg_log(LOG_DEBUG, 
		    "User %s authenticated, bypassing greylisting", 
		    auth_authen);
		priv->priv_sr.sr_elapsed = 0;
		priv->priv_sr.sr_whitelist = EXF_WHITELIST | EXF_AUTH;

		return SMFIS_CONTINUE;
	} 

	/* 
	 * STARTTLS authentication?
	 */
	if ((conf.c_noauth == 0) &&
	    ((verify = smfi_getsymval(ctx, "{verify}")) != NULL) &&
	    (strcmp(verify, "OK") == 0) &&
	    ((cert_subject = smfi_getsymval(ctx, "{cert_subject}")) != NULL)) {
		mg_log(LOG_DEBUG, 
		    "STARTTLS succeeded for DN=\"%s\", bypassing greylisting", 
		    cert_subject);
		priv->priv_sr.sr_elapsed = 0;
		priv->priv_sr.sr_whitelist = EXF_WHITELIST | EXF_STARTTLS;

		return SMFIS_CONTINUE;
	}

	/*
	 * Is the sender address SPF-compliant?
	 */
	if ((conf.c_nospf == 0) && SPF_CHECK(priv)) {
		priv->priv_sr.sr_elapsed = 0;
		priv->priv_sr.sr_whitelist = EXF_WHITELIST | EXF_SPF;

		return SMFIS_CONTINUE;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
real_envrcpt(ctx, envrcpt)
	SMFICTX *ctx;
	char **envrcpt;
{
	struct mlfi_priv *priv;
	time_t remaining;
	char *greylist;
	char addrstr[IPADDRSTRLEN];
	char rcpt[ADDRLEN + 1];
	long long save_nolog;
	struct tuple_fields tuple;
	time_t sleep_duration = 0;
	/*
	 * Strip spaces from the recipient address
	 */
	strncpy_rmsp(rcpt, *envrcpt, ADDRLEN);
	rcpt[ADDRLEN] = '\0';

	if ((priv = (struct mlfi_priv *) smfi_getpriv(ctx)) == NULL) {
		mg_log(LOG_ERR, "Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}
	if ((priv->priv_queueid = smfi_getsymval(ctx, "{i}")) == NULL) {
#ifndef USE_POSTFIX
		/* 
		 * Postfix does not choose a queue file name 
		 * until after it accepts the first valid RCPT TO 
		 * command, unless config option
		 * 'smtpd_delay_open_until_valid_rcpt = no' set,
		 * so don't log the failure.
		 */
		mg_log(LOG_DEBUG, "smfi_getsymval failed for {i}");
#endif
		priv->priv_queueid = "(unknown id)";
	}
	if (tarpit_reentry(priv) == SMFIS_TEMPFAIL)
		return SMFIS_TEMPFAIL;

	if (!iptostring(SA(&priv->priv_addr), priv->priv_addrlen, addrstr,
	    sizeof(addrstr)))
		goto exit_accept;

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "%s: addr = %s[%s], from = %s, rcpt = %s", 
		    priv->priv_queueid, priv->priv_hostname, 
		    addrstr, priv->priv_from, *envrcpt);

	/*
	 * Avoid properties gathered by urlcheck 
	 * to mix for multiple recipients.
	 */
	prop_clear(priv, UP_CLEARPROP);

	/*
	 * If we re-evaluate racl for each recipient, forget
	 * about previous decision. 
	 */
	if (conf.c_multiracl)
		priv->priv_sr.sr_whitelist &=
		     ~(EXF_WHITELIST|EXF_GREYLIST|EXF_BLACKLIST); 

	/*
	 * Global authenticated or TLS whitelisting, unless
	 * - noauth global parameter is set, or
	 * - any ACL with auth or tls clause
	 */
	if (conf.c_noauth == 0) {
		if (priv->priv_sr.sr_whitelist & EXF_AUTH)
			goto exit_accept;
		if (priv->priv_sr.sr_whitelist & EXF_STARTTLS)
			goto exit_accept;
	}

	/*
	 * Global SPF whitelisting, unless
	 * - nospf global parameter is set, or
	 * - any ACL with spf clause
	 */
	if ((conf.c_nospf == 0) && (priv->priv_sr.sr_whitelist & EXF_SPF)) {
		if (priv->priv_rcptcount == 0) // Log only for first recipient
			mg_log(LOG_INFO,
				"%s: Sender IP %s and address %s are "
				"SPF-compliant, bypassing greylist", 
				priv->priv_queueid, addrstr, priv->priv_from);
		goto exit_accept;
	}

	/*
	 * Mail sent from non IP source is always whitelisted
	 */
	if (priv->priv_sr.sr_whitelist & EXF_NONIP) 
		goto exit_accept;

#ifdef USE_DRAC
	if ((SA(&priv->priv_addr)->sa_family == AF_INET) && 
	    (conf.c_nodrac == 0) &&
	    check_drac(addrstr)) {
		mg_log(LOG_DEBUG, "whitelisted by DRAC");
		priv->priv_sr.sr_elapsed = 0;
		priv->priv_sr.sr_whitelist = EXF_WHITELIST | EXF_DRAC;

		goto exit_accept;
	}
#endif

	 /*
	  * If sendmail rules have defined a ${greylist} macro
	  * with value WHITE (or RELAY or OK), then it is whitelisted
	  */
	if ((conf.c_noaccessdb == 0) &&
	    ((greylist = smfi_getsymval(ctx, "{greylist}")) != NULL) &&
	    ((strcmp(greylist, "WHITE") == 0) ||
	    (strcmp(greylist, "RELAY") == 0) ||
	    (strcmp(greylist, "OK") == 0))) {
		mg_log(LOG_DEBUG, 
		    "whitelisted by {greylist}");
		priv->priv_sr.sr_elapsed = 0;
		priv->priv_sr.sr_whitelist = EXF_WHITELIST | EXF_ACCESSDB;
 
		goto exit_accept;
	}

	/* 
	 * Restart the sync master thread if nescessary
	 */
	sync_master_restart();

	/*
	 * Check the ACL
	 */
	reset_acl_values(priv);
	(void)strncpy(priv->priv_cur_rcpt, rcpt, ADDRLEN);
	priv->priv_cur_rcpt[ADDRLEN] = '\0';
	if (acl_filter(AS_RCPT, ctx, priv) != 0) {
		mg_log(LOG_ERR, "ACL evaluation failure");
		return SMFIS_TEMPFAIL;
	}

	if (priv->priv_sr.sr_whitelist & EXF_WHITELIST &&
	    priv->priv_sr.sr_tarpit <= 0) {
		priv->priv_sr.sr_elapsed = 0;
		goto exit_accept;
	}

	/* 
	 * Blacklist overrides autowhitelisting...
	 */
	if (priv->priv_sr.sr_whitelist & EXF_BLACKLIST) {
		char *aclstr;
		char *code = "551";
		char *ecode = "5.7.1";
		char *msg = "Go away!";

		aclstr = fstring_expand(priv, NULL, " (ACL %a)", NULL);

		if (!(priv->priv_sr.sr_whitelist & EXF_NOLOG)) {
			mg_log(LOG_INFO, 
				"%s: addr %s[%s] from %s to %s blacklisted%s",
				priv->priv_queueid, priv->priv_hostname, addrstr, 
				priv->priv_from, rcpt, aclstr);
		}

		set_sr_defaults(priv, code, ecode, msg);
		mg_setreply(ctx, priv, rcpt);
		free(aclstr);
		return mg_stat(priv, stat_from_code(priv->priv_sr.sr_code));
	}

	save_nolog = priv->priv_sr.sr_whitelist & EXF_NOLOG;

	/*
	 * Check if the tuple {sender IP, sender e-mail, recipient e-mail}
	 * is in the greylist or autowhite list and if it can now be 
	 * accepted. If in greylist, the greylist entry will change to 
	 * autowhite entry. If it is not in the greylist, it will be added.
	 */

	tuple.sa = SA(&priv->priv_addr);
	tuple.salen = priv->priv_addrlen;
	tuple.from = priv->priv_from;
	tuple.rcpt = rcpt;
	tuple.remaining = &remaining;
	tuple.elapsed = &priv->priv_sr.sr_elapsed;
	tuple.queueid = priv->priv_queueid;
	tuple.gldelay = priv->priv_sr.sr_delay;
	tuple.autowhite = priv->priv_sr.sr_autowhite;

	switch(mg_tuple_check(&tuple)) {
	case T_AUTOWHITE:		/* autowhite listed */
		priv->priv_sr.sr_elapsed = 0;
		priv->priv_sr.sr_whitelist = EXF_WHITELIST | EXF_AUTO;
		goto exit_accept;
		break;
	case T_PENDING:			/* greylisted */
		if (priv->priv_sr.sr_elapsed > priv->priv_max_elapsed)
			priv->priv_max_elapsed = priv->priv_sr.sr_elapsed;
		goto exit_accept;
		break;
	default:			/* first encounter */
		if (!(priv->priv_sr.sr_whitelist & EXF_TARPIT))
			break;

		if (priv->priv_sr.sr_tarpit_scope == TAP_COMMAND &&
		    priv->priv_sr.sr_tarpit > priv->priv_max_tarpitted)
			sleep_duration = priv->priv_sr.sr_tarpit;
		if (priv->priv_sr.sr_tarpit_scope == TAP_SESSION &&
		    priv->priv_sr.sr_tarpit > priv->priv_total_tarpitted)
			sleep_duration = priv->priv_sr.sr_tarpit -
					      priv->priv_total_tarpitted;

		if (sleep_duration > 0) {
			if (sleep_duration > priv->priv_max_tarpitted)
				priv->priv_max_tarpitted = sleep_duration;
			priv->priv_total_tarpitted += sleep_duration;
			sleep(sleep_duration);
		} else {
		    if (priv->priv_sr.sr_whitelist & EXF_WHITELIST) {
			tuple.updatetype = TU_AUTOWHITE;
			mg_tuple_update(&tuple);
			}
		}
		priv->priv_sr.sr_elapsed = 0;
		goto exit_accept;
	}
	priv->priv_sr.sr_remaining = remaining;

	/*
	 * The message has been added to the greylist and will be delayed.
	 * If the sender address is null, this will be done after the DATA
	 * phase, otherwise immediately.
	 * Delayed reject with per-recipient delays or messages 
	 * will use the last match.
	 */
	if ((conf.c_delayedreject == 1) && 
	    (strcmp(priv->priv_from, "<>") == 0)) {
		priv->priv_delayed_reject = 1;
		goto exit_accept;
	}

	/*
	 * Log temporary failure and report to the client.
	 */
	priv->priv_sr.sr_whitelist |= save_nolog;
	log_and_report_greylisting(ctx, priv, *envrcpt);
	return mg_stat(priv, SMFIS_TEMPFAIL);

exit_accept:
	add_recipient(priv, rcpt);
	if (priv->priv_sr.sr_whitelist & EXF_WHITELIST)
		priv->priv_last_whitelist = priv->priv_sr.sr_whitelist;
	return SMFIS_CONTINUE;
}

static sfsistat
real_header(ctx, name, value)
	SMFICTX *ctx;
	char *name;
	char *value;
{
	struct line *l;
	struct mlfi_priv *priv;
	const char sep[] = ": ";
	const char crlf[] = "\r\n";
	size_t len;
#ifdef USE_DKIM
	sfsistat stat = SMFIS_CONTINUE;
#endif /* USE_DKIM */

	if ((priv = (struct mlfi_priv *) smfi_getpriv(ctx)) == NULL) {
		mg_log(LOG_ERR, "Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

	len = strlen(name) + strlen(sep) + strlen(value) + strlen(crlf);
	priv->priv_msgcount += len;

	if (priv->priv_maxpeek == 0)
		return SMFIS_CONTINUE;

	if ((priv->priv_msgcount > priv->priv_maxpeek) || 
	    (priv->priv_buflen > priv->priv_maxpeek)) {
		if (conf.c_debug)
			mg_log(LOG_DEBUG, 
			    "ignoring message beyond maxpeek = %d", 
			    priv->priv_maxpeek);
		priv->priv_maxpeek = 0;
		return SMFIS_CONTINUE;
	}

	if ((l = malloc(sizeof(*l))) == NULL) {
		mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	len = strlen(name) + strlen(sep) + strlen(value) + strlen(crlf);
	if ((l->l_line = malloc(len + 1)) == NULL) {
		mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	l->l_line[0] = '\0';
	strcat(l->l_line, name);
	strcat(l->l_line, sep);
	strcat(l->l_line, value);
	strcat(l->l_line, crlf);
	l->l_len = len;

	TAILQ_INSERT_TAIL(&priv->priv_header, l, l_list);

#ifdef USE_DKIM
	if ((stat = dkimcheck_header(name, value, priv)) != SMFIS_CONTINUE)
		return stat;
#endif
	return SMFIS_CONTINUE;
}

static sfsistat
real_eoh(ctx)
	SMFICTX *ctx;
{
#ifdef USE_DKIM
	struct mlfi_priv *priv;
	sfsistat stat = SMFIS_CONTINUE;

	if ((priv = (struct mlfi_priv *) smfi_getpriv(ctx)) == NULL) {
		mg_log(LOG_ERR, "Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

	if ((stat = dkimcheck_eoh(priv)) != SMFIS_CONTINUE)
		return stat;
#endif /* USE_DKIM */

	return SMFIS_CONTINUE;
}

static sfsistat
real_body(ctx, chunk, size)
	SMFICTX *ctx;
	unsigned char *chunk;
	size_t size;
{
	struct mlfi_priv *priv;
	struct line *l;
	size_t linelen;
	size_t tsize;	/* data already saved plus last incomplete line */
	size_t bsize;	/* to be copied from saved data in priv_buf */
	size_t csize;	/* to be copied from current chunk */
	int i;
#ifdef USE_DKIM
	sfsistat stat = SMFIS_CONTINUE;
#endif /* USE_DKIM */

	if ((priv = (struct mlfi_priv *) smfi_getpriv(ctx)) == NULL) {
		mg_log(LOG_ERR, "Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

	priv->priv_msgcount += size;

#ifdef USE_DKIM
	if ((stat = dkimcheck_body(chunk, size, priv)) != SMFIS_CONTINUE)
		return stat;
#endif

	/* First time: add \r\n between headers and body */
	if (TAILQ_EMPTY(&priv->priv_body)) {
		const char crlf[] = "\r\n";

		if ((l = malloc(sizeof(*l))) == NULL) {
			mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		if ((l->l_line = strdup(crlf)) == NULL) {
			mg_log(LOG_ERR, "strdup() failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		l->l_len = strlen(crlf);
		TAILQ_INSERT_TAIL(&priv->priv_body, l, l_list);

		priv->priv_msgcount += strlen(crlf);
		priv->priv_peekcount += strlen(crlf);
	}

	/*
	 * maxpeek limit the length of data we inspect.
	 * priv->priv_peekcount count the data seen so far.
	 * If we already reached the limit, jusy continue now.
	 */
	if (priv->priv_peekcount >= priv->priv_maxpeek) {
		if (!priv->priv_peekdone) {
			mg_log(LOG_DEBUG, 
			       "ignoring message beyond maxpeek = %d", 
 			       priv->priv_maxpeek);
			priv->priv_peekdone = 1;
		}
		return SMFIS_CONTINUE;
	}

	/*
	 * priv->priv_buflen count a possible incomplete line
	 * we got from previous call. If it is enough to reach
	 * the limit, we do not take any data from the new chunk,
	 * and we also disregard the incmplete saved line.
	 */
	tsize = priv->priv_peekcount + priv->priv_buflen;
	if (tsize > priv->priv_maxpeek) {
		bsize = priv->priv_maxpeek - priv->priv_peekcount;
		csize = 0;
	} else {
		/* 
		 * If saved data plus current chunk reaches the
		 * limit, use all saved data and truncate the chunk.
		 * Otherwise, take everythin.
		 */
		if (tsize + size > priv->priv_maxpeek) {
			bsize = priv->priv_buflen;
			csize = priv->priv_maxpeek - tsize;
		} else {
			bsize = priv->priv_buflen;
			csize = size;
		}
	} 

	/* 
	 * No data from new chunk: we are done
	 */
	if (csize == 0) {
		priv->priv_peekcount += bsize + csize; 
		return SMFIS_CONTINUE;
	}

	/*
	 * a struct line can hold multiple lines from the message,
	 * We lookup the last \n in the chunk to save the unfinished
	 * line for later.
	 */
	for (i = csize - 1; i >= 0; i--) {
		if (chunk[i] == '\n')
			break;
	}
	++i; /* Use i as byte counter */

	/* From chunk to chunk + i - 1: a set of lines */
	if (chunk[i - 1] == '\n') { /* We have a newline */
		if ((l = malloc(sizeof(*l))) == NULL) {
			mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
			exit(EX_OSERR);
		}
	
		/* Make room for data saved from previous call */
		linelen = bsize + i;
		if ((l->l_line = malloc(linelen + 1)) == NULL) {
			mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		/* Gather data saved from a previous call, then the chunk */
		if (bsize != 0) {
			memcpy(l->l_line, priv->priv_buf, bsize);
			free(priv->priv_buf);
			priv->priv_buf = NULL;
			priv->priv_buflen = 0;
		}

		memcpy(l->l_line + bsize, chunk, i);
		l->l_line[linelen] = '\0';
		l->l_len = linelen;

		TAILQ_INSERT_TAIL(&priv->priv_body, l, l_list);

		priv->priv_peekcount += linelen;
	}

	/* From chunk + i to chunk + csize - 1: an incomplete line */
	if (i < csize) { /* keep the remains for later */
		priv->priv_buf = realloc(priv->priv_buf, 
					 priv->priv_buflen + csize - i);
		if (priv->priv_buf == NULL) {
			mg_log(LOG_ERR, 
			    "realloc() failed: %s", 
			    strerror(errno));
			exit(EX_OSERR);
		}
		memcpy(&priv->priv_buf[priv->priv_buflen], 
		       chunk + i, csize - i);
		priv->priv_buflen += (csize - i);
	}

	return SMFIS_CONTINUE;
}

static sfsistat
real_eom(ctx)
	SMFICTX *ctx;
{
	struct mlfi_priv *priv;
	char whystr [HDRLEN + 1];
	struct smtp_reply rcpt_sr;
	struct rcpt *rcpt;
	time_t remaining;
	int envrcpt_continue = 0;
	int accept = 1;
	struct tuple_fields tuple;
#ifdef USE_DKIM
	sfsistat stat = SMFIS_CONTINUE;
#endif /* USE_DKIM */

	if ((priv = (struct mlfi_priv *) smfi_getpriv(ctx)) == NULL) {
		mg_log(LOG_ERR, "Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

	priv->priv_cur_rcpt[0] = '\0'; /* There is no current recipient */
        /* we want fstring_expand to expand %E to priv_max_elapsed here */
	priv->priv_sr.sr_elapsed = priv->priv_max_elapsed;

	/* 
	 * save the remaining buffer
	 */
	if (priv->priv_buflen > 0) {
		struct line *l;

		if ((l = malloc(sizeof(*l))) == NULL) {
			mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		l->l_line = priv->priv_buf;
		l->l_len = priv->priv_buflen - 1;
		l->l_line[priv->priv_buflen - 1] = '\0';

		priv->priv_buf = NULL;
		priv->priv_buflen = 0;

		TAILQ_INSERT_TAIL(&priv->priv_body, l, l_list);
	}

#ifdef USE_DKIM
	if ((stat = dkimcheck_eom(priv)) != SMFIS_CONTINUE)
		return stat;
#endif

	if (priv->priv_delayed_reject) {
		LIST_FOREACH(rcpt, &priv->priv_rcpt, r_list) 
			log_and_report_greylisting(ctx, priv, rcpt->r_addr);
		return mg_stat(priv, SMFIS_TEMPFAIL);
	}

	if (priv->priv_sr.sr_whitelist & EXF_WHITELIST && 
	    priv->priv_sr.sr_whitelist & EXF_DEFAULT)
		envrcpt_continue = 1;

	/* 
	 * We save data obtained from RCPT and we will restore it afterward
	 */
	memcpy(&rcpt_sr, &priv->priv_sr, sizeof(rcpt_sr));
	smtp_reply_init(&priv->priv_sr);
	priv->priv_sr.sr_elapsed = priv->priv_max_elapsed;
	if (acl_filter(AS_DATA, ctx, priv) != 0) {
		mg_log(LOG_ERR, "ACL evaluation failure");
		return SMFIS_TEMPFAIL;
	}

	if (priv->priv_sr.sr_whitelist & EXF_BLACKLIST) {
		char *aclstr;
		char addrstr[IPADDRSTRLEN];
		char *code = "551";
		char *ecode = "5.7.1";
		char *msg = "Go away!";

		smtp_reply_free(&rcpt_sr);

		aclstr = fstring_expand(priv, NULL, " (ACL %a)", NULL);

		iptostring(SA(&priv->priv_addr), priv->priv_addrlen, addrstr,
		    sizeof(addrstr));

		if (!(priv->priv_sr.sr_whitelist & EXF_NOLOG)) {
			mg_log(LOG_INFO, 
				"%s: addr %s[%s] from %s blacklisted%s",
				priv->priv_queueid, priv->priv_hostname, addrstr, 
				priv->priv_from, aclstr);
		}

	/*
	 * If we re-evaluate racl for each recipient, forget
	 * about whitelisted addresses
	 */
		set_sr_defaults(priv, code, ecode, msg);
		mg_setreply(ctx, priv, NULL);
		free(aclstr);
		return mg_stat(priv, stat_from_code(priv->priv_sr.sr_code));
	}

	if (priv->priv_sr.sr_whitelist & EXF_GREYLIST && envrcpt_continue) {
		/*
		 * Multiple recipients for a single message. Here we check 
		 * each recipient individually for greylisting and autowhite 
		 * listing.
		 */
		priv->priv_sr.sr_whitelist &= ~EXF_NONE;
		LIST_FOREACH(rcpt, &priv->priv_rcpt, r_list) {

			tuple.sa = SA(&priv->priv_addr);
			tuple.salen = priv->priv_addrlen;
			tuple.from = priv->priv_from;
			tuple.rcpt = rcpt->r_addr;
			tuple.remaining = &remaining;
			tuple.elapsed = &priv->priv_sr.sr_elapsed;
			tuple.queueid = priv->priv_queueid;
			tuple.gldelay = priv->priv_sr.sr_delay;
			tuple.autowhite = priv->priv_sr.sr_autowhite;

			switch(mg_tuple_check(&tuple)) {
			case T_AUTOWHITE:	/* autowhite listed */
				priv->priv_sr.sr_whitelist |= 
				    (EXF_WHITELIST | EXF_AUTO);
				break;
			case T_PENDING:		/* greylisted */
				break;
			default:		/* first encounter */
				accept = 0;
				break;
			}

		}

		if (accept) {
			if (priv->priv_sr.sr_elapsed > priv->priv_max_elapsed)
				priv->priv_max_elapsed = 
				    priv->priv_sr.sr_elapsed;
			goto passed;
		}

		priv->priv_sr.sr_remaining = remaining;
		LIST_FOREACH(rcpt, &priv->priv_rcpt, r_list) 
			log_and_report_greylisting(ctx, priv, rcpt->r_addr);

		return mg_stat(priv, SMFIS_TEMPFAIL);
	}

passed:
	/* Add custom header from DATA stage ACL */
	/* XXX we do it twice??? */
	if (priv->priv_sr.sr_addheader) {
		char *hdrname;
		char *hdrvalue;
		char *sep = ": ";

		hdrname = fstring_expand(priv, NULL, 
					 priv->priv_sr.sr_addheader, NULL);
		if ((hdrvalue = strstr(hdrname, sep)) == NULL) {
			mg_log(LOG_ERR, "bad header \"%s\"", hdrname);
		} else {
			*hdrvalue = '\0';
			hdrvalue += strlen(sep);
			if (priv->priv_sr.sr_addheader_index >= 0)
				smfi_insheader(
					ctx, priv->priv_sr.sr_addheader_index,
					hdrname, hdrvalue);
			else
				smfi_addheader(ctx, hdrname, hdrvalue);
		}

		free(hdrname);
	}

	/* Add footer if we have the whole message */
	if (priv->priv_sr.sr_addfooter && 
	    (priv->priv_msgcount <= priv->priv_maxpeek)) {
		char *footer;
		unsigned char *newbody;
		size_t newlen;
		struct line *l;

		footer = fstring_expand(priv, NULL, 
					priv->priv_sr.sr_addfooter, NULL);
		newlen = strlen(footer);
		TAILQ_FOREACH(l, &priv->priv_body, l_list)
			newlen += l->l_len;

		if ((newbody = malloc(newlen)) == NULL) {
			mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		newbody[0] = '\0';
		TAILQ_FOREACH(l, &priv->priv_body, l_list)
			(void)strcat((char *)newbody, l->l_line);

		(void)strcat((char *)newbody, footer);

		if (smfi_replacebody(ctx, newbody, newlen) != MI_SUCCESS)
			mg_log(LOG_WARNING, "smfi_replacebody failed");

		free(footer);
	}

	/* Add subject tag if we have the whole message */
	if (priv->priv_sr.sr_subjtag) {
		const char const subjhdr[] = "Subject: ";
		size_t subjhdrlen = sizeof(subjhdr) - 1;
		char *tag;
		struct line *l;
		char *oldline;

		tag = fstring_expand(priv, NULL, 
				     priv->priv_sr.sr_subjtag, NULL);
		oldline = NULL;

		TAILQ_FOREACH(l, &priv->priv_header, l_list) {
			if (strncmp(l->l_line, subjhdr, subjhdrlen) == 0) {
				size_t oldlinelen;

				oldline = l->l_line + subjhdrlen;
				oldlinelen = strlen(oldline);
				while (!isprint((int)oldline[oldlinelen]))
					oldline[oldlinelen--] = '\0';
				break;
			}
		}

		if (oldline && (strstr(oldline, tag) == NULL)) {
			size_t newlen;
			char *newline;

			newlen = subjhdrlen + strlen(tag) + strlen(oldline) + 1;
			if ((newline = malloc(newlen)) == NULL)
				mg_log(LOG_ERR, "malloc failed");

			newline[0] = '\0';
			(void)strcat(newline, subjhdr);
			(void)strcat(newline, tag);
			(void)strcat(newline, oldline);

			free(l->l_line);
			l->l_line = newline;
			l->l_len = newlen;

			if (smfi_chgheader(ctx, "Subject", 1, 
					   newline + subjhdrlen) != MI_SUCCESS)
				mg_log(LOG_WARNING, "smfi_chgheader failed");
		} 

		free(tag);
	}

	/* Restore the info collected from RCPT stage */
	smtp_reply_free(&priv->priv_sr);
	memcpy(&priv->priv_sr, &rcpt_sr, sizeof(rcpt_sr));

	if (priv->priv_max_elapsed == 0) {
		/* All recipients are whitelisted */
		char *hdrstr = NULL;

		if ((conf.c_report & C_NODELAYS) == 0)
			goto out;
			

		if (priv->priv_sr.sr_report) {
			hdrstr = fstring_expand(priv, 
			    NULL, priv->priv_sr.sr_report, NULL);
		} else {
			whystr[0] = '\0';
			if (priv->priv_last_whitelist & EXF_DOMAIN) {
				ADD_REASON(whystr, 
				    "Sender DNS name whitelisted");
				priv->priv_last_whitelist &= ~EXF_DOMAIN;
			}
			if (priv->priv_last_whitelist & EXF_ADDR) {
				ADD_REASON(whystr, 
				    "Sender IP whitelisted");
				priv->priv_last_whitelist &= ~EXF_ADDR;
			}
			if (priv->priv_last_whitelist & EXF_FROM) {
				ADD_REASON(whystr, 
				    "Sender e-mail whitelisted");
				priv->priv_last_whitelist &= ~EXF_FROM;
			}
			if (priv->priv_last_whitelist & EXF_AUTH) {
				ADD_REASON(whystr, 
				    "Sender succeeded SMTP AUTH");
				priv->priv_last_whitelist &= ~EXF_AUTH;
			}
			if (priv->priv_last_whitelist & EXF_ACCESSDB) {
				ADD_REASON(whystr, 
				    "Message whitelisted by Sendmail "
				    "access database");
				priv->priv_last_whitelist &= ~EXF_ACCESSDB;
			}
			if (priv->priv_last_whitelist & EXF_DRAC) {
				ADD_REASON(whystr, 
				    "Message whitelisted by DRAC "
				    "access database");
				priv->priv_last_whitelist &= ~EXF_DRAC;
			}
			if (priv->priv_last_whitelist & EXF_SPF) {
				ADD_REASON(whystr, "Sender passed SPF test");
				priv->priv_last_whitelist &= ~EXF_SPF;
			}
			if (priv->priv_last_whitelist & EXF_DKIM) {
				ADD_REASON(whystr, "Sender passed DKIM test");
				priv->priv_last_whitelist &= ~EXF_DKIM;
			}
			if (priv->priv_last_whitelist & EXF_NONIP) {
#ifdef AF_INET6
				ADD_REASON(whystr, 
				    "Message not sent from an IPv4 "
				    "neither IPv6 address");
#else
				ADD_REASON(whystr, 
				    "Message not sent from an IPv4 address");
#endif
				priv->priv_last_whitelist &= ~EXF_NONIP;
			}
			if (priv->priv_last_whitelist & EXF_STARTTLS) {
				ADD_REASON(whystr, 
				    "Sender succeeded STARTTLS authentication");
				priv->priv_last_whitelist &= ~EXF_STARTTLS;
			}
			if (priv->priv_last_whitelist & EXF_RCPT) {
				ADD_REASON(whystr, 
				    "Recipient e-mail whitelisted");
				priv->priv_last_whitelist &= ~EXF_RCPT;
			}
			if (priv->priv_last_whitelist & EXF_AUTO) {
				ADD_REASON(whystr, 
				    "IP, sender and "
				    "recipient auto-whitelisted");
				priv->priv_last_whitelist &= ~EXF_AUTO;
			}
			if (priv->priv_last_whitelist & EXF_DNSRBL) {
				ADD_REASON(whystr, 
				    "Sender IP whitelisted by DNSRBL");
				priv->priv_last_whitelist &= ~EXF_DNSRBL;
			}
			if (priv->priv_last_whitelist & EXF_MX) {
				ADD_REASON(whystr, 
				    "Sender IP whitelisted by MX");
				priv->priv_last_whitelist &= ~EXF_MX;
			}
			if (priv->priv_last_whitelist & EXF_URLCHECK) {
				ADD_REASON(whystr, "URL check passed");
				priv->priv_last_whitelist &= ~EXF_URLCHECK;
			}
			if (priv->priv_last_whitelist & EXF_DEFAULT) {
				ADD_REASON(whystr, 
				    "Default is to whitelist mail");
				priv->priv_last_whitelist &= ~EXF_DEFAULT;
			}
			if (priv->priv_last_whitelist & EXF_TARPIT) {
				ADD_REASON(whystr,
				    "Message whitelisted by tarpit %ts");
				priv->priv_last_whitelist &= ~EXF_TARPIT;
			}
			priv->priv_last_whitelist &= 
			    ~(EXF_GREYLIST | EXF_WHITELIST | EXF_BLACKLIST);

			/* Silently ignore other codes, just report ACL */	
			if (priv->priv_last_whitelist != 0) {
				priv->priv_last_whitelist = 0;
				if (whystr[0] != '\0')
					mystrlcat (whystr, ", ", HDRLEN);
				mystrlcat (whystr, "ACL %a matched", HDRLEN);
			}

			mystrlcat (whystr, ", not delayed by %V", HDRLEN);
			hdrstr = fstring_expand(priv, NULL, whystr, NULL);
		}

		smfi_addheader(ctx, HEADERNAME, hdrstr);
		priv->priv_sr.sr_report_x = hdrstr;

		goto out;
	}

	if (conf.c_report & C_DELAYS) {
		char *hdrstr;

		if (priv->priv_sr.sr_report)
			hdrstr = fstring_expand(priv, 
			    NULL, priv->priv_sr.sr_report, NULL);
		else
			hdrstr = fstring_expand(priv, 
			    NULL, "Delayed for %E by %V", NULL);

		smfi_addheader(ctx, HEADERNAME, hdrstr);
		priv->priv_sr.sr_report_x = hdrstr;
	}

out:
	/* Add custom header from DATA stage ACL */
	if (priv->priv_sr.sr_addheader) {
		char *hdrname;
		char *hdrvalue;
		char *sep = ": ";

		hdrname = fstring_expand(priv, NULL, 
					 priv->priv_sr.sr_addheader, NULL);
		if ((hdrvalue = strstr(hdrname, sep)) == NULL) {
			mg_log(LOG_ERR, "bad header \"%s\"", hdrname);
		} else {
			*hdrvalue = '\0';
			hdrvalue += strlen(sep);
			if (priv->priv_sr.sr_addheader_index >= 0)
				smfi_insheader(
					ctx, priv->priv_sr.sr_addheader_index,
					hdrname, hdrvalue);
			else
				smfi_addheader(ctx, hdrname, hdrvalue);
		}

		free(hdrname);
	}

	return mg_stat(priv, SMFIS_CONTINUE);
}

static sfsistat
real_abort(ctx)
	SMFICTX *ctx;
{
	struct mlfi_priv *priv;
	struct tuple_fields tuple;

	if ((priv = (struct mlfi_priv *) smfi_getpriv(ctx)) != NULL) {
		if (priv->priv_sr.sr_whitelist & EXF_TARPIT) {

			tuple.sa = SA(&priv->priv_addr);
			tuple.salen = priv->priv_addrlen;
			tuple.from = priv->priv_from;
			tuple.rcpt = priv->priv_rcpt.lh_first->r_addr;
			tuple.autowhite = 0;
			tuple.updatetype = TU_TARPIT;

			mg_tuple_update(&tuple);

			priv->priv_sr.sr_whitelist &= ~EXF_TARPIT;
		}
	}

	return SMFIS_CONTINUE;
}

static sfsistat
real_close(ctx)
	SMFICTX *ctx;
{
	struct mlfi_priv *priv;
	struct rcpt *r;
	struct line *l;

	if ((priv = (struct mlfi_priv *) smfi_getpriv(ctx)) != NULL) {
		smtp_reply_free(&priv->priv_sr);

		while ((r = LIST_FIRST(&priv->priv_rcpt)) != NULL) {
			LIST_REMOVE(r, r_list);
			free(r);
		}
		while ((l = TAILQ_FIRST(&priv->priv_header)) != NULL) {
			free(l->l_line);
			TAILQ_REMOVE(&priv->priv_header, l,  l_list);
			free(l);
		}
		while ((l = TAILQ_FIRST(&priv->priv_body)) != NULL) {
			free(l->l_line);
			TAILQ_REMOVE(&priv->priv_body, l, l_list);
			free(l);
		}
		if (priv->priv_buf)
			free(priv->priv_buf);
		prop_clear(priv, UP_PLAINPROP);
#ifdef USE_DNSRBL
		dnsrbl_list_cleanup(priv);
#endif     
#ifdef USE_P0F
		if (priv->priv_p0f != NULL)
			free(priv->priv_p0f);
#endif
#ifdef HAVE_SPF2
		if (priv->priv_spf_header != NULL)
			free(priv->priv_spf_header);
#endif
#ifdef USE_DKIM
		dkimcheck_free(priv);
#endif
		free(priv);
		smfi_setpriv(ctx, NULL);
	}

	/*
	 * If we need to dump on each change and something changed, dump
	 */
	dump_flush();

	return SMFIS_CONTINUE;
}

#ifdef HAVE_DATA_CALLBACK
static sfsistat
real_data(ctx)
	SMFICTX *ctx;
{
	struct mlfi_priv *priv;

	if ((priv = (struct mlfi_priv *) smfi_getpriv(ctx)) == NULL) {
		mg_log(LOG_ERR, "Internal error: smfi_getpriv() returns NULL");
		return SMFIS_TEMPFAIL;
	}

	return tarpit_reentry(priv);
}
#endif

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int ch;
	int checkonly = 0;
	int exitval;
	sigset_t set;

	/*
	 * Load configuration defaults
	 */
	conf_defaults(&defconf);

	/* 
	 * Process command line options 
	 */
	while ((ch = getopt(argc, argv, "Aa:cvDd:qw:f:hp:P:Tu:rSL:M:l")) != -1) {
		switch (ch) {
		case 'A':
			defconf.c_noauth = 1;
			defconf.c_forced |= C_NOAUTH;
			break;

		case 'a':
			if (optarg == NULL) {
				mg_log(LOG_ERR, "%s: -a needs an argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_autowhite_validity = 
			    (time_t)humanized_atoi(optarg);
			defconf.c_forced |= C_AUTOWHITE;
			break;

		case 'c':
		        checkonly = 1;
			break;

		case 'D':
			defconf.c_nodetach = 1;
			defconf.c_forced |= C_NODETACH;
			break;

		case 'q':
			defconf.c_quiet = 1;
			defconf.c_forced |= C_QUIET;
			break;

		case 'r':
			mg_log(LOG_INFO, "milter-greylist-%s %s", 
			    PACKAGE_VERSION, BUILD_ENV);
			mg_log(LOG_INFO,
			    "Version: %s%s%s",
			    PACKAGE_STRING,
			    strlen(PACKAGE_URL) ? 
				" distributed from " PACKAGE_URL : "" ,
			    strlen(PACKAGE_BUGREPORT) ? 
				", report bugs to " PACKAGE_BUGREPORT : "" );
			exit(EX_OK);
			break;

		case 'S':
			defconf.c_nospf = 1;
			defconf.c_forced |= C_NOSPF;
			break;

		case 'u': {
			if (geteuid() != 0) {
				mg_log(LOG_ERR, "%s: only root can use -u", 
				    argv[0]);
				exit(EX_USAGE);
			}

			if (optarg == NULL) {
				mg_log(LOG_ERR,
				    "%s: -u needs a valid user as argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_user = optarg;
			defconf.c_forced |= C_USER;
			break;
		}
			
		case 'v':
			defconf.c_debug = 1;
			defconf.c_forced |= C_DEBUG;
			break;

		case 'w':
			if ((optarg == NULL) || 
			    ((defconf.c_delay = humanized_atoi(optarg)) == 0)) {
				mg_log(LOG_ERR,
				    "%s: -w needs a positive argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_forced |= C_DELAY;
			break;

		case 'f':
			if (optarg == NULL) {
				mg_log(LOG_ERR, "%s: -f needs an argument",
				    argv[0]);
				usage(argv[0]);
			}
			conffile = optarg;
			conf_specified = 1;
			break;

		case 'd':
			if (optarg == NULL) {
				mg_log(LOG_ERR, "%s: -d needs an argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_dumpfile = optarg;
			defconf.c_forced |= C_DUMPFILE;
			break;
				
		case 'P':
			if (optarg == NULL) {
				mg_log(LOG_ERR, "%s: -P needs an argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_pidfile = optarg;
			defconf.c_forced |= C_PIDFILE;
			break;

		case 'p':
			if (optarg == NULL) {
				mg_log(LOG_ERR, "%s: -p needs an argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_socket = optarg;
			defconf.c_forced |= C_SOCKET;
			break;

		case 'L': {
			int cidr;
			char maskstr[IPADDRLEN + 1];

		  	if (optarg == NULL) {
				mg_log(LOG_ERR,
				    "%s: -L requires a CIDR mask", argv[0]);
				usage(argv[0]);
			}

			cidr = atoi(optarg);
			if ((cidr > 32) || (cidr < 0)) {
				mg_log(LOG_ERR,
				    "%s: -L requires a CIDR mask", argv[0]);
				usage(argv[0]);
			}
			prefix2mask4(cidr, &defconf.c_match_mask);
			defconf.c_forced |= C_MATCHMASK;

			if (defconf.c_debug)
				mg_log(LOG_DEBUG, "match mask: %s", 
				    inet_ntop(AF_INET, &defconf.c_match_mask, 
				    maskstr, IPADDRLEN));

			break;
		}

		case 'M': {
			int plen;
#ifdef AF_INET6
			char maskstr[INET6_ADDRSTRLEN + 1];
#endif

		  	if (optarg == NULL) {
				mg_log(LOG_ERR,
				    "%s: -M requires a prefix length",
				    argv[0]);
				usage(argv[0]);
			}

			plen = atoi(optarg);
			if ((plen > 128) || (plen < 0)) {
				mg_log(LOG_ERR,
				    "%s: -M requires a prefix length",
				    argv[0]);
				usage(argv[0]);
			}
#ifdef AF_INET6
			prefix2mask6(plen, &defconf.c_match_mask6);
			defconf.c_forced |= C_MATCHMASK6;

			if (defconf.c_debug)
				mg_log(LOG_DEBUG, "match mask: %s", 
				    inet_ntop(AF_INET6, &defconf.c_match_mask6,
				    maskstr, INET6_ADDRSTRLEN));

#endif
			break;
		}

		case 'T':
			defconf.c_testmode = 1;	
			defconf.c_forced |= C_TESTMODE;
			break;

		case 'l':
			defconf.c_acldebug = 1;
			defconf.c_forced |= C_ACLDEBUG;
			break;

		case 'h':
		default:
			usage(argv[0]);
			break;
		}
	}
	
	/*
	 * Various init
	 */
	tzset();
	conf_init();
	all_list_init();
	acl_init ();
	peer_init();

#ifdef USE_DNSRBL
	dnsrbl_init();
#endif
#ifdef USE_CURL
	urlcheck_init();
#endif
#ifdef USE_LDAP
	ldapcheck_init();
#endif
#ifdef USE_DKIM
	dkimcheck_init();
#endif
#ifdef USE_GEOIP
	geoip_init();
#endif
#ifdef USE_GEOIP
	geoip2_init();
#endif
	macro_init();
	ratelimit_init();
#ifdef USE_NSUPDATE
	nsupdate_init();
#endif

#ifdef USE_FD_POOL
        /* initialize file descriptor pool */
        fd_pool_init();
#endif

	/*
	 * Load config file
	 * We can do this without locking exceptlist, as
	 * normal operation has not started: no other thread
	 * can access the list yet.
	 */
	conf_load();
	if (checkonly) {
		mg_log(LOG_INFO, "config file \"%s\" is okay", conffile);
		exit(EX_OK);
	}
	conf_retain();
	nodetach = conf.c_nodetach;

	openlog("milter-greylist", 0, conf.c_logfac);
	conf_cold = 0;
	
	if (conf.c_socket == NULL) {
		mg_log(LOG_ERR, "%s: No socket provided, exiting", argv[0]);
		usage(argv[0]);
	}
	cleanup_sock(conf.c_socket);
	cleanup_pidfile(conf.c_pidfile);

	(void)smfi_setconn(conf.c_socket);

	/*
	 * Initialize the storage backend
	 */
	mg_init();

	/*
	 * If no body/header search exists, don't install the hooks,
	 * it will improve performance a lot.
	 */
	if (conf.c_maxpeek == 0) {
		smfilter.xxfi_header = NULL;
		smfilter.xxfi_body = NULL;
		smfilter.xxfi_flags &= ~SMFIF_CHGBODY;
	}

	/* 
	 * Register our callbacks 
	 */
	if (smfi_register(smfilter) == MI_FAILURE) {
		mg_log(LOG_ERR, "%s: smfi_register failed", argv[0]);
		exit(EX_UNAVAILABLE);
	}

        /* 
	 * Create directory before creating socket each time, 
	 * just in case we use tmpfs for sockets
	 */
	mkparentdir(conf.c_socket, 0755);

	if (smfi_opensocket(1) == MI_FAILURE) {
		mg_log(LOG_ERR, "%s: failed to open socket: %s",
		       argv[0], conf.c_socket);
		exit(EX_UNAVAILABLE);
	}
	/*
	 * Set socket permission
	 */
	if (conf.c_socket_mode != -1) {
		switch(conf.c_socket_mode) {
		case 0666:
		case 0660:
		case 0600:
			if (chmod(conf.c_socket, conf.c_socket_mode) == -1)
				mg_log(LOG_ERR,
				       "failed to change socket mode: %s: %s: O%o",
				       strerror(errno),
				       conf.c_socket,
				       conf.c_socket_mode);
			break;
		default:
			mg_log(LOG_ERR, "unexpected socket mode %d",
			    conf.c_socket_mode);
			exit(EX_SOFTWARE);
			break;
		}
	}

	/*
	 * Turn into a daemon
	 */
	if (conf.c_nodetach == 0) {

		(void)close(0);
		(void)open("/dev/null", O_RDONLY, 0);
		(void)close(1);
		(void)open("/dev/null", O_WRONLY, 0);
		(void)close(2);
		(void)open("/dev/null", O_WRONLY, 0);

		if (chdir("/") != 0) {
			mg_log(LOG_ERR, "%s: cannot chdir to root: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}

		switch (fork()) {
		case -1:
			mg_log(LOG_ERR, "%s: cannot fork: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
			break;

		case 0:
			break;

		default:
			exit(EX_OK);	
			break;
		}

		if (setsid() == -1) {
			mg_log(LOG_ERR, "%s: setsid failed: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}
	}

	/* 
	 * Write down our PID to a file
	 */
	if (conf.c_pidfile != NULL)
		writepid(conf.c_pidfile);

	/*
	 * Drop root privs, if we run as root
	 */
	if ((geteuid() == 0) && (conf.c_user != NULL)) {
		struct passwd *pw = NULL;
		struct group *gr = NULL;
		char *c_group = NULL;

		if ((c_group = strchr(conf.c_user, ':')) != NULL)
			*c_group++ = '\0';

		if ((pw = getpwnam(conf.c_user)) == NULL) {
			mg_log(LOG_ERR, "%s: cannot get user %s data: %s",
			    argv[0], conf.c_user, strerror(errno));
			exit(EX_OSERR);
		}

		if (c_group != NULL) {
			if ((gr = getgrnam(c_group)) == NULL) {
				mg_log(LOG_ERR, "%s: cannot get group %s data: %s",
			    	argv[0], c_group, strerror(errno));
				exit(EX_OSERR);
			}
			pw->pw_gid = gr->gr_gid;
		} else {
			if ((gr = getgrgid(pw->pw_gid)) == NULL) {
				mg_log(LOG_ERR, "%s: cannot get group %d data: %s",
			    	argv[0], pw->pw_gid, strerror(errno));
				exit(EX_OSERR);
			}
                }

#ifdef HAVE_INITGROUPS
		if (initgroups(conf.c_user, pw->pw_gid) != 0) {
		        mg_log(LOG_ERR, "%s: cannot change "
			    "supplementary groups: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}
#endif

		/* 
		 * Make sure we keep write access to the PID file
		 * so that we can remove it later
		 */
		if (conf.c_pidfile != NULL) {
			if (chown(conf.c_pidfile, pw->pw_uid, pw->pw_gid) != 0)
				mg_log(LOG_WARNING, "%s: cannot change \"%s\""
				    " ownership to %s/%s: %s", argv[0], 
				    conf.c_pidfile, pw->pw_name, gr->gr_name,
				    strerror(errno));
		}

 		/* 
 		 * chown the socket so that sendmail does not complain
 		 */
		if ((access(conf.c_socket, F_OK) == 0) &&
		    (chown(conf.c_socket, pw->pw_uid, pw->pw_gid) != 0))
			mg_log(LOG_WARNING, "%s: cannot change \"%s\""
			    " ownership to %s/%s: %s", argv[0], 
			    conf.c_socket, pw->pw_name, gr->gr_name,
			    strerror(errno));


		if (setgid(pw->pw_gid) != 0 ||
		    setegid(pw->pw_gid) != 0) {
			mg_log(LOG_ERR, "%s: cannot change GID: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}


		if ((setuid(pw->pw_uid) != 0) ||
		    (seteuid(pw->pw_uid) != 0)) {
			mg_log(LOG_ERR, "%s: cannot change UID: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}
	}

	/*
	 * Block signals before all other threads start.
	 * The libmilter watches them and returns from smfi_main() if got.
	 */
	sigemptyset(&set);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	/*
	 * Start the storage backend background thread
	 */
	mg_start();

	/*
	 * Here we go!
	 */
	conf_release();
	exitval = smfi_main();
	mg_log(LOG_ERR, "smfi_main() returned %d", exitval);
	
#ifdef WORKAROUND_LIBMILTER_RACE_CONDITION
	signal(SIGSEGV, SIG_IGN);
	signal(SIGBUS, SIG_IGN);
	signal(SIGABRT, SIG_IGN);
	conf_retain();
	dump_perform(1);
	conf_release();
#else
	mg_tuple_stop();	/* stop storage background threads */
#endif
	mg_tuple_close();	/* close storage backend */
	return exitval;
}

void
usage(progname)
	char *progname;
{
	mg_log(LOG_ERR,
	    "Version: %s%s%s",
	    PACKAGE_STRING,
	    strlen(PACKAGE_URL) ?
		" distributed from " PACKAGE_URL : "" ,
	    strlen(PACKAGE_BUGREPORT) ?
		", report bugs to " PACKAGE_BUGREPORT : "" );
	mg_log(LOG_ERR,
	    "usage: %s [-A] [-a autowhite_delay] [-c] [-D] [-d dumpfile]",
	    progname);
	mg_log(LOG_ERR,
	    "       [-f configfile] [-h] [-l] [-q] [-r] [-S] [-T]");
	mg_log(LOG_ERR,
	    "       [-u username[:groupname]] [-v] [-w greylist_delay] [-L cidrmask]");
	mg_log(LOG_ERR,
	    "       [-M prefixlen] [-P pidfile] [-p socket]");
	exit(EX_USAGE);
}

void
mkparentdir(path, mode)
	char *path;
	mode_t mode;
{
	char *parent;
	char *pathcp;

	if ((pathcp = strdup(path)) == NULL) {
		mg_log(LOG_ERR, "strdup(\"%s\") failed", path);
		exit(EX_OSERR);
	}

	parent = dirname(pathcp);

	if ((strcmp(parent, ".") == 0) ||
	    (strcmp(parent, "..") == 0) ||
	    (strcmp(parent, "") == 0) ||
	    (strcmp(parent, "/") == 0))
		goto out;

	if (access(path, F_OK) != -1 || access(parent, F_OK) != -1)
		goto out;

	if (mkdir(parent, mode) == -1 || access(parent, F_OK) == -1) {
		mg_log(LOG_ERR, "mkdir(\"%s\") failed", parent);
		exit(EX_OSERR);
	}

out:
	free(pathcp);

	return;
}

static void
cleanup_sock(path)
	char *path;
{
	struct stat st;

	/* Does it exists? Get information on it if it does */
	if (stat(path, &st) != 0)
		return;

	/* Is it a socket? */
	if ((st.st_mode & S_IFSOCK) == 0)
		return;

	/* Remove the beast */
	(void)unlink(path);
	return;
}

static void
cleanup_pidfile(path)
	char *path;
{
	struct stat st;
	
	if (stat(path, &st) != 0)
		return;          /* pidfile does not exist */

	if ((st.st_mode & S_IFREG) == 0)
		return;    /* not a regular file */

	(void)unlink(path);
	return;
}

char *
strncpy_rmsp(dst, src, len)
	char *dst;
	char *src;
	size_t len;
{
	unsigned int i;

	for (i = 0; src[i] && (i < len); i++) {
		if (isgraph((int)(unsigned char)src[i]))
			dst[i] = src[i];
		else
			dst[i] = '_';
	}

	if (i < len)
		dst[i] = '\0';

	return dst;
}

int
humanized_atoi(str)	/* *str is modified */
	char *str;
{
	unsigned int unit;
	size_t len;
	char numstr[NUMLEN + 1];

	if (((len = strlen(str)) || (len > NUMLEN)) == 0)
		return 0;

	switch(str[len - 1]) {
	case 's':
		unit = 1;
		break;

	case 'm':
		unit = 60;
		break;

	case 'h':
		unit = 60 * 60;
		break;

	case 'd':
		unit = 24 * 60 * 60;
		break;

	case 'w':
		unit = 7 * 24 * 60 * 60;
		break;

	/* For msgsize clauses */
	case 'k':
		unit = 1024;
		break;

	case 'M':
		unit = 1024 * 1024;
		break;

	/* Giga and beyond is probably useless... */

	default:
		return atoi(str);
		break;
	}

	strncpy(numstr, str, NUMLEN);
	numstr[len - 1] = '\0';

	return (atoi(numstr) * unit);
}

static char *
gmtoffset(date, buf, size)
	time_t *date;
	char *buf;
	size_t size;
{
	struct tm gmt;
	struct tm local;
	int offset;
	char *sign;
	int h, mn;

	gmtime_r(date, &gmt);
	localtime_r(date, &local);

	offset = local.tm_min - gmt.tm_min;
	offset += (local.tm_hour - gmt.tm_hour) * 60;

	/* Offset cannot be greater than a day */
	if (local.tm_year <  gmt.tm_year)
		offset -= 24 * 60;
	else
		offset += (local.tm_yday - gmt.tm_yday) * 60 * 24;

	if (offset >= 0) {
		sign = "+";
	} else {
		sign = "-";
		offset = -offset;
	}
	 
	h = offset / 60;
	mn = offset % 60;

	snprintf(buf, size, "%s%02d%02d", sign, h, mn);
	return buf;
}

static void
writepid(pidfile)
	char *pidfile;
{
	FILE *stream;

	errno = 0;
	mkparentdir(pidfile, 0755);
	if ((stream = Fopen(pidfile, "w")) == NULL) {
		mg_log(LOG_ERR, "Cannot open pidfile \"%s\" for writing: %s", 
		    pidfile, 
		    (errno == 0) ? "out of stdio streams" : strerror(errno));
		return;
	}

	fprintf(stream, "%ld\n", (long)getpid());
	Fclose(stream);

	return;
}


struct in_addr *
prefix2mask4(cidr, mask)
	int cidr;
	struct in_addr *mask;
{

	if ((cidr == 0) || (cidr > 32)) {
		bzero((void *)mask, sizeof(*mask));
	} else {
		cidr = 32 - cidr;
		mask->s_addr = htonl(~((1UL << cidr) - 1));
	}
	
	return mask;
}

#ifdef AF_INET6
struct in6_addr *
prefix2mask6(plen, mask)
	int plen;
	struct in6_addr *mask;
{
	int i;
	uint32_t m;

	if (plen == 0 || plen > 128)
		bzero((void *)mask, sizeof(*mask));
	else {
		for (i = 0; i < 16; i += 4) {
			if (plen < 32)
				m = ~(0xffffffff >> plen);
			else
				m = 0xffffffff;
			*(uint32_t *)&mask->s6_addr[i] = htonl(m);
			plen -= 32;
			if (plen < 0)
				plen = 0;
		}
	}

	return mask;
}
#endif

void
unmappedaddr(sa, salen)
	struct sockaddr *sa;
	socklen_t *salen;
{
#ifdef AF_INET6
	struct in_addr addr4;
	int port;       
			
	if (SA6(sa)->sin6_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(SADDR6(sa)))
		return;
	addr4.s_addr = *(uint32_t *)&SADDR6(sa)->s6_addr[12];
	port = SA6(sa)->sin6_port;
	bzero(sa, sizeof(struct sockaddr_in));
	SADDR4(sa)->s_addr = addr4.s_addr;
	SA4(sa)->sin_port = port;
	SA4(sa)->sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	SA4(sa)->sin_len = sizeof(struct sockaddr_in);
#endif
	*salen = sizeof(struct sockaddr_in);
#endif
	return;
}

void
log_and_report_greylisting(ctx, priv, rcpt)
	SMFICTX *ctx;
	struct mlfi_priv *priv;
	char *rcpt;
{
	int h, mn, s;
	char addrstr[IPADDRSTRLEN];
	time_t remaining;
	char *delayed_rj;
	char *aclstr;
	char *code = "451";
	char *ecode = "4.7.1";
	char *msg = conf.c_quiet ?
		"Greylisting in action, please come back later" :
		"Greylisting in action, please come back in %R";

	/*
	 * The message has been added to the greylist and will be delayed.
	 * Log this and report to the client.
	 */
	iptostring(SA(&priv->priv_addr), priv->priv_addrlen, addrstr,
	    sizeof(addrstr));

	remaining = priv->priv_sr.sr_remaining;
	h = remaining / 3600;
	remaining = remaining % 3600;
	mn = (remaining / 60);
	remaining = remaining % 60;
	s = remaining;

	if (priv->priv_delayed_reject)
		delayed_rj = " after DATA phase";
	else
		delayed_rj = "";

	aclstr = fstring_expand(priv, NULL, " (ACL %a)", NULL);

	if (!(priv->priv_sr.sr_whitelist & EXF_NOLOG)) {
		mg_log(LOG_INFO, 
			"%s: addr %s[%s] from %s to %s delayed%s for %02d:%02d:%02d%s",
			priv->priv_queueid, priv->priv_hostname, addrstr, 
			priv->priv_from, rcpt, delayed_rj, h, mn, s, aclstr);
	}

	set_sr_defaults(priv, code, ecode, msg);
	mg_setreply(ctx, priv, rcpt);
	free(aclstr);
	return;
}

#ifdef	USE_DRAC
#ifndef O_SHLOCK
#define O_SHLOCK 0
#endif /* O_SHLOCK */
static int
check_drac(dotted_ip)
	char *dotted_ip;
{
	DB *ddb;
	DBT key, data;
	char ipkey[64];
	int rc;

	ddb = dbopen(conf.c_dracdb, O_RDONLY | O_SHLOCK, 0666, DB_BTREE, NULL);
	if (ddb == NULL) {
		mg_log(LOG_DEBUG, "dbopen \"%s\" failed", conf.c_dracdb);
		return 0;
	}

	key.data = strncpy(ipkey, dotted_ip, sizeof(ipkey));
	ipkey[sizeof(ipkey) - 1] = '\0';
	key.size = strlen(ipkey);
	rc = ddb->get(ddb, &key, &data, 0);
	ddb->close(ddb);

	switch (rc) {
	case 0:
#ifdef TEST
		mg_log(LOG_DEBUG, "key.data=%.*s (len=%d) "
		    "data.data=%.*s (len=%d)",
		    key.size, key.data, key.size,
		    data.size, data.data, data.size);
#endif /* TEST */
		return 1;
		break;

	case 1:
		return 0;
		break;

	default:
		mg_log(LOG_ERR, "check_drac: errno=%d", errno);
		break;
	}

	return 0;
}
#endif	/* USE_DRAC */

static void 
smtp_reply_init(sr)
	struct smtp_reply *sr;
{
	memset(sr, 0, sizeof(*sr));
	sr->sr_retcode = -1;
	/* sr->sr_elapsed = (time_t)0xdeadbeefU; */
	sr->sr_delay = conf.c_delay;
	sr->sr_autowhite = conf.c_autowhite_validity;
	sr->sr_tarpit = conf.c_tarpit;

	return;
}

static void 
smtp_reply_free(sr)
	struct smtp_reply *sr;
{
	if (sr->sr_acl_id)
		free(sr->sr_acl_id);
	free(sr->sr_code);
	free(sr->sr_ecode);
	free(sr->sr_msg);
	free(sr->sr_msg_x);
	free(sr->sr_report);
	free(sr->sr_report_x);
	if (sr->sr_addheader)
		free(sr->sr_addheader);
	if (sr->sr_addfooter)
		free(sr->sr_addfooter);

	if (sr->sr_pmatch) {
		int i;		

		for (i = 0; i < sr->sr_nmatch; i++)
			if (sr->sr_pmatch[i] != NULL)
				free(sr->sr_pmatch[i]);
		free(sr->sr_pmatch);
	}

	return;
}

static void 
reset_acl_values(priv)
	struct mlfi_priv *priv;
{
	smtp_reply_free(&priv->priv_sr);
	smtp_reply_init(&priv->priv_sr);

	return;
}


#ifndef HAVE_STRLCAT
size_t
mystrlcat(dst, src, len)
	char *dst;
	const char *src;
	size_t len;
{
	size_t srclen = strlen(src);
	size_t dstlen;

	for (dstlen = 0; dstlen != len && dst[dstlen]; ++dstlen)
		;
	if (dstlen == len) {
#if 0
		/* BSD's strlcat leaves the string not NUL-terminated. */
		return dstlen + srclen;
#else
		/* This situation is a bug. We make core dump. */
		abort();
#endif
	}
	strncpy(dst + dstlen, src, len - dstlen - 1);
	dst[len - 1] = '\0';
	return dstlen + srclen;
}
#endif

#ifndef HAVE_VSYSLOG
#ifndef LINE_MAX
#define LINE_MAX 1024
#endif /* LINE_MAX */
void
vsyslog(level, fmt, ap)
	int level;
	char *fmt;
	va_list ap;
{
	char messagebuf[LINE_MAX];

	vsnprintf(messagebuf, sizeof(messagebuf), fmt, ap);
	messagebuf[sizeof(messagebuf) - 1] = '\0';
	syslog(level, "%s", messagebuf);

	return;
}
#endif /* HAVE_VSYSLOG */

/* VARARGS */
void
mg_log(int level, char *fmt, ...) {
	va_list ap;
	int logfac;

	if (conf_cold) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		va_end(ap);
		return;
	}

	if (!GET_CONF()) {
		conf_retain();
		logfac = conf.c_logfac;
		conf_release();
	} else {
		logfac = conf.c_logfac;
	}

	if (logfac == -1) {
		return;
	}

	va_start(ap, fmt);
	vsyslog(logfac | level, fmt, ap);
	va_end(ap);
	return;
}

static void
add_recipient(priv, rcpt)
	struct mlfi_priv *priv;
	char *rcpt;
{
	struct rcpt *nr;

	if ((nr = malloc(sizeof(*nr))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	strncpy(nr->r_addr, rcpt, sizeof(nr->r_addr));
	nr->r_addr[ADDRLEN] = '\0';

	LIST_INSERT_HEAD(&priv->priv_rcpt, nr, r_list);
	priv->priv_rcptcount++;
	return;
}

static void
mystrncat(s, append, slenmax, cv)
	char **s;
	char *append;
	size_t *slenmax;
	char *(*cv)(char *);
{
	char *append_esc = NULL;
	char *str = *s;
	size_t alen;
	size_t slen;

	if (cv != NULL) {
		if ((append_esc = cv(append)) != NULL)
			append = append_esc;
	}

	slen = strlen(*s);
	alen = strlen(append);

	if (slen + alen > *slenmax) {
		if (conf.c_debug)
			mg_log(LOG_DEBUG, "resize url buffer %d -> %d",
			    *slenmax, slen + alen);

		if ((str = realloc(str, slen + alen + 1)) == NULL) {
			mg_log(LOG_ERR, "malloc(%d) failed",
			    slen + alen + 1, strerror(errno));
			exit(EX_OSERR);
		}
		*slenmax = slen + alen;
		*s = str;
	}

	memcpy(str + slen, append, alen);
	str[slen + alen] = '\0';

	if (cv && append_esc)
		free(append_esc);

	return;
}

static char *
strip_brackets(out, in, len)
	char *out;
	char *in;
	size_t len;
{
	char *outp;
	size_t outlen;

	/* Strip leading and trailing <> */
	(void)strncpy(out, in, len);
	out[len] = '\0';

	outp = out;
	if (outp[0] == '<')
		outp++;

	outlen = strlen(outp);
	if ((outlen > 0) && 
	    (outp[outlen - 1] == '>'))
		outp[outlen - 1] = '\0';

	return outp;
}

static char *
mbox_only(out, in, len)
	char *out;
	char *in;
	size_t len;
{
	char *outp;
	char *ap;

	outp = strip_brackets(out, in, len);
	if ((ap = index(outp, (int)'@')) != NULL)
		*ap = '\0';

	return outp;
}

static char *
site_only(out, in, len)
	char *out;
	char *in;
	size_t len;
{
	char *outp;
	char *ap;

	outp = strip_brackets(out, in, len);
	if ((ap = index(outp, (int)'@')) != NULL)
		outp = ap + 1;

	return outp;
}

static char *
machine_only(out, in, len)
	char *out;
	char *in;
	size_t len;
{
	char *outp;
	char *ap;

	outp = strip_brackets(out, in, len);
	if ((ap = index(outp, (int)'.')) != NULL)
		*ap = '\0';

	return outp;
}

static char *
domain_only(out, in, len)
	char *out;
	char *in;
	size_t len;
{
	char *outp;
	char *ap;

	outp = strip_brackets(out, in, len);
	if ((ap = index(outp, (int)'.')) != NULL)
		outp = ap + 1;

	return outp;
}

/*
 * fstring_expand had initially been introduced to craft URL.
 * outmaxlen was therefore set to URLMAXLEN, that is 255. 
 * It evolved into a ubuquitous tool used everywhere in 
 * milter-greylist sources, with the need of longer output
 * strings. outmaxlen is not initialized to QSTRLEN, which
 * has been increased to 4096. This means it is possible 
 * to output longer URL. This could cause trouble, but 
 * it does not violate any standard, therefore we live with it.
 */

char *
fstring_expand(priv, rcpt, fstring, cv)
	struct mlfi_priv *priv;
	char *rcpt;
	const char *fstring;
	char *(*cv)(char *);
{
	size_t offset;
	char *outstr;
	size_t outmaxlen = QSTRLEN;
	char *tmpstr;
	char *tmpstrp;
	char *last = NULL;
	char *ptok;
	int fstr_len;	/* format string length, minus the % (eg: %mr -> 2) */
	int skip_until_brace_close = 0;

	/* 
	 * Shortcut if there is nothing to substitute 
	 */
	if (strchr(fstring, '%') == NULL) {
		if ((outstr = strdup(fstring)) == NULL) {
			mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
			exit(EX_OSERR);
		}
		return outstr;
	}
		
	/*
	 * The rcpt argument is not really mandatory since we can
	 * figure out what the recipient is. The operation below
	 * catches the numerous location where fstring_expand()
	 * was called with NULL rcpt. The rcpt argument should
	 * probably be removed.
	 */
	if ((rcpt == NULL) && (priv->priv_cur_rcpt[0] != '\0'))
		rcpt = priv->priv_cur_rcpt;

	if ((outstr = malloc(outmaxlen + 1)) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	outstr[0] = '\0';

	if ((tmpstr = strdup(fstring)) == NULL) {
		mg_log(LOG_ERR, "strdup() failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	tmpstrp = tmpstr;
	fstr_len = 0;

	while ((ptok = strtok_r(tmpstrp, "%", &last)) != NULL) {
		char tmpaddr[ADDRLEN + 1];

		if (skip_until_brace_close) {
			char *cp;

			for (cp = ptok; *cp; cp++)
				if (*cp == '}') 
					break;

			if (*cp == '\0')
				continue;

			skip_until_brace_close = 0;
			ptok = cp + 1;
			mystrncat(&outstr, ptok, &outmaxlen, NULL);
			continue;
		}

		/* 
		 * If first time, check if the first char was a '%'
		 */
		if (tmpstrp != NULL) {
			tmpstrp = NULL;
			if (fstring[0] != '%') {
				mystrncat(&outstr, ptok, &outmaxlen, NULL);
				continue;
			}
		}

		/* 
		 * On second time and later, ptok points on the 
		 * character following '%'
		 * Check if it could be a format string
		 */
		fstr_len = 1;

		switch (*ptok) {
		case 'h':	/* Hello string */
			mystrncat(&outstr, priv->priv_helo, &outmaxlen, cv);
			break;
		case 'd':	/* Sender machine DNS name */
			mystrncat(&outstr, priv->priv_hostname, &outmaxlen, cv);
			break;
		case 'f':	/* Sender e-mail */
			mystrncat(&outstr, 
			    strip_brackets(tmpaddr, priv->priv_from, ADDRLEN), 
			    &outmaxlen, cv);
			break;
		case 'r':	/* Recipient e-mail */
			if (rcpt != NULL)
				mystrncat(&outstr, 
					strip_brackets(tmpaddr, rcpt, ADDRLEN), 
					&outmaxlen, cv);
			break;
		case 'm': 	/* mailbox part of sender or receiver e-mail */
				/* Or machine part of DNS address */
			fstr_len = 2;

			switch(*(ptok + 1)) {
			case 'r':	/* Recipient */
				if (rcpt != NULL)
					mystrncat(&outstr, 
						mbox_only(tmpaddr, 
						      rcpt, 
						      ADDRLEN), 
						&outmaxlen, cv);
				break;
			case 'f':	/* Sender */
				mystrncat(&outstr, 
				    	mbox_only(tmpaddr, 
					      priv->priv_from, 
					      ADDRLEN), 
					&outmaxlen, cv);
				break;
			case 'd':	/* DNS name */
				mystrncat(&outstr, 
				    	machine_only(tmpaddr, 
					      priv->priv_hostname, 
					      ADDRLEN), 
					&outmaxlen, cv);
				break;
			default:
				fstr_len = 0;
				break;
			}
			break;
		case 's':	/* site part of sender or receiver e-mail */
				/* Or domain part of DNS address */
			fstr_len = 2;

			switch(*(ptok + 1)) {
			case 'r':	/* Recipient */
				if (rcpt != NULL)
					mystrncat(&outstr, 
						site_only(tmpaddr, 
						      rcpt, 
						      ADDRLEN), 
						&outmaxlen, cv);
				break;
			case 'f':	/* Sender */
				mystrncat(&outstr, 
				    	site_only(tmpaddr, 
					      priv->priv_from, 
					      ADDRLEN), 
					&outmaxlen, cv);
				break;
			case 'd':	/* DNS name */
				mystrncat(&outstr, 
				    	domain_only(tmpaddr, 
					      priv->priv_hostname, 
					      ADDRLEN), 
					&outmaxlen, cv);
				break;
			default:
				fstr_len = 0;
				break;
			}
			break;
		case 'i': {	/* Sender machine IP address */
			char ipstr[IPADDRSTRLEN + 1];

			iptostring(SA(&priv->priv_addr),
			    priv->priv_addrlen, ipstr, sizeof(ipstr));
			mystrncat(&outstr, ipstr, &outmaxlen, cv);
			break;
		}
		case 'j': {	/* Sender machine IP address, reversed */
			char ipstr[IPADDRSTRLEN + 1];
			char revipstr[IPADDRSTRLEN + 1];
			char *lasts, *cp;
			size_t len;

			iptostring(SA(&priv->priv_addr),
			    priv->priv_addrlen, ipstr, sizeof(ipstr));

			len = strlen(ipstr);
			(void)memset(revipstr, '.', len);
			revipstr[len] = '\0';

			/* XXX only works for IPv4? */
			for (lasts = NULL, cp = strtok_r(ipstr, ".", &lasts);
			     cp;
			     cp = strtok_r(NULL, ".", &lasts)) {
				size_t cplen = strlen(cp);
				(void)memcpy(revipstr + len - cplen, cp, cplen);
				len -= (cplen + 1); /* 1 for dot */
			}
			mystrncat(&outstr, revipstr, &outmaxlen, cv);
			break;
		}
		case 'D': {
#ifdef USE_DNSRBL
			char dnsrbl[QSTRLEN + 1];

			mystrncat(&outstr, 
				  dnsrbl_dump_matches(priv, dnsrbl, QSTRLEN),
				  &outmaxlen, cv);
#endif
			break;
		}

		case 'H': { /* SpamAssassin information */
#ifdef USE_SPAMD
			fstr_len = 2;
			switch(*(ptok + 1)) {
			case 's': { /* score */
				char buf[QSTRLEN + 1];
				(void)snprintf(buf, sizeof(buf), "%g",
				    (double)priv->priv_spamd_score10/10);
				mystrncat(&outstr, buf, &outmaxlen, cv);
				break;
				}
			}
#endif /* USE_SPAMD */
			break;
		}

		case 'I': {	/* Sender machine / cidr, eg: %I{/24} */
			char ipstr[IPADDRSTRLEN + 1];
			struct sockaddr_storage addr;
			socklen_t salen;
			int cidr = 0;
			ipaddr mask;
			int i;

			fstr_len = 0;

			if ((ptok[1] != '{') || (ptok[1] == '\0'))
				break;

			if ((ptok[2] != '/') || (ptok[2] == '\0'))
				break;

			for (i = 3; ptok[i] != '\0'; i++) {
				if (ptok[i] == '}') {
					fstr_len = i + 1;
					break;
				}

				if (!isdigit((int)(ptok[i])))
					break;

				cidr = (10 * cidr) + (ptok[i] - '0');
			}

			if (fstr_len == 0)
				break;

			if (cidr < 0)
				break;

			switch (SA(&priv->priv_addr)->sa_family) {
			case AF_INET:
				salen = sizeof(struct sockaddr_in);

				if (cidr > 32)
					break;

				memcpy(&addr, &priv->priv_addr, 
				    sizeof(struct sockaddr_in));
				prefix2mask4(cidr, &mask.in4);
				SADDR4(&addr)->s_addr &= mask.in4.s_addr;

				break;
#ifdef AF_INET6
			case AF_INET6:
				salen = sizeof(struct sockaddr_in6);

				if (cidr > 128)
					break;

				memcpy(&addr, &priv->priv_addr, 
				    sizeof(struct sockaddr_in6));
				prefix2mask6(cidr, &mask.in6);
				for (i = 0; i < 16; i += 4)
					*(uint32_t *)&SADDR6(&addr)->s6_addr[i] 
					&= *(uint32_t *)&mask.in6.s6_addr[i];

				break;
#endif
			default:
				mg_log(LOG_ERR, "unepxected sa_family");
				exit(EX_SOFTWARE);
				break;
			}

			iptostring(SA(&addr), salen, ipstr, sizeof(ipstr));
			mystrncat(&outstr, ipstr, &outmaxlen, cv);
			break;
		}
		case 'X': {
			char *string = NULL;

			fstr_len =  2;
			switch (ptok[1]) {
			case 'm':	/* SMTP message */
				string = priv->priv_sr.sr_msg_x;
				break;
			case 'c':	/* SMTP code */
				string = priv->priv_sr.sr_code;
				break;
			case 'e':	/* SMTP extended code */
				string = priv->priv_sr.sr_ecode;
				break;
			case 'h':	/* X-Greylist header */
				string = priv->priv_sr.sr_report_x;
				break;
			default:
				fstr_len = 0;
				break;
			}

			if (string != NULL)
				mystrncat(&outstr, string, &outmaxlen, cv);
			break;
		}

		case 'v':	/* milter-greylist version */
			mystrncat(&outstr, PACKAGE_VERSION, &outmaxlen, cv);
			break;

		case 'G': {	/* GMT offset (e.g.: -0100) */
			char tzstr[HDRLEN + 1];
			time_t t;

			t = time(NULL);
			gmtoffset(&t, tzstr, HDRLEN);
			mystrncat(&outstr, tzstr, &outmaxlen, cv);
			break;
		}
		case 'Q': { /* "Query" results */
			fstr_len =  2;
			switch(*(ptok + 1)) {
			case 's': /* SPF result */
#if (defined(HAVE_SPF) || defined(HAVE_SPF_ALT) || \
     defined(HAVE_SPF2_10) || defined(HAVE_SPF2))
				if (priv->priv_spf_result[0])
					mystrncat(&outstr, 
					  	priv->priv_spf_result,
					  	&outmaxlen, cv);
#else
				fstr_len = 0;
#endif
				break;
			case 'd': /* DKIM result */
#ifdef USE_DKIM
				if (priv->priv_dkim_result[0])
					mystrncat(&outstr, 
					  	priv->priv_dkim_result,
					  	&outmaxlen, cv);
#else
				fstr_len = 0;
#endif
				break;
			case 'A': { /* Authentication-Results header value */
				char host[ADDRLEN + 1];
				char output[HDRLEN + 1];
				char *fqdn;
				int cx;

				fqdn = smfi_getsymval(priv->priv_ctx, "{j}");
				if (fqdn == NULL) {
					mg_log(LOG_DEBUG, 
					  "smfi_getsymval failed for {j}");
					gethostname(host, ADDRLEN);
					fqdn = host;
				}

				cx = snprintf(output, HDRLEN, "%s", fqdn);

#if (defined(HAVE_SPF) || defined(HAVE_SPF_ALT) || \
     defined(HAVE_SPF2_10) || defined(HAVE_SPF2))
				if ((cx < HDRLEN) && priv->priv_spf_result[0]) {
					char tmpfrom[
						strlen(priv->priv_from) - 1];

					memcpy(tmpfrom,
						priv->priv_from + 1,
						sizeof(tmpfrom) - 1);
					tmpfrom[sizeof(tmpfrom) - 1] = '\0';

					cx += snprintf(output+cx, HDRLEN-cx,
					      ";\r\n\tspf=%s smtp.mailfrom=%s",
					      priv->priv_spf_result, tmpfrom);
				}
#endif
#ifdef USE_DKIM
				if ((cx < HDRLEN) &&
					priv->priv_dkim_result[0]) {
					DKIM_SIGINFO *sig=NULL;
					unsigned const char *domain;
					cx += snprintf(output+cx, HDRLEN-cx,
						";\r\n\tdkim=%s",
						priv->priv_dkim_result);

					if (priv->priv_dkim != NULL)
						sig = dkim_getsignature(
							priv->priv_dkim);
					if ((cx < HDRLEN) && (sig != NULL) &&
					    ((domain = dkim_sig_getdomain(sig))
					     != NULL))
						cx += snprintf(output+cx,
						HDRLEN-cx, " header.d=%s",
						domain);
				}
#endif
				if ((cx < HDRLEN) && (cx == strlen(fqdn)))
					snprintf(output+cx, HDRLEN-cx,
						"; none");
				mystrncat(&outstr, output, &outmaxlen, cv);
				break;
			}
			case 'S': /* Received-SPF header value */
#ifdef HAVE_SPF2
				if (priv->priv_spf_header != NULL)
					mystrncat(&outstr, 
					  	priv->priv_spf_header,
					  	&outmaxlen, cv);
#else
				fstr_len = 0;
#endif
				break;
			default:
				fstr_len = 0;
				break;
			}
			break;
		}
		case 'C': {	/* Country code from GeoIP */
#if defined(USE_GEOIP) || defined(USE_GEOIP2)
			if (priv->priv_ccode != NULL)
				mystrncat(&outstr, 
					  priv->priv_ccode, 
					  &outmaxlen, cv);
#else
			fstr_len =  0;
#endif
			break;
		}
		case 'F': {	/* System fingerprint from P0F */
#ifdef USE_P0F
			char *string = NULL;

			fstr_len =  2;
			switch (ptok[1]) {
			case 'x':	/* Type + detail */
				string = priv->priv_p0f;
				break;
			default:
				fstr_len = 0;
				break;
			}

			if (string != NULL)
				mystrncat(&outstr, string, &outmaxlen, cv);
			break;
#else
			fstr_len =  0;
#endif
			break;
		}
		case 'E': {	/* elapsed time */
			int h, mn, s;
			char num[16];

			s = priv->priv_sr.sr_elapsed;	
			h = s / 3600;
			s = s % 3600;
			mn = s / 60;
			s = s % 60;

			fstr_len = 2;

			switch(*(ptok + 1)) {
			case 'h':	/* hours */
				snprintf(num, sizeof(num), "%d", h);
				break;
			case 'm':	/* minutes */
				snprintf(num, sizeof(num), "%d", mn);
				break;
			case 's':	/* seconds */
				snprintf(num, sizeof(num), "%d", s);
				break;
			case 't':	/* total in seconds */
				snprintf(num, sizeof(num), "%d",
				    (int)priv->priv_sr.sr_elapsed);
				break;
			default:	/* hh:mm:ss */
				fstr_len = 1;
				snprintf(num, sizeof(num), 
				    "%02d:%02d:%02d", h, mn, s);
				break;
			}
				
			mystrncat(&outstr, num, &outmaxlen, cv);
			break;
		}

		case 'R': {	/* remaining time */
			int h, mn, s;
			char num[16];

			s = priv->priv_sr.sr_remaining;
			h = s / 3600;
			s = s % 3600;
			mn = s / 60;
			s = s % 60;

			fstr_len = 2;

			switch(*(ptok + 1)) {
			case 'h':	/* hours */
				snprintf(num, sizeof(num), "%d", h);
				break;
			case 'm':	/* minutes */
				snprintf(num, sizeof(num), "%d", mn);
				break;
			case 's':	/* seconds */
				snprintf(num, sizeof(num), "%d", s);
				break;
			case 't':	/* total in seconds */
				snprintf(num, sizeof(num), "%d",
				    (int)priv->priv_sr.sr_remaining);
				break;
			default:	/* hh:mm:ss */
				fstr_len = 1;
				snprintf(num, sizeof(num), 
				    "%02d:%02d:%02d", h, mn, s);
				break;
			}

			mystrncat(&outstr, num, &outmaxlen, cv);
			break;
		}

		case 'V': {	/* milter-greylist-<version> <complete date> */
			char host[ADDRLEN + 1];
			char timestr[HDRLEN + 1];
			char tzstr[HDRLEN + 1];
			char tznamestr[HDRLEN + 1];
			char output[HDRLEN + 1];
			char *fqdn;
			time_t t;
			struct tm ltm;
			
			t = time(NULL);
			localtime_r(&t, &ltm);
			strftime(timestr, HDRLEN, "%a, %d %b %Y %T", &ltm);
			gmtoffset(&t, tzstr, HDRLEN);
			strftime(tznamestr, HDRLEN, "%Z", &ltm);

			fqdn = smfi_getsymval(priv->priv_ctx, "{j}");
			if (fqdn == NULL) {
				mg_log(LOG_DEBUG, 
				    "smfi_getsymval failed for {j}");
				gethostname(host, ADDRLEN);
				fqdn = host;
			}

			snprintf(output, HDRLEN, 
				 "milter-greylist-%s (%s [%s]); %s %s (%s)",
			         PACKAGE_VERSION, fqdn, local_ipstr(priv),
				 timestr, tzstr, tznamestr);
			mystrncat(&outstr, output, &outmaxlen, cv);
			break;
		}

		case 'g': {	/* regex match %g{\1} */
			int i;
			int nmatch = 0;

			fstr_len = 0;

			if ((ptok[1] != '{') || (ptok[1] == '\0'))
				break;

			if ((ptok[2] != '\\') || (ptok[2] == '\0'))
				break;

			for (i = 3; ptok[i] != '\0'; i++) {
				if (ptok[i] == '}') {
					fstr_len = i + 1;
					break;
				}

				if (!isdigit((int)(ptok[i])))
					break;

				nmatch = (10 * nmatch) + (ptok[i] - '0');
			}

			if (fstr_len == 0)
				break;

			if (nmatch == 0)
				break;

			if (nmatch > priv->priv_sr.sr_nmatch)
				break;

			if (priv->priv_sr.sr_pmatch[nmatch - 1] != NULL)
				mystrncat(&outstr, 
				    priv->priv_sr.sr_pmatch[nmatch - 1],
				    &outmaxlen, cv);

			break;
		}

		case 'T': {	/* current time %T{strftime_string} */
			const char *cp;
			time_t now;
			struct tm tm;
			char *format;

			if (*(ptok + 1) != '{')
				break;

			fstr_len = 2;

			/* 
			 * Lookup in the original string and not in tmpstr
			 * since strtok removed the next *
			 */
			offset = ((u_long)ptok + 2) - (u_long)tmpstr;
			for (cp = fstring + offset; *cp; cp++) {
				fstr_len++;
				if (*cp == '}')
					break;
			}

			/* No match, no substitution */
			if (*cp == '\0') {
				fstr_len = 0;
				break;
			}

			format = malloc(fstr_len + 1);
			if (format == NULL) {
				mg_log(LOG_ERR, "malloc failed: %s", 
				    strerror(errno));
				exit(EX_OSERR);
			}

			/* -3 to remove T{ after the % and trailing } */
			memcpy(format, fstring + offset, fstr_len - 3);
			format[fstr_len - 3] = '\0';

			now = time(NULL);
			(void)localtime_r(&now, &tm);
			(void)strftime(outstr + strlen(outstr), 
			    outmaxlen - strlen(outstr), format, &tm);
			
			free(format);

			/* We need to skip inside of %T{} */
			skip_until_brace_close = 1;
			break;
		}
		case 'M': { 	/* sendmail macro (maybe %Mj or %M{foo}) */
			char *cp;
			char *symval;
			char *symname;

			switch(*(ptok + 1)) {
			case '{':
				fstr_len = 2;
				/* Find the trailing } */
				for (cp = ptok + 2; *cp; cp++) {
					fstr_len++;
					if (*cp == '}')
						break;
				}

				/* No match, no substitution */
				if (*cp == '\0')
					fstr_len = 0;

				break;
			default:
				fstr_len = 2;
				break;
			}

			if (fstr_len == 0)
				break;

			symname = malloc(fstr_len + 1);
			if (symname == NULL) {
				mg_log(LOG_ERR, "malloc failed: %s", 
				    strerror(errno));
				exit(EX_OSERR);
			}
			/* +1/-1 to skip the M after the % */
			memcpy(symname, ptok + 1, fstr_len - 1);
			symname[fstr_len - 1] = '\0';

			symval = smfi_getsymval(priv->priv_ctx, symname);

#if 0
			if (conf.c_debug) 
				mg_log(LOG_DEBUG, 
				    "macro %s value = \"%s\"",
				    symname, 
				    (symval == NULL) ? "(null)" : symval);
#endif

			if (symval == NULL)
				symval = "";

			mystrncat(&outstr, symval, &outmaxlen, cv);

			free(symname);
			break;
		}
		case 'S': 	/* status returned to sendmail */
			switch (priv->priv_sr.sr_retcode) {
			case SMFIS_CONTINUE:
				mystrncat(&outstr, "accept", &outmaxlen, cv);
				break;
			case SMFIS_TEMPFAIL:
				mystrncat(&outstr, "tempfail", &outmaxlen, cv);
				break;
			case SMFIS_REJECT:
				mystrncat(&outstr, "reject", &outmaxlen, cv);
				break;
			case -1: /* Not known */
				break;
			default:
				mg_log(LOG_ERR, "unexpected sr_retcode = %d",
				    priv->priv_sr.sr_retcode);
				exit(EX_SOFTWARE);
				break;
			}
			break;
		case 'A': {	/* Line number for matching ACL */
			char buf[16];

			if (priv->priv_sr.sr_acl_line) {
				snprintf(buf, sizeof(buf), "%d", 
				   priv->priv_sr.sr_acl_line); 
				mystrncat(&outstr, buf, &outmaxlen, cv);
			} else {
				mystrncat(&outstr, "(none)", &outmaxlen, cv);
			}
			break;
		}	
		case 'a': {	/* id string for matching ACL */
			char buf[QSTRLEN + 1];

			if (priv->priv_sr.sr_acl_id) {
				snprintf(buf, sizeof(buf), "%s", 
				   priv->priv_sr.sr_acl_id); 
				mystrncat(&outstr, buf, &outmaxlen, cv);
			} else if (priv->priv_sr.sr_acl_line) {
				snprintf(buf, sizeof(buf), "%d", 
				   priv->priv_sr.sr_acl_line); 
				mystrncat(&outstr, buf, &outmaxlen, cv);
			}
			break;
		}	
		case 'c': {	/* currently evaluated ACL */
			fstr_len = 2;

			switch(*(ptok + 1)) {
			case 'A': {	/* Line number for current ACL */
				char buf[16];

				if (priv->priv_acl) {
					snprintf(buf, sizeof(buf), "%d", 
					   priv->priv_acl->a_line); 
					mystrncat(&outstr, buf, &outmaxlen, cv);
				} else {
					mystrncat(&outstr, "(none)", 
						  &outmaxlen, cv);
				}
				break;
			}	
			case 'a': {	/* id string for current ACL */
				char buf[QSTRLEN + 1];

				if (priv->priv_acl && priv->priv_acl->a_id) {
					snprintf(buf, sizeof(buf), "%s", 
					   priv->priv_acl->a_id); 
					mystrncat(&outstr, buf, &outmaxlen, cv);
				} else if (priv->priv_acl) {
					snprintf(buf, sizeof(buf), "%d", 
					   priv->priv_acl->a_line); 
					mystrncat(&outstr, buf, &outmaxlen, cv);
				}
				break;
			}	
			default:
				fstr_len = 0;
				break;
			}
			break;
		}
		case 't': {	/* tarpit time */
			char buf[32];

			snprintf(buf, sizeof(buf),
				 "%ld", (long)priv->priv_sr.sr_tarpit);
			mystrncat(&outstr, buf, &outmaxlen, cv);
			break;
		}
		case 'p': 	/* LDAP or CURL gathered props */
			fstr_len = 2;

			switch(*(ptok + 1)) {
			case 'r':	/* recipent we got the prop from */
				if ((priv->priv_prop_match == NULL) ||
				    (priv->priv_prop_match->up_rcpt == NULL)) {
					mystrncat(&outstr, "", &outmaxlen, cv);
					break;
				}

				mystrncat(&outstr, 
					  priv->priv_prop_match->up_rcpt,
					  &outmaxlen, cv);
				break;
			case 'n':	/* property name */
				mystrncat(&outstr, 
					  priv->priv_prop_match->up_name,
					  &outmaxlen, cv);
				break;
			case 'v':	/* property value */
				mystrncat(&outstr, 
					  priv->priv_prop_match->up_value,
					  &outmaxlen, cv);
				break;
			default:
				fstr_len = 0;
				break;
			}
			break;
		case 'P': { 	/* random prop value: %P{propname} */
			char *cp;
			char *value;
			char *name;

			switch(*(ptok + 1)) {
			case '{':
				fstr_len = 2;
				/* Find the trailing } */
				for (cp = ptok + 2; *cp; cp++) {
					fstr_len++;
					if (*cp == '}')
						break;
				}

				/* No match, no substitution */
				if (*cp == '\0')
					fstr_len = 0;

				break;
			default:
				fstr_len = 2;
				break;
			}

			if (fstr_len == 0)
				break;

			if ((name = malloc(fstr_len + 1)) == NULL) {
				mg_log(LOG_ERR, "malloc failed: %s", 
				    strerror(errno));
				exit(EX_OSERR);
			}
			/* +2/-3 to skip the leading P{ and trailing } */
			memcpy(name, ptok + 2, fstr_len - 3);
			name[fstr_len - 3] = '\0';

			if ((value = prop_byname(priv, name)) == NULL)
				value = "";

			mystrncat(&outstr, value, &outmaxlen, cv);

			free(name);
			break;
		}
		case '%':	/* Literal '%' */
			mystrncat(&outstr, "%", &outmaxlen, cv);
			break;
			
		default:
			fstr_len = 0;
			break;
		}

		/* 
		 * Special case for %T{}: no need to copy the 
		 * next chars until a %, as we want to skip until a }
		 */
		if (skip_until_brace_close)
			continue;

		/* 
		 * If no substitution was made, then keep the '%' 
		 * Otherwise, skip the format string
		 */
		if (fstr_len == 0)
			mystrncat(&outstr, "%", &outmaxlen, NULL);
		else
			ptok += fstr_len;

		mystrncat(&outstr, ptok, &outmaxlen, NULL);
	}

	free(tmpstr);

	return outstr;
}

char *
fstring_escape(fstring)
	char *fstring;
{
	char *cp;

	if (fstring == NULL)
		return NULL;

	for (cp = fstring; *cp != '\0'; cp++) {
		int slen;

		if (*cp != '\\')
			continue;

		slen = 0;
		switch(*(cp + 1)) {
		case '\0':
			return fstring;
			break;
		case 'a':	/* bell */
			*cp = '\a';
			slen = 1;
			break;
		case 'b':	/* backspace */
			*cp = '\f';
			slen = 1;
			break;
		case 'f':	/* formfeed */
			*cp = '\f';
			slen = 1;
			break;
		case 'n':	/* newline */
			*cp = '\n';
			slen = 1;
			break;
		case 'r':	/* carriage return */
			*cp = '\r';
			slen = 1;
			break;
		case 't':	/* horizontal tab */
			*cp = '\t';
			slen = 1;
			break;
		case 'v':	/* vertical tab */
			*cp = '\v';
			slen = 1;
			break;
		case '\\':	/* backslash */
			*cp = '\\';
			slen = 1;
			break;
		case '\?':	/* question mark */
			*cp = '\?';
			slen = 1;
			break;
		case '\'':	/* single quote */
			*cp = '\'';
			slen = 1;
			break;
		case '\"':	/* double quote */
			*cp = '\"';
			slen = 1;
			break;
		case '0': {	/* octal value */
			char c1, c2;
			
			if (*(cp + 2) == '\0')
				break;
			c1 = *(cp + 2);
			if (*(cp + 3) == '\0')
				break;
			c2 = *(cp + 2);

			if (isdigit((int)c1) && isdigit((int)c2)) {
				int d1, d2;

				d1 = c1 - '0';
				d2 = c2 - '0';
				*cp = (8 * d1) + d2;
				slen = 3;
			} 
			/* And we'll ignore \0 alone */
			break;
		}
		case 'x': {	/* hexadecimal value */
			char c1, c2;
			
			if (*(cp + 2) == '\0')
				break;
			c1 = *(cp + 2);
			if (*(cp + 3) == '\0')
				break;
			c2 = *(cp + 2);

			if (isxdigit((int)c1) && isxdigit((int)c2)) {
				int d1, d2;

				if (isdigit((int)c1))
					d1 = c1 - '0';
				else if (islower((int)c1))
					d1 = c1 - 'a';
				else
					d1 = c1 - 'A';

				if (isdigit((int)c2))
					d2 = c2 - '0';
				else if (islower((int)c2))
					d2 = c2 - 'a';
				else
					d2 = c2 - 'A';

				*cp = (16 * d1) + d2;
				slen = 3;
			} 
			break;
		}
		default: /* Unknown sequence, discard */
			slen = -1;
			break;
		}

		if (slen == -1)
			bcopy(cp + 1, cp, strlen(cp + 1) + 1);
		if (slen != 0)
			bcopy(cp + 1 + slen, cp + 1, strlen(cp + 1 + slen) + 1);
		slen = 0;
	}

	return fstring;
}

char *
local_ipstr(priv)
	struct mlfi_priv *priv;
{
	static int log_missing_if_addr = 1;
	char *ip;

	/* 
	 * Macro {if_addr} does not exist in Postfix and CommSuite
	 */
	ip = smfi_getsymval(priv->priv_ctx, "{if_addr}");
#ifdef AF_INET6
	/*
	 * XXX: sendmail doesn't return {if_addr} when connection is
	 * from ::1
	 */
	if (ip == NULL && SA(&priv->priv_addr)->sa_family == AF_INET6) {
		char buf[IPADDRSTRLEN];

		if (iptostring(SA(&priv->priv_addr), priv->priv_addrlen, buf,
		    sizeof(buf)) != NULL &&
		    strcmp(buf, "::1") == 0)
			ip = "IPv6:::1";
	}
#endif /* AF_INET6 */
	if (ip == NULL) {
		if (conf.c_localaddr_string[0] != '\0')
			return conf.c_localaddr_string;

		if (log_missing_if_addr) {
			mg_log(LOG_DEBUG,
			       "smfi_getsymval failed for {if_addr}, "
			       "consider setting localaddr option");
			log_missing_if_addr = 0;
		}
		ip = "0.0.0.0";
	}

	return ip;
}

static void
set_sr_defaults(priv, code, ecode, msg)
	struct mlfi_priv *priv;
	char *code;
	char *ecode;
	char *msg;
{	
	if (priv->priv_sr.sr_code == NULL) {
		if ((priv->priv_sr.sr_code = strdup(code)) == NULL) {
			mg_log(LOG_ERR, 
			    "strdup() failed: %s", 
			    strerror(errno));
			exit(EX_OSERR);
		}
	}

	if (priv->priv_sr.sr_ecode == NULL) {
		if ((priv->priv_sr.sr_ecode = strdup(ecode)) == NULL) {
			mg_log(LOG_ERR, 
			    "strdup() failed: %s", 
			    strerror(errno));
			exit(EX_OSERR);
		}
	}

	if (priv->priv_sr.sr_msg == NULL) {
		if ((priv->priv_sr.sr_msg = strdup(msg)) == NULL) {
			mg_log(LOG_ERR, 
			    "strdup() failed: %s", 
			    strerror(errno));
			exit(EX_OSERR);
		}
	}

	return;
}

static sfsistat 
stat_from_code(code)
	char *code;
{
	switch (*code) {
	case '5':
		return SMFIS_REJECT;
		break;	
	case '4':
	default:
		return SMFIS_TEMPFAIL;
		break;	
	}

	/* NOTREACHED */
	return SMFIS_TEMPFAIL;
}

#ifndef MAXREPLYLEN
#define MAXREPLYLEN 980
#endif

static int
mg_setreply(ctx, priv, rcpt)
	SMFICTX *ctx;
	struct mlfi_priv *priv;
	char *rcpt;
{
	int r;
	size_t len;

	if (priv->priv_sr.sr_msg_x != NULL) {
		free(priv->priv_sr.sr_msg_x);
		priv->priv_sr.sr_msg_x = NULL;
	}

	priv->priv_sr.sr_msg_x =
		fstring_expand(priv, rcpt, priv->priv_sr.sr_msg, NULL);

	if ((len = strlen(priv->priv_sr.sr_msg_x)) <= MAXREPLYLEN) {
		r = smfi_setreply(ctx,
				priv->priv_sr.sr_code, priv->priv_sr.sr_ecode,
				priv->priv_sr.sr_msg_x);
	} else {	/* multi line reply hell */
		int lcount;
		int i;
		char **lbufs;
		char *src;

		lcount = len / MAXREPLYLEN;
		if (len % MAXREPLYLEN != 0)
			lcount++;

		if ((lbufs = malloc(sizeof(*lbufs) * (lcount + 1))) == NULL) {
			mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		src = priv->priv_sr.sr_msg_x;
		for (i = 0; i < lcount; i++) {
			if ((lbufs[i] = malloc(MAXREPLYLEN + 1)) == NULL) {
				mg_log(LOG_ERR, "malloc failed: %s",
				       strerror(errno));
				exit(EX_OSERR);
			}

			(void)strncpy(lbufs[i], src, MAXREPLYLEN);
			lbufs[i][MAXREPLYLEN] = 0;

			src += MAXREPLYLEN;		
		}

		lbufs[i] = NULL;

		r = mg_setmlreply(ctx, 
				  priv->priv_sr.sr_code,
				  priv->priv_sr.sr_ecode,
				  lcount, lbufs);

		for (i = 0; i < lcount; i++)
			free(lbufs[i]);
		free(lbufs);

	}

	return r;
}


static int
resolve_bracketed(addr)
	char *addr;
{
#if defined(HAVE_GETNAMEINFO) && defined(HAVE_GETADDRINFO)
	size_t len;
	struct addrinfo hint;
	struct addrinfo *res;
	char abuf[IPADDRSTRLEN];
	int rc;

	len = strlen(addr);
	if ((len < 3) || (addr[0] != '[') || (addr[len - 1] != ']'))
		return 0;

	/*
	 * Strip leading and trailing brackets. If the MTA
	 * inserted a leading "IPv6:", also stip it.
	 */
	if (strncmp(addr, "[IPv6:", 6) == 0) {
		(void)strncpy(abuf, addr + 6, len - 7);
		abuf[len - 7] = '\0';
	} else {
		(void)strncpy(abuf, addr + 1, len - 2);
		abuf[len - 2] = '\0';
	}

	(void)memset(&hint, 0, sizeof(hint));
	hint.ai_flags = AI_NUMERICHOST;
	
	if ((rc = getaddrinfo(abuf, NULL, &hint, &res)) != 0) {
		mg_log(LOG_ERR, "failed parsing %s: %s", 
		     addr, gai_strerror(rc));		
		return -1;
	}
           
	rc = getnameinfo(res->ai_addr, res->ai_addrlen,
			 abuf, IPADDRSTRLEN, NULL, 0, NI_NAMEREQD);
	if (rc == 0) {
		if (conf.c_debug)
			mg_log(LOG_DEBUG, "Unbracketed '%s' into '%s'",
			       addr, abuf);
		(void)strncpy(addr, abuf, IPADDRSTRLEN);
		addr[IPADDRSTRLEN] = '\0';
	} else {
		mg_log(LOG_INFO, "failed resolving %s: %s", 
		       addr, gai_strerror(rc));		
	}

	freeaddrinfo(res);
#else
	mg_log(LOG_ERR, "unbracket option set whithout "
	       "getaddrinfo(3) or getnameinfo(3) support";
#endif /* HAVE_GETNAMEINFO && HAVE_GETADDRINFO */
	return 0;
}


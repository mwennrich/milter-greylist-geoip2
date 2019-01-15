/* $Id: prop.c,v 1.17 2015/06/18 03:42:48 manu Exp $ */

/*
 * Copyright (c) 2006-2012 Emmanuel Dreyfus
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
__RCSID("$Id: prop.c,v 1.17 2015/06/18 03:42:48 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>
#include <sysexits.h>
#include <signal.h>
#include <fnmatch.h>

#if defined(HAVE_OLD_QUEUE_H) || !defined(HAVE_SYS_QUEUE_H) 
#include "queue.h"
#else 
#include <sys/queue.h>
#endif
#include <sys/types.h>

#include "milter-greylist.h"
#include "pending.h"
#include "spf.h"
#include "acl.h"
#include "conf.h"
#include "sync.h"
#include "prop.h"

#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif

#ifndef FNM_CASEFOLD
#define FNM_CASEFOLD 0	/* non portable extension */
#endif

static void
_prop_push(linep, valp, clear, priv, dolower)
	char *linep;
	char *valp;
	int clear;
	struct mlfi_priv *priv;
	int dolower;
{
	char *cp;
	struct prop *up;

	if ((up = malloc(sizeof(*up))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if ((up->up_name = strdup(linep)) == NULL) {
		mg_log(LOG_ERR, "strup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if ((up->up_value = strdup(valp)) == NULL) {
		mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	/*
	 * Convert everything to lower-case
	 */
	if (dolower) {
		for (cp = up->up_name; *cp; cp++)
			*cp = (char)tolower((int)*cp);

		for (cp = up->up_value; *cp; cp++)
			*cp = (char)tolower((int)*cp);
	}

	up->up_flags = UP_PLAINPROP|UP_TMPPROP;
	if (clear)
		up->up_flags |= UP_CLEARPROP;

	/*
	 * If called at RCPT stage, record the recipient
	 */
	if (priv->priv_cur_rcpt[0] != '\0') {
		if ((up->up_rcpt = strdup(priv->priv_cur_rcpt)) == NULL) {
			mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
			exit(EX_OSERR);
		}
	} else {
		up->up_rcpt = NULL;
	}

	LIST_INSERT_HEAD(&priv->priv_prop, up, up_list);

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "got prop $%s = \"%s\"", linep, valp);

	return;
}

void
prop_push(linep, valp, clear, priv)
	char *linep;
	char *valp;
	int clear;
	struct mlfi_priv *priv;
{
	_prop_push(linep, valp, clear, priv, 1);
}


int 
prop_string_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv; 
{
	struct prop *up;
	acl_data_t *upd;
	char *string;
	int retval = 0;

	upd = ad->prop->upd_data;
	string = fstring_expand(priv, NULL, upd->string, NULL);

	LIST_FOREACH(up, &priv->priv_prop, up_list) {
		if (strcasecmp(ad->prop->upd_name, up->up_name) != 0)
			continue;

		if (conf.c_debug)
			mg_log(LOG_DEBUG, "test $%s = \"%s\" vs \"%s\"",
			    up->up_name, up->up_value, string);

		if (strcasecmp(up->up_value, string) == 0) {
			priv->priv_prop_match = up;
			retval = 1;
			break;
		}
	}

	free(string);	
	return retval;
}

int 
prop_glob_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv; 
{
	struct prop *up;
	acl_data_t *upd;
	char *string;
	int retval = 0;

	upd = ad->prop->upd_data;
	string = fstring_expand(priv, NULL, upd->string, NULL);

	LIST_FOREACH(up, &priv->priv_prop, up_list) {
		if (strcasecmp(ad->prop->upd_name, up->up_name) != 0)
			continue;

		if (conf.c_debug)
			mg_log(LOG_DEBUG, "test $%s = \"%s\" vs \"%s\"",
			    up->up_name, up->up_value, string);

		if (fnmatch(up->up_value, string, FNM_CASEFOLD) == 0) {
			priv->priv_prop_match = up;
			retval = 1;
			break;
		}
	}

	free(string);	
	return retval;
}

void
prop_opnum_add(ad, data)
	acl_data_t *ad;
	void *data;
{
	struct acl_opnum_prop *aonp;

	aonp = (struct acl_opnum_prop *)data;

	if ((ad->aonp = malloc(sizeof(*ad->aonp))) == NULL) {
		mg_log(LOG_ERR, "malloc() failed");
		exit(EX_OSERR);
	}

	ad->aonp->aonp_op = aonp->aonp_op;
	ad->aonp->aonp_type = aonp->aonp_type;
	if ((ad->aonp->aonp_name = strdup(aonp->aonp_name)) == NULL) {
		mg_log(LOG_ERR, "strdup() failed");
		exit(EX_OSERR);
	}

	return;
}

void
prop_opnum_free(ad)
	acl_data_t *ad;
{
	free(ad->aonp->aonp_name);
	free(ad->aonp);
	return;
}


char *
prop_opnum_print(ad, buf, len)
	acl_data_t *ad;
	char *buf;
	size_t len;
{
	struct {
		enum operator op;
		char *str;
	} op_to_str[] = {
		{ OP_EQ, "==" },
		{ OP_NE, "!=" },
		{ OP_GT, ">" },
		{ OP_LT, "<" },
		{ OP_GE, ">=" },
		{ OP_LE, "<=" },
	};
	int i;
	char *str = NULL;

	for (i = 0; i < sizeof(op_to_str) / sizeof(*op_to_str); i++) {
		if (op_to_str[i].op == ad->aonp->aonp_op) {
			str = op_to_str[i].str;
			break;
		}
	}
	if (str == NULL) {
		mg_log(LOG_ERR, "unexpected operator");
		exit(EX_SOFTWARE);
	}

	snprintf(buf, len, "%s $%s", str, ad->aonp->aonp_name);

	return buf;
}

int
prop_rhsnum_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv; 
{
	struct prop *up;
	struct acl_opnum_prop *aonp;
	int val1, val2;
	int retval = 0;

	aonp = ad->aonp;
	LIST_FOREACH(up, &priv->priv_prop, up_list) {
		if (strcasecmp(up->up_name, aonp->aonp_name) != 0)
			continue;

		if (conf.c_debug)
			mg_log(LOG_DEBUG, "test $%s = \"%s\" vs \"%s\"",
			    up->up_name, up->up_value, aonp->aonp_name);
	
		switch (aonp->aonp_type) {
		case AONP_MSGSIZE:
			val1 = priv->priv_msgcount;
			break;
		case AONP_RCPTCOUNT:
			val1 = priv->priv_rcptcount;
			break;
#ifdef USE_SPAMD
		case AONP_SPAMD:
			val1 = priv->priv_spamd_score10;
			break;
#endif /* USE_SPAMD */
		default:
			mg_log(LOG_ERR, "unexpected aonp_type");
			exit(EX_SOFTWARE);
		}
		val2 = atoi(up->up_value);
		
		retval = acl_opnum_cmp(val1, aonp->aonp_op, val2);
		break;
	}

	return retval;
}

int
prop_lhsnum_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv; 
{
	struct acl_opnum_data *aond;
	char *current;

	aond = ad->prop->upd_data;

	current = prop_byname(priv, ad->prop->upd_name);
	if (current == NULL)
		return 0;

	return acl_opnum_cmp(atoi(current), aond->op, aond->num);
}

int
prop_pop_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv; 
{
	struct acl_prop_pop *apop;
	char *lhs_str;
	char *rhs_str;

	apop = ad->apop;

	lhs_str = prop_byname(priv, apop->apop_lhs);
	if (lhs_str == NULL)
		lhs_str = "0";

	rhs_str = prop_byname(priv, apop->apop_rhs);
	if (rhs_str == NULL)
		rhs_str = "0";

	return acl_opnum_cmp(atoi(lhs_str), apop->apop_op, atoi(rhs_str));
}


void
prop_delete(up)
	struct prop *up;
{
	free(up->up_name);
	free(up->up_value);
	if (up->up_rcpt != NULL)
		free(up->up_rcpt);
	LIST_REMOVE(up, up_list);
	free(up);
}
	
void
prop_delete_byname(priv, name)
	struct mlfi_priv *priv; 
	char *name;
{
	struct prop *up;
	struct prop *nup;

	up = LIST_FIRST(&priv->priv_prop); 

	while (up != NULL) {
		nup = LIST_NEXT(up, up_list);
		if (strcmp(up->up_name, name) == 0)
			prop_delete(up);
		up = nup;
	}
	return;
}
	
void
prop_clear(priv, flags)
	struct mlfi_priv *priv; 
	int flags;
{
	struct prop *up;
	struct prop *nup;

	up = LIST_FIRST(&priv->priv_prop); 

	while (up != NULL) {
		nup = LIST_NEXT(up, up_list);
		if (up->up_flags & flags) {
			if (priv->priv_prop_match == up)
				priv->priv_prop_match = NULL;
			free(up->up_name);
			free(up->up_value);
			if (up->up_rcpt != NULL)
				free(up->up_rcpt);
			LIST_REMOVE(up, up_list);
			free(up);
		}
		up = nup;
	}
	return;
}

void
prop_untmp(priv)
	struct mlfi_priv *priv; 
{
	struct prop *up;

	LIST_FOREACH(up, &priv->priv_prop, up_list)
		up->up_flags &= ~UP_TMPPROP;
	return;
}

int 
prop_regex_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv; 
{
	struct prop *up;
	acl_data_t *upd;
	int retval = 0;

	upd = ad->prop->upd_data;

	LIST_FOREACH(up, &priv->priv_prop, up_list) {
		if (strcasecmp(ad->prop->upd_name, up->up_name) != 0)
			continue;

		if (conf.c_debug)
			mg_log(LOG_DEBUG, "test $%s = \"%s\" vs %s",
			    up->up_name, up->up_value, upd->regex.re_copy);

		if (myregexec(priv, upd, ap, up->up_value) == 0) {
			priv->priv_prop_match = up;
			retval = 1;
			break;
		}
	}

	return retval;
}

#define ERRLEN 1024
typedef enum { PBV_BODY, PBV_HEADER } pbv_t;

static int 
prop_data_validate(ad, stage, ap, priv, type)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv; 
	pbv_t type;
{
	struct prop *up;
	struct line *l;
	int retval = 0;
	char *typestr;
	struct bh_line *data;

	if (type == PBV_BODY) {
		typestr = "body";
		data = &priv->priv_body;
	} else {
		typestr = "header";
		data = &priv->priv_header;
	}

	if (stage != AS_DATA) {
		mg_log(LOG_ERR, "%s filter called at non DATA stage", typestr);
		exit(EX_SOFTWARE);
	}

	LIST_FOREACH(up, &priv->priv_prop, up_list) {
		size_t len;
		char *regexstr = NULL;
		regex_t regex;
		int is_regex;

		if (strcasecmp(ad->string, up->up_name) != 0)
			continue;

		if (conf.c_debug)
			mg_log(LOG_DEBUG, "test $%s = %s vs %s",
			    up->up_name, up->up_value, typestr);

		len = strlen(up->up_value);
		is_regex = 0;

		/*
		 * Regex case
		 */
		if (up->up_value[0] == '/' && up->up_value[len - 1] == '/') {
			char errstr[ERRLEN + 1];
			int fl;
			int error;

			if ((regexstr = strdup(up->up_value)) == NULL) {
				mg_log(LOG_ERR, "strdup failed");
				exit(EX_OSERR);
			}
			
			/* Strip trailing / */
			regexstr[len - 1] = '\0';
	
			fl = (REG_ICASE | REG_NEWLINE | REG_NOSUB);
			if (conf.c_extendedregex)
				fl |= REG_EXTENDED;

			/* +1 to strip leading / */
			if ((error = regcomp(&regex, regexstr + 1, fl)) != 0) {
				regerror(error, &regex, errstr, ERRLEN);
				mg_log(LOG_WARNING, "bad regular expression "
				       "\"%s\": %s", regexstr, errstr);
				free(regexstr);
				continue;
        		}

			is_regex = 1;
		}


		/* 
		 * For each line
		 */
		TAILQ_FOREACH(l, data, l_list) {
			if (conf.c_debug)
				mg_log(LOG_DEBUG, "test $%s = %s vs \"%s\"",
				    up->up_name, up->up_value, l->l_line);

			/*
			 * substring match
			 */
			if (!is_regex) {
				if (strstr(l->l_line, up->up_value) != NULL) {
					priv->priv_prop_match = up;
					return 1;
				}
				continue;
			}

			/* 
			 * regex match
			 */
			if (regexec(&regex, l->l_line, 0, NULL, 0) == 0) {
				priv->priv_prop_match = up;
				retval = 1;
				break;
			}
		}

		if (is_regex) {
			regfree(&regex);
			free(regexstr);
		}

		if (retval == 1)
			return 1;
	}

	return 0;
}

int 
prop_body_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv; 
{
	return prop_data_validate(ad, stage, ap, priv, PBV_BODY);
}

int 
prop_header_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv; 
{
	return prop_data_validate(ad, stage, ap, priv, PBV_HEADER);
}

/* 
 * This does not cope well with multivalued props
 */
char *
prop_byname(priv, name)
	struct mlfi_priv *priv;
	char *name;
{
	struct prop *up;

	LIST_FOREACH(up, &priv->priv_prop, up_list) {
		if (strcasecmp(name, up->up_name) != 0)
			continue;

		return up->up_value;
	}
	
	return NULL;
}

static int 
_prop_eqset_string(ad, priv, clear)
	acl_data_t *ad; 
	struct mlfi_priv *priv;
	int clear;
{
	acl_data_t *upd;
	char *string;

	upd = ad->prop->upd_data;
	string = fstring_expand(priv, NULL, upd->string, NULL);

	/* Delete existing value, add new one */
	prop_delete_byname(priv, ad->prop->upd_name);
	_prop_push(ad->prop->upd_name, string, clear, priv, 0);

	free(string);

	/* always match */	
	return 1; 
}

static int 
_prop_incset_string(ad, priv, clear, coef)
	acl_data_t *ad; 
	struct mlfi_priv *priv;
	int clear;
	int coef;
{
	acl_data_t *upd;
	char *current;
	char *string;
	char newval[16]; /* 16 is enough for an int */

	current = prop_byname(priv, ad->prop->upd_name);
	if (current == NULL)
		current = "0";

	upd = ad->prop->upd_data;
	string = fstring_expand(priv, NULL, upd->string, NULL);

	(void)sprintf(newval, "%d", atoi(current) + (coef * atoi(string)));

	/* Delete existing value, add new one */
	prop_delete_byname(priv, ad->prop->upd_name);
	_prop_push(ad->prop->upd_name, newval, clear, priv, 0);

	free(string);

	/* always match */	
	return 1; 
}

static int 
_prop_eqset_prop(ad, priv, clear)
	acl_data_t *ad; 
	struct mlfi_priv *priv;
	int clear;
{
	acl_data_t *upd;
	char *string;

	upd = ad->prop->upd_data;
	string = prop_byname(priv, upd->string);

	if (string == NULL)
		string = "";

	/* Delete existing value, add new one */
	prop_delete_byname(priv, ad->prop->upd_name);
	_prop_push(ad->prop->upd_name, string, clear, priv, 0);

	/* always match */	
	return 1; 
}

static int 
_prop_incset_prop(ad, priv, clear, coef)
	acl_data_t *ad; 
	struct mlfi_priv *priv;
	int clear;
	int coef;
{
	acl_data_t *upd;
	char *current;
	char *string;
	char newval[16]; /* 16 is enough for an int */

	current = prop_byname(priv, ad->prop->upd_name);
	if (current == NULL)
		current = "0";

	upd = ad->prop->upd_data;
	string = prop_byname(priv, upd->string);

	if (string == NULL)
		goto out;

	(void)sprintf(newval, "%d", atoi(current) +(coef * atoi(string)));

	/* Delete existing value, add new one */
	prop_delete_byname(priv, ad->prop->upd_name);
	_prop_push(ad->prop->upd_name, newval, clear, priv, 0);

out:
	/* always match */	
	return 1; 
}

int
prop_eqset_string(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	return _prop_eqset_string(ad, priv, 0);
}

int 
prop_eqrset_string(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	return _prop_eqset_string(ad, priv, UP_CLEARPROP);
}

int
prop_incset_string(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	return _prop_incset_string(ad, priv, 0, 1);
}

int 
prop_incrset_string(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	return _prop_incset_string(ad, priv, UP_CLEARPROP, 1);
}

int
prop_decset_string(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	return _prop_incset_string(ad, priv, 0, -1);
}

int 
prop_decrset_string(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	return _prop_incset_string(ad, priv, UP_CLEARPROP, -1);
}

int
prop_eqset_prop(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	return _prop_eqset_prop(ad, priv, 0);
}

int 
prop_eqrset_prop(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	return _prop_eqset_prop(ad, priv, UP_CLEARPROP);
}

int
prop_incset_prop(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	return _prop_incset_prop(ad, priv, 0, 1);
}

int 
prop_incrset_prop(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	return _prop_incset_prop(ad, priv, UP_CLEARPROP, 1);
}

int
prop_decset_prop(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	return _prop_incset_prop(ad, priv, 0, -1);
}

int 
prop_decrset_prop(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	return _prop_incset_prop(ad, priv, UP_CLEARPROP, -1);
}

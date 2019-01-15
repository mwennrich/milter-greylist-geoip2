/* $Id: acl.h,v 1.57 2016/11/02 17:41:05 manu Exp $ */

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

#ifndef _ACL_H_
#define _ACL_H_

#include "config.h"
#if defined(HAVE_OLD_QUEUE_H) || !defined(HAVE_SYS_QUEUE_H)
#include "queue.h"
#else 
#include <sys/queue.h>
#endif

#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex.h>

typedef enum { A_GREYLIST, A_WHITELIST, A_BLACKLIST, A_CONTINUE, } acl_type_t;
typedef enum { AS_NONE, AS_RCPT, AS_DATA, AS_ANY, } acl_stage_t;
typedef enum { AT_NONE, AT_STRING, AT_REGEX, AT_NETBLOCK, AT_OPNUM, 
	       AT_CLOCKSPEC, AT_DNSRBL, AT_MX, AT_URLCHECK, AT_MACRO, 
	       AT_LIST, AT_PROP, AT_SPF, AT_DKIM, AT_NSUPDATE,
	       AT_LDAPCHECK, AT_TIME, AT_RATELIMIT } acl_data_type_t;

typedef enum {
	AC_NONE,
	AC_LIST,
	AC_EMAIL,
	AC_REGEX,
	AC_STRING,
	AC_STRING_PROP,
	AC_HELO,
	AC_HELO_RE,
	AC_HELO_LIST,
	AC_FROM,
	AC_FROM_RE,
	AC_FROM_LIST,
	AC_RAWFROM,
	AC_RAWFROM_RE,
	AC_RAWFROM_LIST,
	AC_RCPT,
	AC_RCPT_RE,
	AC_RCPT_LIST,
	AC_DOMAIN,
	AC_DOMAIN_RE,
	AC_DOMAIN_LIST,
	AC_NETBLOCK,
	AC_NETBLOCK_LIST,
	AC_BODY,
	AC_BODY_LIST,
	AC_BODY_RE,
	AC_BODY_PROP,
	AC_HEADER,
	AC_HEADER_LIST,
	AC_HEADER_RE,
	AC_HEADER_PROP,
	AC_DNSRBL,
	AC_DNSRBL_LIST,
	AC_MX,
	AC_MACRO,
	AC_MACRO_RE,
	AC_MACRO_LIST,
	AC_URLCHECK,
	AC_URLCHECK_LIST,
	AC_LDAPCHECK,
	AC_PROP_STR,
	AC_PROP_GLOB,
	AC_PROP_NUM,
	AC_PROP_PROP,
	AC_PROP_RE,
	AC_HEADERPROP,
	AC_AUTH,
	AC_AUTH_RE,
	AC_AUTH_LIST,
	AC_TLS,
	AC_TLS_RE,
	AC_TLS_LIST,
	AC_SPF,
	AC_DKIM,
	AC_MSGSIZE,
	AC_MSGSIZE_PROP,
	AC_RCPTCOUNT,
	AC_RCPTCOUNT_PROP,
	AC_CLOCKSPEC,
	AC_CLOCKSPEC_LIST,
	AC_GEOIP,
	AC_GEOIP_LIST,
	AC_P0F,
	AC_P0F_RE,
	AC_P0F_LIST,
	AC_SA,
	AC_SASCORE,
	AC_SASCORE_PROP,
	AC_TARPIT,
	AC_RATELIMIT,
	AC_NSUPDATE,
	AC_EQSET,
	AC_EQRSET,
	AC_INCSET,
	AC_INCRSET,
	AC_DECSET,
	AC_DECRSET,
	AC_EQSETPROP,
	AC_EQRSETPROP,
	AC_INCSETPROP,
	AC_INCRSETPROP,
	AC_DECSETPROP,
	AC_DECRSETPROP,
	AC_LOG,
} acl_clause_t;

typedef union acl_data acl_data_t;
struct acl_clause;
struct acl_param;

#include "pending.h"
#include "milter-greylist.h"
#ifdef USE_NSUPDATE
#include "nsupdate.h"
#endif

#define ACL_WRLOCK WRLOCK(acl_lock) 
#define ACL_RDLOCK RDLOCK(acl_lock) 
#define ACL_UNLOCK UNLOCK(acl_lock)

TAILQ_HEAD(acllist, acl_entry);

enum operator { OP_EQ, OP_NE, OP_GT, OP_LT, OP_GE, OP_LE };

struct acl_opnum_data {
	enum operator op;
	int num;
};

struct acl_netblock_data {
        struct sockaddr *addr;
        ipaddr *mask;
	socklen_t salen;
	int cidr;
};

struct acl_param {
	acl_type_t ap_type;
	time_t ap_delay;
	time_t ap_autowhite;
	time_t ap_tarpit;
	time_t ap_tarpitted;
	tarpit_scope_t ap_tarpit_scope;
	int ap_flags;
	char *ap_id;
	char *ap_code;
	char *ap_ecode;
	char *ap_msg;
	char *ap_report;
	char *ap_addheader;
	int ap_addheader_index;
	char *ap_addfooter;
	char *ap_subjtag;
	int ap_maxpeek;
	int ap_nmatch;
	char **ap_pmatch;
};

/* a_flags */
#define A_FLUSHADDR		0x001
#define A_FREE_CODE		0x002
#define A_FREE_ECODE		0x004
#define A_FREE_MSG		0x008
#define A_FREE_REPORT		0x010
#define A_FREE_ID		0x020
#define A_DROP_ACL		0x040
#define A_NOLOG			0x080
#define A_FREE_ADDHEADER	0x100
#define A_FREE_ADDFOOTER	0x200
#define A_FREE_SUBJTAG		0x400

struct all_list_entry;

union acl_data {
	struct acl_netblock_data netblock;
	char *string;
	struct {
		regex_t *re;
		char *re_copy;
		int nmatch;
	} regex;
	struct all_list_entry *list;
	struct macro_entry *macro;
#ifdef USE_DNSRBL
	struct dnsrbl_entry *dnsrbl;
#endif
#ifdef USE_MX
	int mx_cidr;
#endif
#ifdef USE_CURL
	struct urlcheck_entry *urlcheck;
#endif
#ifdef USE_LDAP
	struct ldapcheck_entry *ldapcheck;
#endif
	struct prop_data *prop;
	struct acl_opnum_prop *aonp;
	struct acl_prop_pop *apop;
	struct acl_opnum_data opnum;
	struct clockspec *clockspec;
#if (defined(HAVE_SPF) || defined(HAVE_SPF_ALT) || \
     defined(HAVE_SPF2_10) || defined(HAVE_SPF2))
	enum spf_status spf_status;
#endif
#ifdef USE_DKIM
	enum spf_status dkim_status;
#endif
	time_t time;
	struct ratelimit_conf *ratelimit_conf;
#ifdef USE_NSUPDATE
	struct nsupdate_entry *nsupdate;
#endif
};

struct acl_clause_rec {
	acl_clause_t acr_type;
	enum { UNIQUE, MULTIPLE_OK } acr_unicity;
	acl_stage_t acr_stage;
	char *acr_name;
	acl_data_type_t acr_data_type;
	acl_clause_t acr_list_type;
	acl_clause_t acr_item_type;
	long long acr_exf;
	char *(*acr_print)(acl_data_t *, char *, size_t);
	void (*acr_add)(acl_data_t *, void *data);
	void (*acr_free)(acl_data_t *);
	int (*acr_filter)(acl_data_t *, acl_stage_t, 
			  struct acl_param *, struct mlfi_priv *);
};

struct acl_clause {
	acl_clause_t ac_type;
	enum { PLAIN, NEGATED } ac_negation;
	union acl_data ac_data;
	struct acl_clause_rec *ac_acr;
	TAILQ_ENTRY(acl_clause) ac_list;
};

#define a_addr a_netblock.nb_addr
#define a_addrlen a_netblock.nb_addrlen
#define a_mask a_netblock.nb_mask

struct acl_entry {
	int a_line;
	char *a_id;
	acl_type_t a_type;
	acl_stage_t a_stage;
	TAILQ_HEAD(,acl_clause) a_clause;
	time_t a_delay;
	time_t a_autowhite;
	time_t a_tarpit;
	tarpit_scope_t a_tarpit_scope;
	int a_flags;
	char *a_code;
	char *a_ecode;
	char *a_msg;
	char *a_report;
	char *a_addheader;
	int a_addheader_index;
	char *a_addfooter;
	char *a_subjtag;
	int a_maxpeek;
	TAILQ_ENTRY(acl_entry) a_list;
};

extern int testmode;
extern pthread_rwlock_t acl_lock;

char *stage_string(acl_stage_t);
struct acl_clause_rec *get_acl_clause_rec(acl_clause_t);
struct acl_clause_rec *acl_list_item_fixup(acl_clause_t, acl_clause_t);
void acl_init(void);
void acl_drop(void);
void acl_clear(void);
void acl_add_clause(acl_clause_t, void *);
void acl_negate_clause(void);
void acl_add_delay(time_t);
void acl_add_autowhite(time_t);
void acl_add_tarpit_scope(tarpit_scope_t);
void acl_add_flushaddr(void);
void acl_add_nolog(void);
void acl_add_id(char *);
void acl_add_code(char *);
void acl_add_ecode(char *);
void acl_add_msg(char *);
void acl_add_report(char *);
void acl_add_addheader(char *, int);
void acl_add_addfooter(char *);
void acl_add_subjtag(char *);
void acl_add_maxpeek(int);
void acl_maxpeek_fixup(int);
struct acl_entry *acl_register_entry_first(acl_stage_t, acl_type_t);
struct acl_entry *acl_register_entry_last(acl_stage_t, acl_type_t);
int acl_filter(acl_stage_t, SMFICTX *, struct mlfi_priv *);
char *acl_entry(char *, size_t, struct acl_entry *);
void acl_dump(void);
int emailcmp(char *, char *);        

int acl_netblock_filter(acl_data_t *, acl_stage_t, 
			struct acl_param *, struct mlfi_priv *);
int acl_list_filter(acl_data_t *, acl_stage_t, 
		    struct acl_param *, struct mlfi_priv *);
int acl_tarpit_filter(acl_data_t *, acl_stage_t,
		    struct acl_param *, struct mlfi_priv *);
int acl_helo_strstr(acl_data_t *, acl_stage_t, 
		    struct acl_param *, struct mlfi_priv *);
int acl_helo_regexec(acl_data_t *, acl_stage_t, 
		     struct acl_param *, struct mlfi_priv *);
int acl_from_cmp(acl_data_t *, acl_stage_t, 
		 struct acl_param *, struct mlfi_priv *);
int acl_rawfrom_cmp(acl_data_t *, acl_stage_t, 
		 struct acl_param *, struct mlfi_priv *);
int acl_from_regexec(acl_data_t *, acl_stage_t, 
		 struct acl_param *, struct mlfi_priv *);
int acl_rawfrom_regexec(acl_data_t *, acl_stage_t, 
		 struct acl_param *, struct mlfi_priv *);
int acl_rcpt_cmp(acl_data_t *, acl_stage_t, 
		 struct acl_param *, struct mlfi_priv *);
int acl_rcpt_regexec(acl_data_t *, acl_stage_t, 
		 struct acl_param *, struct mlfi_priv *);
int acl_auth_strcmp(acl_data_t *, acl_stage_t, 
		    struct acl_param *, struct mlfi_priv *);
int acl_auth_regexec(acl_data_t *, acl_stage_t, 
		     struct acl_param *, struct mlfi_priv *);
int acl_tls_strcmp(acl_data_t *, acl_stage_t, 
		   struct acl_param *, struct mlfi_priv *);
int acl_tls_regexec(acl_data_t *, acl_stage_t, 
		    struct acl_param *, struct mlfi_priv *);
int acl_domain_cmp(acl_data_t *, acl_stage_t, 
	           struct acl_param *, struct mlfi_priv *);
int acl_domain_regexec(acl_data_t *, acl_stage_t, 
		       struct acl_param *, struct mlfi_priv *);
int acl_body_strstr(acl_data_t *, acl_stage_t, 
		    struct acl_param *, struct mlfi_priv *);
int acl_header_strstr(acl_data_t *, acl_stage_t, 
		      struct acl_param *, struct mlfi_priv *);
int acl_body_regexec(acl_data_t *, acl_stage_t, 
		     struct acl_param *, struct mlfi_priv *);
int acl_header_regexec(acl_data_t *, acl_stage_t, 
		       struct acl_param *, struct mlfi_priv *);
int acl_rcptcount_cmp(acl_data_t *, acl_stage_t, 
		      struct acl_param *, struct mlfi_priv *);
int acl_msgsize_cmp(acl_data_t *, acl_stage_t, 
		    struct acl_param *, struct mlfi_priv *);
int acl_opnum_cmp(int, enum operator, int);
int myregexec(struct mlfi_priv *, acl_data_t *, 
	      struct acl_param *, const char *);
int acl_modify_by_prop(char *, char *, struct acl_param *);
/* acl_filter() return codes */
#define	EXF_UNSET	0
#define	EXF_GREYLIST	(1LL << 0)
#define EXF_WHITELIST	(1LL << 1)

#define	EXF_DEFAULT	(1LL << 2)
#define	EXF_ADDR	(1LL << 3)
#define	EXF_DOMAIN	(1LL << 4)
#define	EXF_FROM	(1LL << 5)
#define	EXF_RCPT	(1LL << 6)
#define	EXF_AUTO	(1LL << 7)
#define	EXF_NONE	(1LL << 8)
#define	EXF_AUTH	(1LL << 9)
#define	EXF_SPF		(1LL << 10)
#define	EXF_NONIP	(1LL << 11)
#define	EXF_STARTTLS	(1LL << 12)
#define EXF_ACCESSDB	(1LL << 13)
#define EXF_DRAC	(1LL << 14)
#define EXF_DNSRBL	(1LL << 15)
#define EXF_BLACKLIST	(1LL << 16)
#define EXF_MACRO	(1LL << 17)
#define EXF_URLCHECK	(1LL << 18)
#define EXF_HEADER	(1LL << 19)
#define EXF_BODY	(1LL << 20)
#define EXF_MSGSIZE	(1LL << 21)
#define EXF_RCPTCOUNT	(1LL << 22)
#define EXF_CLOCKSPEC	(1LL << 23)
#define EXF_GEOIP	(1LL << 24)
#define EXF_PROP	(1LL << 25)
#define EXF_HELO	(1LL << 26)
#define EXF_LDAPCHECK	(1LL << 27)
#define EXF_NOLOG	(1LL << 28)
#define EXF_P0F		(1LL << 29)
#define EXF_SA		(1LL << 30)
#define EXF_TARPIT	(1LL << 31)
#define EXF_MX		(1LL << 32) /* Need long long (64b) */
#define	EXF_DKIM	(1LL << 33)
#endif /* _ACL_H_ */

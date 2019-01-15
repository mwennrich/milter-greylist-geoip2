/* $Id: nsupdate.h,v 1.2 2013/10/15 07:45:37 manu Exp $ */

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

#ifndef NSUPDATE_H
#define NSUPDATE_H

#include <resolv.h>
#include <arpa/nameser.h>

#include "acl.h"

#ifndef HAVE_RES_STATE
typedef struct __res_state *res_state;
#endif

void nsupdate_init(void);

struct tsig_entry {
	ns_tsig_key tse_tsig;
	LIST_ENTRY(tsig_entry) tse_list;
};

int tsig_add(char *, char *, char *);
struct ns_tsig_key *tsig_byname(char *);
void tsig_clear(void);

struct nsupdate_entry {
	res_state nse_res; /* for runtime only */
	char *nse_servers; /* for config only */
	char *nse_name;
	char *nse_rname;
	int nse_ttl;
	int nse_class;
	int nse_type;
	char *nse_rvalue;
	ns_tsig_key *nse_tsig;
	LIST_ENTRY(nsupdate_entry) nse_list;
};
int nsupdate_add_servers(char *);
int nsupdate_add_rname(char *);
int nsupdate_add_rvalue(char *);
int nsupdate_add_ttl(int);
int nsupdate_add_class(int);
int nsupdate_add_type(int);
int nsupdate_add_tsig(char *);
int nsupdate_add(char *);

int nsupdate_filter(acl_data_t *, acl_stage_t,
		    struct acl_param *, struct mlfi_priv *);
struct nsupdate_entry *nsupdate_byname(char *);
void nsupdate_clear(void);

#endif /* NSUPDATE_H */

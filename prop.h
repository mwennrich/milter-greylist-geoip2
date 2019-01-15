/* $Id: prop.h,v 1.10 2015/06/16 12:27:29 manu Exp $ */

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

#ifndef _PROP_H_
#define _PROP_H_

#include "config.h"

struct prop_data {
	char *upd_name;
	void *upd_data;
};

struct acl_opnum_prop {
	enum operator aonp_op;
	enum { AONP_MSGSIZE, AONP_RCPTCOUNT, AONP_SPAMD } aonp_type;
	char *aonp_name;
}; 

/* pop for PROP OP PROP */
struct acl_prop_pop {
	char *apop_rhs;
	enum operator apop_op;
	char *apop_lhs;
};

struct prop {
	char *up_name;
	char *up_value;
	int up_flags;
	char *up_rcpt;
	LIST_ENTRY(prop) up_list;
};

#define UP_CLEARPROP	0x04
#define UP_TMPPROP	0x08
#define UP_PLAINPROP	0x10

void prop_push(char *, char *, int, struct mlfi_priv *);
void prop_clear(struct mlfi_priv *, int);
void prop_untmp(struct mlfi_priv *);
char *prop_byname(struct mlfi_priv *, char *);
int prop_rhsnum_validate(acl_data_t *, acl_stage_t,
			 struct acl_param *, struct mlfi_priv *); 
int prop_lhsnum_validate(acl_data_t *, acl_stage_t,
			 struct acl_param *, struct mlfi_priv *); 
int prop_pop_validate(acl_data_t *, acl_stage_t,
		      struct acl_param *, struct mlfi_priv *); 
int prop_string_validate(acl_data_t *, acl_stage_t,
			 struct acl_param *, struct mlfi_priv *); 
int prop_glob_validate(acl_data_t *, acl_stage_t,
		       struct acl_param *, struct mlfi_priv *); 
int prop_regex_validate(acl_data_t *, acl_stage_t,
			struct acl_param *, struct mlfi_priv *); 
int prop_body_validate(acl_data_t *, acl_stage_t,
		       struct acl_param *, struct mlfi_priv *); 
int prop_header_validate(acl_data_t *, acl_stage_t,
			 struct acl_param *, struct mlfi_priv *); 

int prop_eqset_string(acl_data_t *, acl_stage_t,
		      struct acl_param *, struct mlfi_priv *);
int prop_eqrset_string(acl_data_t *, acl_stage_t,
		       struct acl_param *, struct mlfi_priv *);
int prop_incset_string(acl_data_t *, acl_stage_t,
		       struct acl_param *, struct mlfi_priv *);
int prop_incrset_string(acl_data_t *, acl_stage_t,
		        struct acl_param *, struct mlfi_priv *);
int prop_decset_string(acl_data_t *, acl_stage_t,
		       struct acl_param *, struct mlfi_priv *);
int prop_decrset_string(acl_data_t *, acl_stage_t,
		        struct acl_param *, struct mlfi_priv *);
int prop_eqset_prop(acl_data_t *, acl_stage_t,
		    struct acl_param *, struct mlfi_priv *);
int prop_eqrset_prop(acl_data_t *, acl_stage_t,
		     struct acl_param *, struct mlfi_priv *);
int prop_incset_prop(acl_data_t *, acl_stage_t,
		     struct acl_param *, struct mlfi_priv *);
int prop_incrset_prop(acl_data_t *, acl_stage_t,
		      struct acl_param *, struct mlfi_priv *);
int prop_decset_prop(acl_data_t *, acl_stage_t,
		     struct acl_param *, struct mlfi_priv *);
int prop_decrset_prop(acl_data_t *, acl_stage_t,
		      struct acl_param *, struct mlfi_priv *);

char *prop_opnum_print(acl_data_t *, char *, size_t);     
void prop_opnum_add(acl_data_t *, void *);
void prop_opnum_free(acl_data_t *);

#endif /* _PROP_H_ */

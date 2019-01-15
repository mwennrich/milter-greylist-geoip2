#include "spf.h"
#include "acl.h"

#ifndef NS_MAXDNAME
#define NS_MAXDNAME 1025 
#endif 

int mx_check(acl_data_t *, acl_stage_t,
			struct acl_param *, struct mlfi_priv *);

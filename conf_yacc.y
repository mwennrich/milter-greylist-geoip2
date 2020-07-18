%token TNUMBER ADDR IPADDR IP6ADDR CIDR HELO FROM RCPT EMAIL PEER AUTOWHITE
%token GREYLIST NOAUTH NOACCESSDB EXTENDEDREGEX NOSPF QUIET TESTMODE MULTIRACL
%token VERBOSE PIDFILE GLDUMPFILE QSTRING TDELAY SUBNETMATCH SUBNETMATCH6
%token SOCKET USER NODETACH REGEX REPORT NONE DELAYS NODELAYS ALL LAZYAW
%token GLDUMPFREQ GLTIMEOUT DOMAIN DOMAINNAME SYNCADDR SYNCSRCADDR
%token SYNCMAXQLEN PORT ACL WHITELIST DEFAULT STAR DELAYEDREJECT DB NODRAC
%token DRAC DUMP_NO_TIME_TRANSLATION LOGEXPIRED GLXDELAY DNSRBL LIST
%token OPENLIST CLOSELIST BLACKLIST FLUSHADDR CODE ECODE MSG SM_MACRO
%token UNSET URLCHECK RACL DACL GLHEADER BODY MAXPEEK STAT POSTMSG FORK
%token GETPROP CLEAR PROP AUTH TLS SPF MSGSIZE RCPTCOUNT OP NO SLASH MINUS
%token COMMA TIME GEOIPDB GEOIPV6DB GEOIP PASS FAIL SOFTFAIL NEUTRAL UNKNWON ERROR
%token SELF SPF_STATUS LDAPCONF LDAPCHECK LOGFAC LOGFAC_KERN LOGFAC_USER
%token LOGFAC_MAIL LOGFAC_DAEMON LOGFAC_AUTH LOGFAC_SYSLOG LOGFAC_LPR
%token LOGFAC_NEWS LOGFAC_UUCP LOGFAC_CRON LOGFAC_AUTHPRIV LOGFAC_FTP
%token LOGFAC_LOCAL0 LOGFAC_LOCAL1 LOGFAC_LOCAL2 LOGFAC_LOCAL3 LOGFAC_LOCAL4
%token LOGFAC_LOCAL5 LOGFAC_LOCAL6 LOGFAC_LOCAL7 P0F P0FSOCK DKIMCHECK
%token SPAMDSOCK SPAMDSOCKT SPAMD DOMAINEXACT ADDHEADER NOLOG LDAPBINDDN 
%token LDAPBINDPW TARPIT TARPIT_SCOPE SESSION COMMAND MX RATELIMIT KEY
%token DOMATCH DATA LOCALADDR ADDFOOTER CONTINUE FIXLDAPCHECK SUBJTAG
%token NOENCODE NOESCAPE TSIG NSUPDATE SERVERS RNAME RVALUE TTL CLASS TYPE
%token UNBRACKET SET RSET EQSET INCSET DECSET LOG RAWFROM
%token GEOIP2DB

%{
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: conf_yacc.y,v 1.129 2016/11/24 04:11:37 manu Exp $");
#endif
#endif

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <syslog.h>
#include <sysexits.h>
#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif
#include "conf.h"
#include "spf.h"
#include "acl.h"
#include "sync.h"
#include "list.h"
#include "macro.h"
#include "ratelimit.h"
#include "nsupdate.h"
#ifdef USE_DNSRBL
#include "dnsrbl.h"
#endif
#ifdef USE_CURL
#include "urlcheck.h"
#endif
#ifdef USE_LDAP
#include "ldapcheck.h"
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
#ifdef USE_SPAMD
#include "spamd.h"
#endif
#include "stat.h"
#include "clock.h"
#include "ratelimit.h"
#include "spf.h"
#include "milter-greylist.h"

#define LEN4 sizeof(struct sockaddr_in)
#define IP4TOSTRING(ip4, str) iptostring(SA(&(ip4)), LEN4, (str), IPADDRSTRLEN)

#define LEN6 sizeof(struct sockaddr_in6)
#define IP6TOSTRING(ip6, str) iptostring(SA(&(ip6)), LEN6, (str), IPADDRSTRLEN)

int conf_lex(void);
void conf_error(char *);

%}

%union	{
	struct sockaddr_in ipaddr;
#ifdef AF_INET6
	struct sockaddr_in6 ip6addr;
#else
	struct sockaddr_in ip6addr;	/* XXX: for dummy */
#endif
	int cidr;
	char email[ADDRLEN + 1];
	char domainname[ADDRLEN + 1];
	char qstring[QSTRLEN + 1];
	char delay[NUMLEN + 1];
	char regex[REGEXLEN + 1];
	enum operator op; 
	char prop[QSTRLEN + 1];
	enum spf_status spf_status;
	enum spf_status dkim_status;
	char spamdsockt[QSTRLEN + 1];
	int ratelimit_type;
	}
%type <ipaddr> IPADDR;
%type <ip6addr> IP6ADDR;
%type <cidr> CIDR;
%type <email> EMAIL;
%type <domainname> DOMAINNAME;
%type <delay> TDELAY;
%type <delay> TNUMBER;
%type <qstring> QSTRING;
%type <regex> REGEX;
%type <op> OP;
%type <prop> PROP;
%type <spf_status> SPF_STATUS;
%type <spamdsockt> SPAMDSOCKT;

%%
lines	:	lines netblock '\n' 
	|	lines fromaddr '\n' 
	|	lines rawfromaddr '\n' 
	|	lines rcptaddr '\n' 
	|	lines fromregex '\n' 
	|	lines rawfromregex '\n' 
	|	lines rcptregex '\n' 
	|	lines domainaddr '\n'
	|	lines domainregex '\n'
	|	lines peeraddr '\n' 
	|	lines verbose '\n' 
	|	lines dump_no_time_translation '\n'
	|	lines quiet '\n' 
	|	lines noauth '\n' 
	|	lines multiracl '\n' 
	|	lines noaccessdb '\n' 
	|	lines extendedregex '\n'
	|	lines unbracket '\n'
	|	lines nospf '\n' 
	|	lines delayedreject '\n' 
	|	lines testmode '\n' 
	|	lines autowhite '\n'
	|	lines greylist '\n'
	|	lines tarpit '\n'
	|	lines tarpit_scope '\n'
	|	lines pidfile '\n'
	|	lines dumpfile '\n'
	|	lines subnetmatch '\n'
	|	lines subnetmatch6 '\n'
	|	lines socket '\n'
	|	lines user '\n'
	|	lines geoipdb '\n'
	|	lines geoipv6db '\n'
	|	lines geoip2db '\n'
	|	lines nodetach '\n'
	|	lines lazyaw '\n'
	|	lines report '\n'
	|	lines logfac '\n'
	|	lines statdef '\n'
	|	lines dumpfreq '\n'
	|	lines timeout '\n'
	|       lines syncaddr '\n'
	|       lines syncsrcaddr '\n'
	|	lines access_list '\n'
	|	lines rcpt_access_list '\n'
	|	lines data_access_list '\n'
	|	lines dracdb '\n'
	|	lines maxpeek '\n'
	|	lines nodrac '\n'
	|       lines logexpired '\n'
	|	lines dnsrbldef '\n'
	|	lines macrodef '\n'
	|	lines urlcheckdef '\n'
	|	lines ldapcheckdef '\n'
	|	lines ldapconfdef '\n'
	|	lines fixldapcheck '\n'
	|	lines localaddrdef '\n'
	|	lines p0fsockdef '\n'
	|	lines spamdsockdef '\n'
	|	lines tsigdef '\n'
	|	lines nsupdatedef '\n'
	|	lines listdef '\n'
	|	lines domainexact '\n'
	|	lines syncmaxqlen '\n'
	|	lines ratelimitdef '\n'
	|	lines '\n'
	|
	;
netblock:	ADDR IPADDR CIDR{
			struct acl_netblock_data and;

			and.addr = SA(&$2);
			and.salen = sizeof(struct sockaddr_in);
			and.cidr = $3;

			acl_add_clause(AC_NETBLOCK, &and);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	|	ADDR IPADDR	{
			struct acl_netblock_data and;

			and.addr = SA(&$2);
			and.salen = sizeof(struct sockaddr_in);
			and.cidr = 32;

			acl_add_clause(AC_NETBLOCK, &and);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	|	ADDR IP6ADDR CIDR{
#ifdef AF_INET6
			struct acl_netblock_data and;

			and.addr = SA(&$2);
			and.salen = sizeof(struct sockaddr_in6);
			and.cidr = $3;

			acl_add_clause(AC_NETBLOCK, &and);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
#else
			acl_drop();
			mg_log(LOG_INFO,
			    "IPv6 is not supported, ignore line %d",
			    conf_line);
#endif
		}
	|	ADDR IP6ADDR	{
#ifdef AF_INET6
			struct acl_netblock_data and;

			and.addr = SA(&$2);
			and.salen = sizeof(struct sockaddr_in6);
			and.cidr = 128;

			acl_add_clause(AC_NETBLOCK, &and);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
#else
			acl_drop();
			mg_log(LOG_INFO,
			    "IPv6 is not supported, ignore line %d",
			    conf_line);
#endif
		}
	;
fromaddr:	FROM EMAIL	{
			acl_add_clause(AC_FROM, $2);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	;
rawfromaddr:	RAWFROM EMAIL	{
			acl_add_clause(AC_RAWFROM, $2);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	;
rcptaddr:	RCPT EMAIL	{
			acl_add_clause(AC_RCPT, $2);
			if (conf.c_testmode)
				acl_register_entry_first(AS_RCPT, A_GREYLIST);
			else
				acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}

	;
fromregex:	FROM REGEX	{
			acl_add_clause(AC_FROM_RE, $2);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	;
rawfromregex:	RAWFROM REGEX	{
			acl_add_clause(AC_RAWFROM_RE, $2);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	;
rcptregex:	RCPT REGEX	{
			acl_add_clause(AC_RCPT_RE, $2);
			if (conf.c_testmode)
				acl_register_entry_first(AS_RCPT, A_GREYLIST);
			else
				acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	;
domainaddr:	DOMAIN DOMAINNAME {
			acl_add_clause(AC_DOMAIN, $2);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	;
domainregex:	DOMAIN REGEX	 {
			acl_add_clause(AC_DOMAIN_RE, $2);
			acl_register_entry_first(AS_RCPT, A_WHITELIST);
		}
	;
peeraddr:	PEER IPADDR GLTIMEOUT TDELAY	{
			char addr[IPADDRSTRLEN];

			if (IP4TOSTRING($2, addr) == NULL) {
				mg_log(LOG_ERR,
				    "invalid IPv4 address line %d",
				    conf_line);
				exit(EX_DATAERR);
			}
			peer_add(addr, (time_t)humanized_atoi($4));
		}
	|	PEER IP6ADDR GLTIMEOUT TDELAY	{
#ifdef AF_INET6
			char addr[IPADDRSTRLEN];

			if (IP6TOSTRING($2, addr) == NULL) {
				mg_log(LOG_ERR, 
				    "invalid IPv6 address line %d",
				    conf_line);
				exit(EX_DATAERR);
			}
			peer_add(addr, (time_t)humanized_atoi($4));
#else
			mg_log(LOG_INFO,
			    "IPv6 is not supported, ignore line %d",
			    conf_line);
#endif
		}
	|	PEER DOMAINNAME GLTIMEOUT TDELAY	{
#ifdef HAVE_GETADDRINFO
			peer_add($2, (time_t)humanized_atoi($4));
#else
			mg_log(LOG_INFO,
			    "FQDN in peer is not supported, "
			    "ignore line %d", conf_line);
#endif
		}
	|	PEER IPADDR GLTIMEOUT TNUMBER	{
			char addr[IPADDRSTRLEN];

			if (IP4TOSTRING($2, addr) == NULL) {
				mg_log(LOG_ERR,
				    "invalid IPv4 address line %d",
				    conf_line);
				exit(EX_DATAERR);
			}
			peer_add(addr, (time_t)humanized_atoi($4));
		}
	|	PEER IP6ADDR GLTIMEOUT TNUMBER	{
#ifdef AF_INET6
			char addr[IPADDRSTRLEN];

			if (IP6TOSTRING($2, addr) == NULL) {
				mg_log(LOG_ERR, 
				    "invalid IPv6 address line %d",
				    conf_line);
				exit(EX_DATAERR);
			}
			peer_add(addr, (time_t)humanized_atoi($4));
#else
			mg_log(LOG_INFO,
			    "IPv6 is not supported, ignore line %d",
			    conf_line);
#endif
		}
	|	PEER DOMAINNAME GLTIMEOUT TNUMBER	{
#ifdef HAVE_GETADDRINFO
			peer_add($2, (time_t)humanized_atoi($4));
#else
			mg_log(LOG_INFO,
			    "FQDN in peer is not supported, "
			    "ignore line %d", conf_line);
#endif
		}
	|	PEER IPADDR	{
			char addr[IPADDRSTRLEN];

			if (IP4TOSTRING($2, addr) == NULL) {
				mg_log(LOG_ERR,
				    "invalid IPv4 address line %d",
				    conf_line);
				exit(EX_DATAERR);
			}
			peer_add(addr, (time_t)COM_TIMEOUT);
		}
	|	PEER IP6ADDR	{
#ifdef AF_INET6
			char addr[IPADDRSTRLEN];

			if (IP6TOSTRING($2, addr) == NULL) {
				mg_log(LOG_ERR, 
				    "invalid IPv6 address line %d",
				    conf_line);
				exit(EX_DATAERR);
			}
			peer_add(addr, (time_t)COM_TIMEOUT);
#else
			mg_log(LOG_INFO,
			    "IPv6 is not supported, ignore line %d",
			    conf_line);
#endif
		}
	|	PEER DOMAINNAME	{
#ifdef HAVE_GETADDRINFO
			peer_add($2, (time_t)COM_TIMEOUT);
#else
			mg_log(LOG_INFO,
			    "FQDN in peer is not supported, "
			    "ignore line %d", conf_line);
#endif
		}
	;
autowhite:	AUTOWHITE TDELAY{ if (C_NOTFORCED(C_AUTOWHITE))
					conf.c_autowhite_validity =
					    (time_t)humanized_atoi($2);
				}
	|	AUTOWHITE TNUMBER{ if (C_NOTFORCED(C_AUTOWHITE))
					conf.c_autowhite_validity =
					    (time_t)humanized_atoi($2);
				}
	;
greylist:	GREYLIST TDELAY	{ if (C_NOTFORCED(C_DELAY))
					conf.c_delay =
					    (time_t)humanized_atoi($2);
				}
	|	GREYLIST TNUMBER{ if (C_NOTFORCED(C_DELAY))
					conf.c_delay =
					    (time_t)humanized_atoi($2);
				}
	;
tarpit:		TARPIT TDELAY 	{
#ifdef HAVE_DATA_CALLBACK
			if (C_NOTFORCED(C_TARPIT))
				conf.c_tarpit = (time_t)humanized_atoi($2);
#else
			mg_log(LOG_ERR, "libmilter >= 8.14 is required "
					"for tarpit, line %d",
					conf_line);
			exit(EX_DATAERR);
#endif
		}
	|	TARPIT TNUMBER	{
#ifdef HAVE_DATA_CALLBACK
			if (C_NOTFORCED(C_TARPIT))
				conf.c_tarpit = (time_t)humanized_atoi($2);
#else
			mg_log(LOG_ERR, "libmilter >= 8.14 is required "
					"for tarpit, line %d",
					conf_line);
			exit(EX_DATAERR);
#endif
		}
	;
tarpit_scope:
		TARPIT_SCOPE SESSION {
#ifdef HAVE_DATA_CALLBACK
			if (C_NOTFORCED(C_TARPIT_SCOPE))
				conf.c_tarpit_scope = TAP_SESSION;
#else
			mg_log(LOG_ERR, "libmilter >= 8.14 is required "
					"for tarpit_scope, line %d",
					conf_line);
			exit(EX_DATAERR);
#endif
		}
	|	TARPIT_SCOPE COMMAND {
#ifdef HAVE_DATA_CALLBACK
			if (C_NOTFORCED(C_TARPIT_SCOPE))
				conf.c_tarpit_scope = TAP_COMMAND;
#else
			mg_log(LOG_ERR, "libmilter >= 8.14 is required "
					"for tarpit_scope, line %d",
					conf_line);
			exit(EX_DATAERR);
#endif
		}
	;
verbose:	VERBOSE	{ if (C_NOTFORCED(C_DEBUG)) conf.c_debug = 1; }
	;
dump_no_time_translation:	DUMP_NO_TIME_TRANSLATION	{ 
			conf.c_dump_no_time_translation = 1; 
			}
	;
logexpired:   LOGEXPIRED { conf.c_logexpired = 1; }
	;
quiet:		QUIET	{ if (C_NOTFORCED(C_QUIET)) conf.c_quiet = 1; }
	;
noauth:		NOAUTH	{ if (C_NOTFORCED(C_NOAUTH)) conf.c_noauth = 1; }
	;
multiracl:	MULTIRACL { conf.c_multiracl = 1; }
	;
noaccessdb:	NOACCESSDB	{ conf.c_noaccessdb = 1; }
	;
extendedregex:	EXTENDEDREGEX	{ conf.c_extendedregex = 1; }
	;
unbracket:	UNBRACKET	{ conf.c_unbracket = 1; }
	;
nospf:		NOSPF	{ if (C_NOTFORCED(C_NOSPF)) conf.c_nospf = 1; }
	;
delayedreject:	DELAYEDREJECT	{ conf.c_delayedreject = 1; }
	;
testmode:	TESTMODE{ if (C_NOTFORCED(C_TESTMODE)) conf.c_testmode = 1; }
	;
nodetach:	NODETACH{ if (C_NOTFORCED(C_NODETACH)) conf.c_nodetach = 1; }
	;
lazyaw:		LAZYAW	{ if (C_NOTFORCED(C_LAZYAW)) conf.c_lazyaw = 1; }
	;
domainexact:	DOMAINEXACT	{ if (C_NOTFORCED(C_DOMAINEXACT)) 
					conf.c_domainexact = 1;
				}
	;
pidfile:	PIDFILE QSTRING	{ if (C_NOTFORCED(C_PIDFILE)) 
					conf.c_pidfile = 
					    quotepath(conf.c_pidfile_storage, 
						$2, QSTRLEN);
				}
	;
dumpfile:	GLDUMPFILE QSTRING{ if (C_NOTFORCED(C_DUMPFILE)) 
					conf.c_dumpfile = 
					    quotepath(conf.c_dumpfile_storage, 
					    $2, QSTRLEN);
				}
	|	GLDUMPFILE QSTRING TNUMBER 	{
				if (C_NOTFORCED(C_DUMPFILE))
					conf.c_dumpfile = 
					    quotepath(conf.c_dumpfile_storage, 
					    $2, QSTRLEN);

				conf.c_dumpfile_mode = (int)strtol($3, NULL, 8);
			}
	;
subnetmatch:	SUBNETMATCH CIDR{ if (C_NOTFORCED(C_MATCHMASK))
					prefix2mask4($2, &conf.c_match_mask);
				}
	;	
subnetmatch6:	SUBNETMATCH6 CIDR{ 
#ifdef AF_INET6
				if (C_NOTFORCED(C_MATCHMASK6))
					prefix2mask6($2, &conf.c_match_mask6);
#else
				mg_log(LOG_INFO, "IPv6 is not supported, "
				    "ignore line %d", conf_line);
#endif
				}
	;
socket:		SOCKET QSTRING	{ if (C_NOTFORCED(C_SOCKET))
					conf.c_socket = 
					    quotepath(conf.c_socket_storage, 
					    $2, QSTRLEN);
				}
	|	SOCKET QSTRING TNUMBER 	{
				int mode = atoi($3);

				if (C_NOTFORCED(C_SOCKET))
					conf.c_socket = 
					    quotepath(conf.c_socket_storage, 
					    $2, QSTRLEN);

				switch(mode) {
				case 666:
					conf.c_socket_mode = 0666;
					break;
				case 660:
					conf.c_socket_mode = 0660;
					break;
				case 600:
					conf.c_socket_mode = 0600;
					break;
				default:
					mg_log(LOG_ERR, "socket mode %d is "
					    "not allowed, Use either 666, "
					    "660, or 600", mode);
					exit(EX_DATAERR);
				}
			}
	;
user:		USER QSTRING	{ if (C_NOTFORCED(C_USER))
					conf.c_user =
					    quotepath(conf.c_user_storage, $2, QSTRLEN);
				}
	;	
p0fsockdef:	P0FSOCK QSTRING	{
#ifdef USE_P0F
				char path[QSTRLEN + 1];

				p0f_sock_set(quotepath(path, $2, QSTRLEN));
#else
				mg_log(LOG_INFO, 
				    "p0f support not compiled in, "
				    "ignore line %d", 
				    conf_line);
#endif
				}
	;
spamdsockdef:	SPAMDSOCK SPAMDSOCKT QSTRING	{
#ifdef USE_SPAMD
				char path[QSTRLEN + 1];

				spamd_sock_set($2, 
					       quotepath(path, $3, QSTRLEN));
#else
				mg_log(LOG_INFO, 
				    "spamassassin support not compiled in, "
				    "ignore line %d", 
				    conf_line);
#endif
				}
	;
tsigdef:		TSIG QSTRING QSTRING QSTRING	{
#ifdef USE_NSUPDATE
				char name[QSTRLEN + 1];
				char alg[QSTRLEN + 1];
				char key[QSTRLEN + 1];

				if (tsig_add(quotepath(name, $2, QSTRLEN),
					     quotepath(alg, $3, QSTRLEN),
					     quotepath(key, $4, QSTRLEN))) {
					mg_log(LOG_ERR, "error at %d",
					       conf_line);
					exit(EX_DATAERR);
				}
#else
				mg_log(LOG_INFO, 
				    "nsupdate support not compiled in, "
				    "ignore line %d", 
				    conf_line);
#endif
			}
	;
nsupdatedef:		NSUPDATE QSTRING OPENLIST nsupdatedefitems CLOSELIST {
#ifdef USE_NSUPDATE
				char name[QSTRLEN + 1];

				if (nsupdate_add(quotepath(name, $2, QSTRLEN))){
					mg_log(LOG_ERR, "error at %d",
					       conf_line);
					exit(EX_DATAERR);
				}
#else
				mg_log(LOG_INFO, 
				    "nsupdate support not compiled in, "
				    "ignore line %d", 
				    conf_line);
#endif
			}
	;
nsupdatedefitems:	nsupdatedefitems nsupdatedefservers
		|	nsupdatedefitems nsupdatedefrname
		|	nsupdatedefitems nsupdatedefrvalue 
		|	nsupdatedefitems nsupdatedefttl
		|	nsupdatedefitems nsupdatedefclass
		|	nsupdatedefitems nsupdatedeftype
		|	nsupdatedefitems nsupdatedeftsig 
		|
		;

nsupdatedefservers:	SERVERS QSTRING {
#ifdef USE_NSUPDATE
				char name[QSTRLEN + 1];

				if (nsupdate_add_servers(quotepath(name,
				    $2, QSTRLEN))) {
					mg_log(LOG_ERR, "error at %d",
					       conf_line);
					exit(EX_DATAERR);
				}
#else
				mg_log(LOG_INFO, 
				    "nsupdate support not compiled in, "
				    "ignore line %d", 
				    conf_line);
#endif
			}
	;
nsupdatedefrname:	RNAME QSTRING {
#ifdef USE_NSUPDATE
				char name[QSTRLEN + 1];

				if (nsupdate_add_rname(quotepath(name,
				    $2, QSTRLEN))) {
					mg_log(LOG_ERR, "error at %d",
					       conf_line);
					exit(EX_DATAERR);
				}
#else
				mg_log(LOG_INFO, 
				    "nsupdate support not compiled in, "
				    "ignore line %d", 
				    conf_line);
#endif
			}
	;
nsupdatedefrvalue:	RVALUE QSTRING {
#ifdef USE_NSUPDATE
				char name[QSTRLEN + 1];

				if (nsupdate_add_rvalue(quotepath(name,
				    $2, QSTRLEN))) {
					mg_log(LOG_ERR, "error at %d",
					       conf_line);
					exit(EX_DATAERR);
				}
#else
				mg_log(LOG_INFO, 
				    "nsupdate support not compiled in, "
				    "ignore line %d", 
				    conf_line);
#endif
			}
	;
nsupdatedefttl:		TTL TDELAY {
#ifdef USE_NSUPDATE
				if (nsupdate_add_ttl(humanized_atoi($2))) {
					mg_log(LOG_ERR, "error at %d",
					       conf_line);
					exit(EX_DATAERR);
				}
#else
				mg_log(LOG_INFO, 
				    "nsupdate support not compiled in, "
				    "ignore line %d", 
				    conf_line);
#endif
			}
	;
nsupdatedefclass:	CLASS TNUMBER {
#ifdef USE_NSUPDATE
				if (nsupdate_add_class(atoi($2))) {
					mg_log(LOG_ERR, "error at %d",
					       conf_line);
					exit(EX_DATAERR);
				}
#else
				mg_log(LOG_INFO, 
				    "nsupdate support not compiled in, "
				    "ignore line %d", 
				    conf_line);
#endif
			}
	;
nsupdatedeftype:	TYPE TNUMBER {
#ifdef USE_NSUPDATE
				if (nsupdate_add_type(atoi($2))) {
					mg_log(LOG_ERR, "error at %d",
					       conf_line);
					exit(EX_DATAERR);
				}
#else
				mg_log(LOG_INFO, 
				    "nsupdate support not compiled in, "
				    "ignore line %d", 
				    conf_line);
#endif
			}
	;
nsupdatedeftsig:	TSIG QSTRING {
#ifdef USE_NSUPDATE
				char name[QSTRLEN + 1];

				if (nsupdate_add_tsig(quotepath(name,
				    $2, QSTRLEN))) {
					mg_log(LOG_ERR, "error at %d",
					       conf_line);
					exit(EX_DATAERR);
				}
#else
				mg_log(LOG_INFO, 
				    "nsupdate support not compiled in, "
				    "ignore line %d", 
				    conf_line);
#endif
			}
	;
geoipdb:	GEOIPDB QSTRING	{
#ifdef USE_GEOIP
				char path[QSTRLEN + 1];

				geoip_set_db(quotepath(path, $2, QSTRLEN));
#else
				mg_log(LOG_INFO, 
				    "GeoIP support not compiled in, "
				    "ignore line %d", 
				    conf_line);
#endif
				}
	;
geoipv6db:	GEOIPV6DB QSTRING	{
#ifdef USE_GEOIP
				char path[QSTRLEN + 1];

				geoip_set_db_v6(quotepath(path, $2, QSTRLEN));
#else
				mg_log(LOG_INFO, 
				    "GeoIP support not compiled in, "
				    "ignore line %d", 
				    conf_line);
#endif
				}
	;
geoip2db:	GEOIP2DB QSTRING	{
#ifdef USE_GEOIP2
				char path[QSTRLEN + 1];

				geoip2_set_db(quotepath(path, $2, QSTRLEN));
#else
				mg_log(LOG_INFO,
				    "GeoIP2 support not compiled in, "
				    "ignore line %d",
				    conf_line);
#endif
				}
	;
report:		REPORT NONE	{ conf.c_report = C_GLNONE; }
	|	REPORT DELAYS	{ conf.c_report = C_DELAYS; }
	|	REPORT NODELAYS	{ conf.c_report = C_NODELAYS; }
	|	REPORT ALL	{ conf.c_report = C_ALL; }
	;

logfac:	LOGFAC NONE { conf.c_logfac = -1; }
	|	LOGFAC LOGFAC_KERN { conf.c_logfac = LOG_KERN; }
	|	LOGFAC LOGFAC_USER { conf.c_logfac = LOG_USER; }
	|	LOGFAC LOGFAC_MAIL { conf.c_logfac = LOG_MAIL; }
	|	LOGFAC LOGFAC_DAEMON { conf.c_logfac = LOG_DAEMON; }
	|	LOGFAC LOGFAC_AUTH { conf.c_logfac = LOG_AUTH; }
	|	LOGFAC LOGFAC_SYSLOG { conf.c_logfac = LOG_SYSLOG; }
	|	LOGFAC LOGFAC_LPR { conf.c_logfac = LOG_LPR; }
	|	LOGFAC LOGFAC_NEWS { conf.c_logfac = LOG_NEWS; }
	|	LOGFAC LOGFAC_UUCP { conf.c_logfac = LOG_UUCP; }
	|	LOGFAC LOGFAC_CRON { conf.c_logfac = LOG_CRON; }
	|	LOGFAC LOGFAC_AUTHPRIV {
#ifdef LOG_AUTHPRIV
		      conf.c_logfac = LOG_AUTHPRIV;
#else
		      mg_log(LOG_ERR, "Your system does not support "
		      		      "authpriv syslog facility, line %d",
		      		      conf_line);
		      exit(EX_DATAERR);
#endif
		}
	|	LOGFAC LOGFAC_FTP {
#ifdef LOG_FTP
		      conf.c_logfac = LOG_FTP;
#else
		      mg_log(LOG_ERR, "Your system does not support "
		      		      "ftp syslog facility, line %d",
		      		      conf_line);
		      exit(EX_DATAERR);
#endif
		}
	|	LOGFAC LOGFAC_LOCAL0 { conf.c_logfac = LOG_LOCAL0; }
	|	LOGFAC LOGFAC_LOCAL1 { conf.c_logfac = LOG_LOCAL1; }
	|	LOGFAC LOGFAC_LOCAL2 { conf.c_logfac = LOG_LOCAL2; }
	|	LOGFAC LOGFAC_LOCAL3 { conf.c_logfac = LOG_LOCAL3; }
	|	LOGFAC LOGFAC_LOCAL4 { conf.c_logfac = LOG_LOCAL4; }
	|	LOGFAC LOGFAC_LOCAL5 { conf.c_logfac = LOG_LOCAL5; }
	|	LOGFAC LOGFAC_LOCAL6 { conf.c_logfac = LOG_LOCAL6; }
	|	LOGFAC LOGFAC_LOCAL7 { conf.c_logfac = LOG_LOCAL7; }
	;

statdef:	STAT QSTRING QSTRING	{ 
				char output[QSTRLEN + 1];
				char format[QSTRLEN + 1];

				mg_stat_def(quotepath(output, $2, QSTRLEN),
					    quotepath(format, $3, QSTRLEN));
		}
	;

dumpfreq:	GLDUMPFREQ TDELAY { conf.c_dumpfreq =
				    (time_t)humanized_atoi($2);
				}
	|	GLDUMPFREQ TNUMBER { conf.c_dumpfreq =
				    (time_t)humanized_atoi($2);
				}
	;
timeout:	GLTIMEOUT TDELAY { conf.c_timeout =
				    (time_t)humanized_atoi($2);
				}
	|	GLTIMEOUT TNUMBER { conf.c_timeout =
				    (time_t)humanized_atoi($2);
				}
	;
syncaddr:	SYNCADDR STAR	{
				   conf.c_syncaddr = NULL;
				   conf.c_syncport = NULL;
				}
	|	SYNCADDR IPADDR	{
				if (IP4TOSTRING($2, conf.c_syncaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv4 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncaddr = conf.c_syncaddr_storage;
				conf.c_syncport = NULL;
	                        }
	|	SYNCADDR IP6ADDR {
#ifdef AF_INET6
				if (IP6TOSTRING($2, conf.c_syncaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv6 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncaddr = conf.c_syncaddr_storage;
				conf.c_syncport = NULL;
#else /* AF_INET6 */
				mg_log(LOG_INFO, "IPv6 is not supported, "
				    "ignore line %d", conf_line);
#endif /* AF_INET6 */
				}
	|	SYNCADDR STAR PORT TNUMBER {
				conf.c_syncaddr = NULL;
				conf.c_syncport = conf.c_syncport_storage;
				strncpy(conf.c_syncport, $4, NUMLEN);
				conf.c_syncport[NUMLEN] = '\0';
				}
	|	SYNCADDR IPADDR PORT TNUMBER {
				if (IP4TOSTRING($2, conf.c_syncaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv4 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncaddr = conf.c_syncaddr_storage;
				conf.c_syncport = conf.c_syncport_storage;
				strncpy(conf.c_syncport, $4, NUMLEN);
				conf.c_syncport[NUMLEN] = '\0';
				}
	|	SYNCADDR IP6ADDR PORT TNUMBER {
#ifdef AF_INET6
				if (IP6TOSTRING($2, conf.c_syncaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv6 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncaddr = conf.c_syncaddr_storage;
				conf.c_syncport = conf.c_syncport_storage;
				strncpy(conf.c_syncport, $4, NUMLEN);
				conf.c_syncport[NUMLEN] = '\0';
#else /* AF_INET6 */
				mg_log(LOG_INFO, "IPv6 is not supported, "
				    "ignore line %d", conf_line);
#endif /* AF_INET6 */
				}
	;

syncsrcaddr:	SYNCSRCADDR STAR	{
				   conf.c_syncsrcaddr = NULL;
				   conf.c_syncsrcport = NULL;
				}
	|	SYNCSRCADDR IPADDR	{
				if (IP4TOSTRING($2, conf.c_syncsrcaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv4 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncsrcaddr = conf.c_syncsrcaddr_storage;
				conf.c_syncsrcport = NULL;
	                        }
	|	SYNCSRCADDR IP6ADDR {
#ifdef AF_INET6
				if (IP6TOSTRING($2, conf.c_syncsrcaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv6 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncsrcaddr = conf.c_syncsrcaddr_storage;
				conf.c_syncsrcport = NULL;
#else /* AF_INET6 */
				mg_log(LOG_INFO, "IPv6 is not supported, "
				    "ignore line %d", conf_line);
#endif /* AF_INET6 */
				}
	|	SYNCSRCADDR STAR PORT TNUMBER {
				conf.c_syncsrcaddr = NULL;
				conf.c_syncsrcport = conf.c_syncsrcport_storage;
				strncpy(conf.c_syncsrcport, $4, NUMLEN);
				conf.c_syncsrcport[NUMLEN] = '\0';
				}
	|	SYNCSRCADDR IPADDR PORT TNUMBER {
				if (IP4TOSTRING($2, conf.c_syncsrcaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv4 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncsrcaddr = conf.c_syncsrcaddr_storage;
				conf.c_syncsrcport = conf.c_syncsrcport_storage;
				strncpy(conf.c_syncsrcport, $4, NUMLEN);
				conf.c_syncsrcport[NUMLEN] = '\0';
				}
	|	SYNCSRCADDR IP6ADDR PORT TNUMBER {
#ifdef AF_INET6
				if (IP6TOSTRING($2, conf.c_syncsrcaddr_storage) == NULL) {
					mg_log(LOG_ERR, "invalid IPv6 address "
					    "line %d", conf_line);
					exit(EX_DATAERR);
				}
				conf.c_syncsrcaddr = conf.c_syncsrcaddr_storage;
				conf.c_syncsrcport = conf.c_syncsrcport_storage;
				strncpy(conf.c_syncsrcport, $4, NUMLEN);
				conf.c_syncsrcport[NUMLEN] = '\0';
#else /* AF_INET6 */
				mg_log(LOG_INFO, "IPv6 is not supported, "
				    "ignore line %d", conf_line);
#endif /* AF_INET6 */
				}
	;

syncmaxqlen:	SYNCMAXQLEN TNUMBER { conf.c_syncmaxqlen = atoi($2) ; 
		}
	;

ratelimitdef:	RATELIMIT QSTRING RCPT TNUMBER SLASH TDELAY {
			char name[QSTRLEN + 1];

			ratelimit_conf_add(quotepath(name, $2, QSTRLEN), 
					   RL_RCPT, humanized_atoi($4),
					   humanized_atoi($6), NULL);
		}
	|	RATELIMIT QSTRING RCPT TNUMBER SLASH TDELAY KEY QSTRING {
			char name[QSTRLEN + 1];
			char key[QSTRLEN + 1];
			ratelimit_conf_add(quotepath(name, $2, QSTRLEN), 
					   RL_RCPT, humanized_atoi($4),
					   humanized_atoi($6), 
					   quotepath(key, $8, QSTRLEN));
		}
	|	RATELIMIT QSTRING SESSION TNUMBER SLASH TDELAY {
			char name[QSTRLEN + 1];

			ratelimit_conf_add(quotepath(name, $2, QSTRLEN), 
					   RL_SESS, humanized_atoi($4),
					   humanized_atoi($6), NULL);
		}
	|	RATELIMIT QSTRING SESSION TNUMBER SLASH TDELAY KEY QSTRING {
			char name[QSTRLEN + 1];
			char key[QSTRLEN + 1];
			ratelimit_conf_add(quotepath(name, $2, QSTRLEN), 
					   RL_SESS, humanized_atoi($4),
					   humanized_atoi($6), 
					   quotepath(key, $8, QSTRLEN));
		}
	|	RATELIMIT QSTRING DATA TNUMBER SLASH TDELAY {
			char name[QSTRLEN + 1];

			ratelimit_conf_add(quotepath(name, $2, QSTRLEN), 
					   RL_DATA, humanized_atoi($4),
					   humanized_atoi($6), NULL);
		}
	|	RATELIMIT QSTRING DATA TNUMBER SLASH TDELAY KEY QSTRING {
			char name[QSTRLEN + 1];
			char key[QSTRLEN + 1];
			ratelimit_conf_add(quotepath(name, $2, QSTRLEN), 
					   RL_DATA, humanized_atoi($4),
					   humanized_atoi($6), 
					   quotepath(key, $8, QSTRLEN));
		}
	;

access_list:	ACL GREYLIST  acl_entry { 
			acl_register_entry_last(AS_RCPT, A_GREYLIST);
		}
	|	ACL WHITELIST acl_entry { 
			acl_register_entry_last(AS_RCPT, A_WHITELIST);
		}
	|	ACL BLACKLIST acl_entry { 
			acl_register_entry_last(AS_RCPT, A_BLACKLIST);
		}
	;

rcpt_access_list:
		RACL id GREYLIST  acl_entry { 
			acl_register_entry_last(AS_RCPT, A_GREYLIST);
		}
	|	RACL id WHITELIST acl_entry { 
			acl_register_entry_last(AS_RCPT, A_WHITELIST);
		}
	|	RACL id BLACKLIST acl_entry { 
			acl_register_entry_last(AS_RCPT, A_BLACKLIST);
		}
	|	RACL id CONTINUE acl_entry { 
			acl_register_entry_last(AS_RCPT, A_CONTINUE);
		}
	;

data_access_list:
		DACL id GREYLIST  acl_entry { 
			acl_register_entry_last(AS_DATA, A_GREYLIST);
		}
	|	DACL id WHITELIST acl_entry { 
			acl_register_entry_last(AS_DATA, A_WHITELIST);
		}
	|	DACL id BLACKLIST acl_entry { 
			acl_register_entry_last(AS_DATA, A_BLACKLIST);
		}
	|	DACL id CONTINUE acl_entry { 
			acl_register_entry_last(AS_DATA, A_CONTINUE);
		}
	;

id:		QSTRING { 
			char id[QSTRLEN + 1];

			acl_add_id(quotepath(id, $1, QSTRLEN)); 
		}
	|
	;

acl_entry:	acl_default_entry 	{ conf_acl_end = 1; }
	| 	acl_plain_entry	
	;	

acl_default_entry: DEFAULT acl_values |	DEFAULT	;
acl_plain_entry: acl_clauses acl_values | acl_clauses;

acl_clauses:	acl_clause
	|	acl_clauses acl_clause
	;

acl_clause:	helo_clause
	|	heloregex_clause
	|	fromaddr_clause
	|	fromregex_clause
	|	rcptaddr_clause
	|	rcptregex_clause
	|	domainaddr_clause
	|	domainregex_clause
	|	netblock_clause
	|	dnsrbl_clause
	|	mx_clause
	|	macro_clause
	|	ratelimit_clause
	|	urlcheck_clause
	|	ldapcheck_clause
	|	eqsetstring_clause
	|	eqrsetstring_clause
	|	incsetstring_clause
	|	incrsetstring_clause
	|	decsetstring_clause
	|	decrsetstring_clause
	|	eqsetnum_clause
	|	eqrsetnum_clause
	|	incsetnum_clause
	|	incrsetnum_clause
	|	decsetnum_clause
	|	decrsetnum_clause
	|	eqsetprop_clause
	|	eqrsetprop_clause
	|	incsetprop_clause
	|	incrsetprop_clause
	|	decsetprop_clause
	|	decrsetprop_clause
	|	p0f_clause
	|	p0fregex_clause
	|	list_clause
	|	header_clause
	|	headerregex_clause
	|	body_clause
	|	bodyregex_clause
	|	auth_clause
	|	authregex_clause
	|	tls_clause
	|	tlsregex_clause
	|	spf_clause
	|	spf_compat_clause
	|	dkim_clause
	|	msgsize_clause
	|	msgsize_prop_clause
	|	rcptcount_clause
	|	rcptcount_prop_clause
	|	no_clause
	|	time_clause
	|	geoip_clause
	|	propstr_clause
	|	propglob_clause
	|	propregex_clause
	|	propnum_clause
	|	propprop_clause
	|	bodyprop_clause
	|	headerprop_clause
	|	spamd_clause
	|	spamd_score_clause
	|	spamd_score_prop_clause
	|	tarpit_clause
	|	nsupdate_clause
	|	log_clause
	;

acl_values:	acl_value
	|	acl_values acl_value
	;

acl_value:	greylist_value
	|	autowhite_value
	|	tarpit_scope_value
	|	code_value
	|	ecode_value
	|	msg_value
	|	report_value
	|	flush_value
	|	nolog_value
	|	addheader_value
	|	addfooter_value
	|	subjtag_value
	|	maxpeek_value
	;

greylist_value:		GLXDELAY TDELAY 
			    { acl_add_delay((time_t)humanized_atoi($2)); }
	;
autowhite_value:	AUTOWHITE TDELAY 
			    { acl_add_autowhite((time_t)humanized_atoi($2)); }
	;
tarpit_scope_value:
			TARPIT_SCOPE SESSION
			    {
#ifdef HAVE_DATA_CALLBACK
				acl_add_tarpit_scope(TAP_SESSION);
#else
				mg_log(LOG_ERR, "libmilter >= 8.14 is required "
						"for tarpit_scope, line %d",
						conf_line);
				exit(EX_DATAERR);
#endif
			    }
	|		TARPIT_SCOPE COMMAND
			    {
#ifdef HAVE_DATA_CALLBACK
				acl_add_tarpit_scope(TAP_COMMAND);
#else
				mg_log(LOG_ERR, "libmilter >= 8.14 is required "
						"for tarpit_scope, line %d",
						conf_line);
				exit(EX_DATAERR);
#endif
			    }
	;
flush_value:		FLUSHADDR { acl_add_flushaddr(); }
	;
nolog_value:		NOLOG { acl_add_nolog(); }
	;
code_value:		CODE QSTRING {
				char code[QSTRLEN + 1];

				acl_add_code(quotepath(code, $2, QSTRLEN));
			}
	;
ecode_value:		ECODE QSTRING {
				char ecode[QSTRLEN + 1];

				acl_add_ecode(quotepath(ecode, $2, QSTRLEN));
			}
	;
msg_value:		MSG QSTRING {
				char msg[QSTRLEN + 1];

				acl_add_msg(quotepath(msg, $2, QSTRLEN));
			}
	;
report_value:		REPORT QSTRING {
				char msg[QSTRLEN + 1];

				acl_add_report(quotepath(msg, $2, QSTRLEN));
			}
	;
addheader_value:	ADDHEADER QSTRING {
				char hdr[QSTRLEN + 1];

				acl_add_addheader(
					quotepath(hdr, $2, QSTRLEN), -1);
			}
	|	ADDHEADER QSTRING COMMA TNUMBER {
				char hdr[QSTRLEN + 1];

				acl_add_addheader(
					quotepath(hdr, $2, QSTRLEN), atoi($4));
			}
	;
addfooter_value:	ADDFOOTER QSTRING {
				char hdr[QSTRLEN + 1];

				acl_add_addfooter(quotepath(hdr, $2, QSTRLEN));
			}
	;
subjtag_value:		SUBJTAG QSTRING {
				char hdr[QSTRLEN + 1];

				acl_add_subjtag(quotepath(hdr, $2, QSTRLEN));
			}
	;
maxpeek_value:		MAXPEEK TNUMBER {
				acl_add_maxpeek(atoi($2));
			}
	;
no_clause:		NO { acl_negate_clause(); }
	;

time_clause:		TIME clockspec clockspec clockspec clockspec clockspec
			{ acl_add_clause(AC_CLOCKSPEC, register_clock()); }
	;

p0f_clause:		P0F QSTRING { 
#ifdef USE_P0F
			char name[QSTRLEN + 1];

			acl_add_clause(AC_P0F, 
				       quotepath(name, $2, QSTRLEN));
#else
			acl_drop();
			mg_log(LOG_INFO, 
			    "p0f support not compiled in, ignore line %d", 
			    conf_line);
#endif
			}
	;
p0fregex_clause:	P0F REGEX { 
#ifdef USE_P0F
			acl_add_clause(AC_P0F_RE, $2); 
#else
			acl_drop();
			mg_log(LOG_INFO, 
			    "p0f support not compiled in, ignore line %d", 
			    conf_line);
#endif
			}
	;
spamd_clause:		SPAMD {
#ifdef USE_SPAMD
				acl_add_clause(AC_SA, NULL);
#else
				mg_log(LOG_INFO, 
				       "spamassassin support "
				       "not compiled in, ignore line %d", 
				       conf_line);
#endif
			}
	;
spamd_score_clause:	SPAMD OP TNUMBER {
#ifdef USE_SPAMD
				struct acl_opnum_data aond;

				aond.op = $2;
				aond.num = atoi($3);
				
				acl_add_clause(AC_SASCORE, &aond);
#else
				mg_log(LOG_INFO, 
				       "spamassassin support not compiled in, ignore line %d", 
				 conf_line);
#endif
			}
	;

spamd_score_prop_clause:	SPAMD OP PROP {
			struct acl_opnum_prop aonp;

			aonp.aonp_op = $2;
			aonp.aonp_type = AONP_SPAMD;
			aonp.aonp_name = $3 + 1; /* + 1 to strip leading $ */
			acl_add_clause(AC_SASCORE_PROP, &aonp);
		}
	;

geoip_clause:		GEOIP QSTRING {
#if defined(USE_GEOIP) || defined(USE_GEOIP2)
				char ccode[IPADDRSTRLEN + 1];

				acl_add_clause(AC_GEOIP, 
				    quotepath(ccode, $2, IPADDRSTRLEN));
#else
				acl_drop();
				mg_log(LOG_INFO, 
				    "GeoIP support not compiled in, "
				    "ignoting line %d", 
				    conf_line);
#endif
			}
	;

helo_clause:		HELO QSTRING {
				char string[QSTRLEN + 1];

				acl_add_clause(AC_HELO, 
				    quotepath(string, $2, QSTRLEN));
			}
	;

heloregex_clause:	HELO REGEX { acl_add_clause(AC_HELO_RE, $2); }
	;

fromaddr_clause:	FROM EMAIL { acl_add_clause(AC_FROM, $2); }
	;

rawfromaddr_clause:	RAWFROM EMAIL { acl_add_clause(AC_RAWFROM, $2); }
	;

fromregex_clause:	FROM REGEX { acl_add_clause(AC_FROM_RE, $2); }
	;

rawfromregex_clause:	RAWFROM REGEX { acl_add_clause(AC_RAWFROM_RE, $2); }
	;

rcptaddr_clause:	RCPT EMAIL { acl_add_clause(AC_RCPT, $2); }
	;

rcptregex_clause:	RCPT REGEX { acl_add_clause(AC_RCPT_RE, $2); }
	;

domainaddr_clause:	DOMAIN DOMAINNAME { acl_add_clause(AC_DOMAIN, $2); }
	;

domainregex_clause:	DOMAIN REGEX { acl_add_clause(AC_DOMAIN_RE, $2); }
	;

dnsrbl_clause:		DNSRBL QSTRING { 
#ifdef USE_DNSRBL
			char path[QSTRLEN + 1];

			acl_add_clause(AC_DNSRBL, quotepath(path, $2, QSTRLEN));
#else
			acl_drop();
			mg_log(LOG_INFO, 
			    "DNSRBL support not compiled in, ignore line %d", 
			    conf_line);
#endif
			}
	;



mx_clause:              MX CIDR {
#ifdef USE_MX

                        acl_add_clause(AC_MX, &$2);
#else
                        acl_drop();
                        mg_log(LOG_INFO,
                            "MX support not compiled in, ignore line %d",
                            conf_line);
#endif
                        }
        ;



macro_clause:	SM_MACRO QSTRING {
			char qstring[QSTRLEN + 1];

			acl_add_clause(AC_MACRO,
				       quotepath(qstring, $2, QSTRLEN));
		}
	;

ratelimit_clause:RATELIMIT QSTRING {
			char qstring[QSTRLEN + 1];

			acl_add_clause(AC_RATELIMIT,
				       quotepath(qstring, $2, QSTRLEN));
		}
	;

header_clause:	GLHEADER QSTRING {
			char qstring[QSTRLEN + 1];

			acl_add_clause(AC_HEADER,
				       quotepath(qstring, $2, QSTRLEN));
		}
	;

headerregex_clause:	GLHEADER REGEX { acl_add_clause(AC_HEADER_RE, $2); }
	;
tarpit_clause:		TARPIT TDELAY {
#ifdef HAVE_DATA_CALLBACK
				time_t t = humanized_atoi($2);
				acl_add_clause(AC_TARPIT, &t);
#else
				mg_log(LOG_ERR, "libmilter >= 8.14 is required "
						"for tarpit, line %d",
						conf_line);
				exit(EX_DATAERR);
#endif
			}
	;

nsupdate_clause:	NSUPDATE QSTRING {
#ifdef USE_NSUPDATE
				char name[QSTRLEN + 1];
				struct nsupdate_entry *nse;

				(void)quotepath(name, $2, QSTRLEN);
				if ((nse = nsupdate_byname(name)) == NULL) {
					mg_log(LOG_ERR, "nsupdate \"%s\" "
					    "not found", name);
					exit(EX_DATAERR);
				} else {
					acl_add_clause(AC_NSUPDATE, nse);
				}
#else
				mg_log(LOG_INFO, 
				    "nsupdate support not compiled in, "
				    "ignore line %d", 
				    conf_line);
#endif
			}
	;

log_clause:		LOG QSTRING {
				char qstring[QSTRLEN + 1];

				acl_add_clause(AC_LOG,
				    quotepath(qstring, $2, QSTRLEN));
			}
	;

body_clause:		BODY QSTRING {
				char qstring[QSTRLEN + 1];

				acl_add_clause(AC_BODY,
				    quotepath(qstring, $2, QSTRLEN));
			}
	;

bodyregex_clause:	BODY REGEX { acl_add_clause(AC_BODY_RE, $2); }
	;

auth_clause:		AUTH QSTRING {
				char qstring[QSTRLEN + 1];

				acl_add_clause(AC_AUTH,
				    quotepath(qstring, $2, QSTRLEN));
				conf.c_noauth = 1; 
			}
	;

authregex_clause:	AUTH REGEX { 
				acl_add_clause(AC_AUTH_RE, $2); 
				conf.c_noauth = 1; 
			}
	;

tls_clause:		TLS QSTRING {
				char qstring[QSTRLEN + 1];

				acl_add_clause(AC_TLS,
				    quotepath(qstring, $2, QSTRLEN));
				conf.c_noauth = 1; 
			}
	;

tlsregex_clause:	TLS REGEX { 
				acl_add_clause(AC_TLS_RE, $2); 
				conf.c_noauth = 1;  
			}
	;

spf_clause:		SPF SPF_STATUS {
#if (defined(HAVE_SPF) || defined(HAVE_SPF_ALT) || \
     defined(HAVE_SPF2_10) || defined(HAVE_SPF2))
				acl_add_clause(AC_SPF, &$2); 
				conf.c_nospf = 1;
#else
				acl_drop();
				mg_log(LOG_INFO, 
				    "SPF support not compiled in,  "
				    "ignore line %d", 
				    conf_line);
#endif
			}
	;

spf_compat_clause:	 SPF {
#if (defined(HAVE_SPF) || defined(HAVE_SPF_ALT) || \
     defined(HAVE_SPF2_10) || defined(HAVE_SPF2))
				enum spf_status status = MGSPF_PASS;

				acl_add_clause(AC_SPF, &status); 
				conf.c_nospf = 1;
#else
				acl_drop();
				mg_log(LOG_INFO, 
				    "SPF support not compiled in, "
				    "ignore line %d", 
				    conf_line);
#endif
			}
	;

dkim_clause:		DKIMCHECK SPF_STATUS {
#ifdef USE_DKIM
				acl_add_clause(AC_DKIM, &$2); 
#else
				acl_drop();
				mg_log(LOG_INFO, 
				    "DKIM support not compiled in,  "
				    "ignore line %d", 
				    conf_line);
#endif
			}
	;

urlcheck_clause:	URLCHECK QSTRING { 
#ifdef USE_CURL
			char path[QSTRLEN + 1];

			acl_add_clause(AC_URLCHECK, 
				       quotepath(path, $2, QSTRLEN));
#else
			acl_drop();
			mg_log(LOG_INFO, 
			    "CURL support not compiled in, ignore line %d", 
			    conf_line);
#endif
			}
	;
ldapcheck_clause:	LDAPCHECK QSTRING { 
#ifdef USE_LDAP
			char name[QSTRLEN + 1];

			acl_add_clause(AC_LDAPCHECK, 
				       quotepath(name, $2, QSTRLEN));
#else
			acl_drop();
			mg_log(LOG_INFO, 
			    "LDAP support not compiled in, ignore line %d", 
			    conf_line);
#endif
			}
	;

eqsetstring_clause:	SET PROP EQSET QSTRING {
			struct prop_data upd;
			char qstring[QSTRLEN + 1];

			upd.upd_name = $2;
			upd.upd_data = quotepath(qstring, $4, QSTRLEN);

			acl_add_clause(AC_EQSET, &upd);
		}
	;

eqrsetstring_clause:	RSET PROP EQSET QSTRING {
			struct prop_data upd;
			char qstring[QSTRLEN + 1];

			upd.upd_name = $2;
			upd.upd_data = quotepath(qstring, $4, QSTRLEN);

			acl_add_clause(AC_EQRSET, &upd);
		}
	;

incsetstring_clause:	SET PROP INCSET QSTRING {
			struct prop_data upd;
			char qstring[QSTRLEN + 1];

			upd.upd_name = $2;
			upd.upd_data = quotepath(qstring, $4, QSTRLEN);

			acl_add_clause(AC_INCSET, &upd);
		}
	;

incrsetstring_clause:	RSET PROP INCSET QSTRING {
			struct prop_data upd;
			char qstring[QSTRLEN + 1];

			upd.upd_name = $2;
			upd.upd_data = quotepath(qstring, $4, QSTRLEN);

			acl_add_clause(AC_INCRSET, &upd);
		}
	;

decsetstring_clause:	SET PROP DECSET QSTRING {
			struct prop_data upd;
			char qstring[QSTRLEN + 1];

			upd.upd_name = $2;
			upd.upd_data = quotepath(qstring, $4, QSTRLEN);

			acl_add_clause(AC_DECSET, &upd);
		}
	;

decrsetstring_clause:	RSET PROP DECSET QSTRING {
			struct prop_data upd;
			char qstring[QSTRLEN + 1];

			upd.upd_name = $2;
			upd.upd_data = quotepath(qstring, $4, QSTRLEN);

			acl_add_clause(AC_DECRSET, &upd);
		}
	;

eqsetnum_clause:	SET PROP EQSET TNUMBER {
			struct prop_data upd;

			upd.upd_name = $2;
			upd.upd_data = $4;

			acl_add_clause(AC_EQSET, &upd);
		}
	;

eqrsetnum_clause:	RSET PROP EQSET TNUMBER {
			struct prop_data upd;

			upd.upd_name = $2;
			upd.upd_data = $4;

			acl_add_clause(AC_EQRSET, &upd);
		}
	;

incsetnum_clause:	SET PROP INCSET TNUMBER {
			struct prop_data upd;

			upd.upd_name = $2;
			upd.upd_data = $4;

			acl_add_clause(AC_INCSET, &upd);
		}
	;

incrsetnum_clause:	RSET PROP INCSET TNUMBER {
			struct prop_data upd;

			upd.upd_name = $2;
			upd.upd_data = $4;

			acl_add_clause(AC_INCRSET, &upd);
		}
	;

decsetnum_clause:	SET PROP DECSET TNUMBER {
			struct prop_data upd;

			upd.upd_name = $2;
			upd.upd_data = $4;

			acl_add_clause(AC_DECSET, &upd);
		}
	;

decrsetnum_clause:	RSET PROP DECSET TNUMBER {
			struct prop_data upd;

			upd.upd_name = $2;
			upd.upd_data = $4;

			acl_add_clause(AC_DECRSET, &upd);
		}
	;

eqsetprop_clause:	SET PROP EQSET PROP {
			struct prop_data upd;

			upd.upd_name = $2;
			upd.upd_data = $4 + 1;

			acl_add_clause(AC_EQSETPROP, &upd);
		}
	;

eqrsetprop_clause:	RSET PROP EQSET PROP {
			struct prop_data upd;

			upd.upd_name = $2;
			upd.upd_data = $4 + 1;

			acl_add_clause(AC_EQRSETPROP, &upd);
		}
	;

incsetprop_clause:	SET PROP INCSET PROP {
			struct prop_data upd;

			upd.upd_name = $2;
			upd.upd_data = $4 + 1;

			acl_add_clause(AC_INCSETPROP, &upd);
		}
	;

incrsetprop_clause:	RSET PROP INCSET PROP {
			struct prop_data upd;

			upd.upd_name = $2;
			upd.upd_data = $4 + 1;

			acl_add_clause(AC_INCRSETPROP, &upd);
		}
	;

decsetprop_clause:	SET PROP DECSET PROP {
			struct prop_data upd;

			upd.upd_name = $2;
			upd.upd_data = $4 + 1;

			acl_add_clause(AC_DECSETPROP, &upd);
		}
	;

decrsetprop_clause:	RSET PROP DECSET PROP {
			struct prop_data upd;

			upd.upd_name = $2;
			upd.upd_data = $4 + 1;

			acl_add_clause(AC_DECRSETPROP, &upd);
		}
	;

propstr_clause:		PROP QSTRING {
			struct prop_data upd;
			char qstring[QSTRLEN + 1];

			upd.upd_name = $1;
			upd.upd_data = quotepath(qstring, $2, QSTRLEN);

			acl_add_clause(AC_PROP_STR, &upd);
		}
	;

propglob_clause:	STAR PROP QSTRING {
			struct prop_data upd;
			char qstring[QSTRLEN + 1];

			upd.upd_name = $2;
			upd.upd_data = quotepath(qstring, $3, QSTRLEN);

			acl_add_clause(AC_PROP_GLOB, &upd);
		}
	;

propnum_clause:		PROP OP TNUMBER {
			struct prop_data upd;
			struct acl_opnum_data aond;

			upd.upd_name = $1;
			aond.op = $2;
			aond.num = humanized_atoi($3);
			upd.upd_data = &aond;
				
			acl_add_clause(AC_PROP_NUM, &upd);
		}
	;

propprop_clause:	PROP OP PROP {
			struct acl_prop_pop apop;

			/* +1 to skip leading $ */
			apop.apop_lhs = $1 + 1;
			apop.apop_op = $2;
			apop.apop_rhs = $3 + 1;
				
			acl_add_clause(AC_PROP_PROP, &apop);
		}
	;

propregex_clause:	PROP REGEX {
			struct prop_data upd;

			upd.upd_name = $1;
			upd.upd_data = $2;
			acl_add_clause(AC_PROP_RE, &upd);
		}
	;

bodyprop_clause:	BODY PROP {
			/* + 1 to strip leading $ */
			acl_add_clause(AC_BODY_PROP, $2 + 1);
		}
	;

headerprop_clause:	GLHEADER PROP {
			/* + 1 to strip leadin $ */
			acl_add_clause(AC_HEADER_PROP, $2 + 1);
		}
	;

list_clause:		LIST QSTRING { 
				char path[QSTRLEN + 1];

				acl_add_clause(AC_LIST, 
					       quotepath(path, $2, QSTRLEN));
			}
	;
netblock_clause:	ADDR IPADDR CIDR {
				struct acl_netblock_data and;

				and.addr = SA(&$2);
				and.salen = sizeof(struct sockaddr_in);
				and.cidr = $3;

				acl_add_clause(AC_NETBLOCK, &and);
			}
	|		ADDR IPADDR	{
				struct acl_netblock_data and;

				and.addr = SA(&$2);
				and.salen = sizeof(struct sockaddr_in);
				and.cidr = 32;

				acl_add_clause(AC_NETBLOCK, &and);
			}
	|		ADDR IP6ADDR CIDR{
#ifdef AF_INET6
				struct acl_netblock_data and;

				and.addr = SA(&$2);
				and.salen = sizeof(struct sockaddr_in6);
				and.cidr = $3;

				acl_add_clause(AC_NETBLOCK, &and);
#else
				acl_drop();
				mg_log(LOG_INFO, 
				    "IPv6 is not supported, ignore line %d",
				    conf_line);
#endif
			}
	|		ADDR IP6ADDR	{
#ifdef AF_INET6
				struct acl_netblock_data and;

				and.addr = SA(&$2);
				and.salen = sizeof(struct sockaddr_in6);
				and.cidr = 128;

				acl_add_clause(AC_NETBLOCK, &and);
#else
				acl_drop();
				mg_log(LOG_INFO, "IPv6 is not supported, "
				     "ignore line %d", conf_line);
#endif
		}
	;

dracdb:			DRAC DB QSTRING	{ 
#ifdef USE_DRAC
				conf.c_dracdb = 
					    quotepath(conf.c_dracdb_storage, $3, QSTRLEN);
#else
				mg_log(LOG_INFO, "DRAC support not compiled "
				    "in, ignore line %d", conf_line);
#endif
		}
	;

msgsize_clause:		MSGSIZE OP TNUMBER {
				struct acl_opnum_data aond;

				aond.op = $2;
				aond.num = humanized_atoi($3);
				
				acl_add_clause(AC_MSGSIZE, &aond);
		}
	;

msgsize_prop_clause:	MSGSIZE OP PROP {
			struct acl_opnum_prop aonp;

			aonp.aonp_op = $2;
			aonp.aonp_type = AONP_MSGSIZE;
			aonp.aonp_name = $3 + 1; /* + 1 to strip leading $ */
			acl_add_clause(AC_MSGSIZE_PROP, &aonp);
		}
	;

rcptcount_clause:	RCPTCOUNT OP TNUMBER {
				struct acl_opnum_data aond;

				aond.op = $2;
				aond.num = humanized_atoi($3);
				
				acl_add_clause(AC_RCPTCOUNT, &aond);
		}
	;

rcptcount_prop_clause:	RCPTCOUNT OP PROP {
			struct acl_opnum_prop aonp;

			aonp.aonp_op = $2;
			aonp.aonp_type = AONP_RCPTCOUNT;
			aonp.aonp_name = $3 + 1; /* + 1 to strip leading $ */
			acl_add_clause(AC_RCPTCOUNT_PROP, &aonp);
		}
	;

nodrac:			NODRAC	{ conf.c_nodrac = 1; }
	;

maxpeek:		MAXPEEK TNUMBER { 
				conf.c_maxpeek = humanized_atoi($2); 
				acl_maxpeek_fixup(conf.c_maxpeek);
			}
	;

dnsrbldef:	dnsrbldefip | dnsrbldefnetblock
	;

dnsrbldefip:	DNSRBL QSTRING DOMAINNAME IPADDR {
#ifdef USE_DNSRBL
			char path[QSTRLEN + 1];

			dnsrbl_source_add(quotepath(path, $2, QSTRLEN), 
			    $3, SA(&$4), 32);
#else
			mg_log(LOG_INFO, 
			    "DNSRBL support not compiled in, ignore  line %d", 
			    conf_line);
#endif
		}
	;

dnsrbldefnetblock:	DNSRBL QSTRING DOMAINNAME IPADDR CIDR {
#ifdef USE_DNSRBL
			char path[QSTRLEN + 1];

			dnsrbl_source_add(quotepath(path, $2, QSTRLEN), 
			    $3, SA(&$4), $5);
#else
			mg_log(LOG_INFO, 
			    "DNSRBL support not compiled in, ignore line %d", 
			    conf_line);
#endif
		}
	;

macrodef:	macrodef_string | macrodef_regex | macrodef_unset;

macrodef_string:	SM_MACRO QSTRING QSTRING QSTRING { 
				char name[QSTRLEN + 1];
				char macro[QSTRLEN + 1];
				char value[QSTRLEN + 1];

				macro_add_string(quotepath(name, $2, QSTRLEN), 
				    quotepath(macro, $3, QSTRLEN),
				    quotepath(value, $4, QSTRLEN));
			}
	;

ldapcheckdef:	LDAPCHECK QSTRING QSTRING ldapcheckdef_flags {
#ifdef USE_LDAP
			char name[QSTRLEN + 1];
			char url[QSTRLEN + 1];

			ldapcheck_def_add(quotepath(name, $2, QSTRLEN), 
			    quotepath(url, $3, QSTRLEN), ldapcheck_gflags);
#else
			mg_log(LOG_INFO, 
			    "LDAP support not compiled in, ignore  line %d", 
			    conf_line);
#endif
		}
	;

ldapcheckdef_flags:	ldapcheckdef_flags ldapcheckdef_clear
		|	ldapcheckdef_flags ldapcheckdef_domatch
		|	ldapcheckdef_flags ldapcheckdef_noescape
		|	
		;

ldapcheckdef_clear:	 CLEAR { 
#ifdef USE_LDAP
				ldapcheck_gflags |= L_CLEARPROP; 
#else
			mg_log(LOG_INFO, 
			    "LDAP support not compiled in, ignore line %d", 
			    conf_line);
#endif
			}
		;
ldapcheckdef_domatch:	 DOMATCH { 
#ifdef USE_LDAP
				ldapcheck_gflags |= L_DOMATCH; 
#else
			mg_log(LOG_INFO, 
			    "LDAP support not compiled in, ignore line %d", 
			    conf_line);
#endif
			}
		;

ldapcheckdef_noescape:	 NOESCAPE { 
#ifdef USE_LDAP
				ldapcheck_gflags |= L_NOESCAPE; 
#else
			mg_log(LOG_INFO, 
			    "LDAP support not compiled in, ignore line %d", 
			    conf_line);
#endif
			}
		;

urlcheckdef:	URLCHECK QSTRING QSTRING TNUMBER urlcheckdef_flags {
#ifdef USE_CURL
			char path1[QSTRLEN + 1];
			char path2[QSTRLEN + 1];

			urlcheck_def_add(quotepath(path1, $2, QSTRLEN), 
			    quotepath(path2, $3, QSTRLEN), atoi($4), 
			    urlcheck_gflags);
#else
			mg_log(LOG_INFO, 
			    "CURL support not compiled in, ignore  line %d", 
			    conf_line);
#endif
		}
	;

urlcheckdef_flags:	urlcheckdef_flags urlcheckdef_postmsg
		|	urlcheckdef_flags urlcheckdef_getprop
		|	urlcheckdef_flags urlcheckdef_noencode
		|	urlcheckdef_flags urlcheckdef_getprop urlcheckdef_clear
		|	urlcheckdef_flags urlcheckdef_fork
		|
		;

urlcheckdef_postmsg:	POSTMSG	{ 
#ifdef USE_CURL
				urlcheck_gflags |= U_POSTMSG; 
#else
			mg_log(LOG_INFO, 
			    "CURL support not compiled in, ignore line %d", 
			    conf_line);
#endif
			}
		;
urlcheckdef_noencode:	NOENCODE	{ 
#ifdef USE_CURL
				urlcheck_gflags |= U_NOENCODE; 
#else
			mg_log(LOG_INFO, 
			    "CURL support not compiled in, ignore line %d", 
			    conf_line);
#endif
			}
		;
urlcheckdef_getprop:	GETPROP	{ 
#ifdef USE_CURL
				urlcheck_gflags |= U_GETPROP; 
#else
			mg_log(LOG_INFO, 
			    "CURL support not compiled in, ignore line %d", 
			    conf_line);
#endif
			}
		;
urlcheckdef_clear:	 CLEAR { 
#ifdef USE_CURL
				urlcheck_gflags |= U_CLEARPROP; 
#else
			mg_log(LOG_INFO, 
			    "CURL support not compiled in, ignore line %d", 
			    conf_line);
#endif
			}
		;
urlcheckdef_fork:	 FORK {
#ifdef USE_CURL
				urlcheck_gflags |= U_FORK;
#else
			mg_log(LOG_INFO, 
			    "CURL support not compiled in, ignore line %d", 
			    conf_line);
#endif
			}
		;

ldapconfdef:	LDAPCONF QSTRING ldaptimeout 
		LDAPBINDDN QSTRING LDAPBINDPW QSTRING {
#ifdef USE_LDAP
			char uris[QSTRLEN + 1];
			char bdn[QSTRLEN +1 ];
			char bpw[QSTRLEN + 1 ];
			ldapcheck_conf_add(
				quotepath(uris, $2, QSTRLEN),
				quotepath(bdn, $5, QSTRLEN),
				quotepath(bpw, $7, QSTRLEN));
#else
			mg_log(LOG_INFO, 
			    "LDAP support not compiled in, ignore  line %d", 
			    conf_line);
#endif
		}
	| LDAPCONF QSTRING ldaptimeout { /* 4.2.1 backward compatiblity */ 
	#ifdef USE_LDAP
				char uris[QSTRLEN + 1];
				char *bdn = NULL;
				char *bpw = NULL;
				ldapcheck_conf_add(
					quotepath(uris, $2, QSTRLEN), bdn, bpw);
	#else
				mg_log(LOG_INFO, 
				    "LDAP support not compiled in, ignore  line %d", 
				    conf_line);
	#endif
			}
	;
ldaptimeout:	GLTIMEOUT TDELAY {
#ifdef USE_LDAP
			ldapcheck_timeout_set(humanized_atoi($2));
#else
			mg_log(LOG_INFO, 
			    "LDAP support not compiled in, ignore  line %d", 
			    conf_line);
#endif
		}
	|	TNUMBER {	/* 4.2.1 backward compatiblity */
#ifdef USE_LDAP
			ldapcheck_timeout_set(atoi($1));
#else
			mg_log(LOG_INFO, 
			    "LDAP support not compiled in, ignore  line %d", 
			    conf_line);
#endif
		}
	|
	;
fixldapcheck:	FIXLDAPCHECK { conf.c_fixldapcheck = 1; }
	;
localaddrdef:	LOCALADDR IPADDR { 
			(void)memcpy(&conf.c_localaddr, &$2, 
				     sizeof(struct sockaddr_in));
			IP4TOSTRING(conf.c_localaddr, conf.c_localaddr_string);
		}
	|	LOCALADDR IP6ADDR {
#ifdef AF_INET6
			(void)memcpy(&conf.c_localaddr, &$2, 
				     sizeof(struct sockaddr_in6));
			IP6TOSTRING(conf.c_localaddr, conf.c_localaddr_string);
#else
			mg_log(LOG_INFO, "IPv6 is not supported, "
			     "ignore line %d", conf_line);
#endif
		}
	;
macrodef_regex:		SM_MACRO QSTRING QSTRING REGEX {
				char name[QSTRLEN + 1];
				char macro[QSTRLEN + 1];

				macro_add_regex(quotepath(name, $2, QSTRLEN),
				    quotepath(macro, $3, QSTRLEN), $4); 
			}
	;

macrodef_unset:		SM_MACRO QSTRING QSTRING UNSET {
				char name[QSTRLEN + 1];
				char macro[QSTRLEN + 1];

				macro_add_unset(quotepath(name, $2, QSTRLEN),
				    quotepath(macro, $3, QSTRLEN));
			}
	;

clockspec:	clockspec_item COMMA clockspec
	|	clockspec_item	{ next_clock_spec(); }
	;
clockspec_item:	TNUMBER			
			{ add_clock_item(atoi($1), atoi($1), 0); }
	|	TNUMBER SLASH TNUMBER	
			{ add_clock_item(atoi($1), atoi($1), atoi($3));  }
	|	TNUMBER MINUS TNUMBER	
			{ add_clock_item(atoi($1), atoi($3), 0); }
	|	TNUMBER MINUS TNUMBER SLASH TNUMBER 
			{ add_clock_item(atoi($1), atoi($3), atoi($5)); }
	|	STAR			
			{ add_clock_item(-1, -1, 0);  }
	|	STAR SLASH TNUMBER	
			{ add_clock_item(-1, -1, atoi($3)); }
	;

listdef:	LIST QSTRING list_clause {
			char path[QSTRLEN + 1];

			all_list_setname(glist, quotepath(path, $2, QSTRLEN));
			glist_init();
		}
	;

list_clause:	HELO OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_HELO_LIST); }
	|	FROM OPENLIST email_list CLOSELIST
			{ all_list_settype(glist, AC_FROM_LIST); }
	|	RAWFROM OPENLIST email_list CLOSELIST
			{ all_list_settype(glist, AC_RAWFROM_LIST); }
	|	RCPT OPENLIST email_list CLOSELIST
			{ all_list_settype(glist, AC_RCPT_LIST); }
	|	DOMAIN OPENLIST domain_list CLOSELIST
			{ all_list_settype(glist, AC_DOMAIN_LIST); }
	|	DNSRBL OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_DNSRBL_LIST); }
	|	URLCHECK OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_URLCHECK_LIST); }
	|	BODY OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_BODY_LIST); }
	|	GLHEADER OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_HEADER_LIST); }
	|	SM_MACRO OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_MACRO_LIST); }
	|	ADDR OPENLIST addr_list CLOSELIST
			{ all_list_settype(glist, AC_NETBLOCK_LIST); }
	|	AUTH OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_AUTH_LIST); }
	|	TLS OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_TLS_LIST); }
	|	TIME OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_CLOCKSPEC_LIST); }
	|	GEOIP OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_GEOIP_LIST); }
	|	P0F OPENLIST qstring_list CLOSELIST
			{ all_list_settype(glist, AC_P0F_LIST); }
	;

email_list:	email_item
	|	email_list email_item
	;

email_item: 	EMAIL	{ list_add(glist, AC_EMAIL, $1); }
	|	REGEX 	{ list_add(glist, AC_REGEX, $1); }
	;

domain_list:	domain_item
	|	domain_list domain_item
	;

domain_item:	DOMAINNAME	{ list_add(glist, AC_DOMAIN, $1); }
	|	REGEX		{ list_add(glist, AC_REGEX, $1); }	
	;

qstring_list:	qstring_item
	|	qstring_list qstring_item
	;

qstring_item:	QSTRING		{ 
			char tmpstr[QSTRLEN + 1];

			list_add(glist, AC_STRING, 
			    quotepath(tmpstr, $1, QSTRLEN));
		}
	|	REGEX		{ list_add(glist, AC_REGEX, $1); }
	;

addr_list:	addr_item
	|	addr_list addr_item
	;

addr_item: 	IPADDR CIDR {
			struct acl_netblock_data and;

			and.addr = SA(&$1);
			and.salen = sizeof(struct sockaddr_in);
			and.cidr = $2;
			list_add(glist, AC_NETBLOCK, &and);
		}
	|	IPADDR {
			struct acl_netblock_data and;

			and.addr = SA(&$1);
			and.salen = sizeof(struct sockaddr_in);
			and.cidr = 32;
			list_add(glist, AC_NETBLOCK, &and);
		}
	|	IP6ADDR CIDR{
#ifdef AF_INET6
			struct acl_netblock_data and;

			and.addr = SA(&$1);
			and.salen = sizeof(struct sockaddr_in6);
			and.cidr = $2;
			list_add(glist, AC_NETBLOCK, &and);
#else
			mg_log(LOG_INFO,
			    "IPv6 is not supported, ignore line %d",
			    conf_line);
#endif
		}
	|	IP6ADDR	{
#ifdef AF_INET6
			struct acl_netblock_data and;

			and.addr = SA(&$1);
			and.salen = sizeof(struct sockaddr_in6);
			and.cidr = 128;
			list_add(glist, AC_NETBLOCK, &and);
#else
			mg_log(LOG_ERR, 
			    "IPv6 is not supported, ignore line %d",
			    conf_line);
#endif
		}
	;
%%
#include "conf_lex.c"

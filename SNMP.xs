#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <sys/types.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>
#include <netdb.h>
#include <stdlib.h>

#ifndef __P
#define __P(x) x
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "snmp_impl.h"
#include "snmp.h"
#include "parse.h"

struct tree *find_node _((char *, struct tree *));
extern struct tree *Mib;
extern int snmp_errno;
int snmp_dump_packet = 0;

#ifdef HAS_MEMCPY
#define bcopy(s,d,l) memcpy((d),(s),(l))
#endif

#define SUCCESS 1
#define FAILURE 0

#define VARBIND_TAG_F 0
#define VARBIND_IID_F 1
#define VARBIND_VAL_F 2
#define VARBIND_TYPE_F 3

static int __sprint_ipaddr _((char *, u_char *));
static int __sprint_num_objid _((char *, oid *, int));
static int __get_type_str _((int, char *));
static int __get_last_label_iid _((char *, char **, char **, int));
static struct tree *__free_tree _((struct tree *));
static int __oid_cmp _((oid *, int, oid *, int));
static int __tag2oid _((char *, char *, oid  *, int  *, int *));
static int __concat_oid_str _((oid *, int *, char *));
static int __translate_str _((char *, char *, int));
static void __add_var_val_str _((struct snmp_pdu *, oid *, int, char *,
                                 int, int));
static int __send_sync_pdu _((struct snmp_session *, struct snmp_pdu *,
                           struct variable_list **, int , SV *, SV *, SV *));
#define FAIL_ON_NULL_IID 1
#define NO_FAIL_ON_NULL_IID 0

typedef struct snmp_session SnmpSession;

static int __sprint_ipaddr (buf, ip)
char *buf;
u_char *ip;
{
   sprintf(buf,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
   return SUCCESS;
}
static int __sprint_num_objid (buf, objid, len)
char *buf;
oid *objid;
int len;
{
   int i;
   buf[0] = '\0';
   for (i=0; i < len; i++) {
	sprintf(buf,".%d",*objid++);
	buf += strlen(buf);
   }
   return SUCCESS;
}

#define MAX_TYPE_NAME_LEN 16
static int __get_type_str (type, str)
int type;
char * str;
{
   switch (type) {
	case TYPE_OBJID:
       		strcpy(str, "OBJECTID");
	        break;
	case TYPE_OCTETSTR:
       		strcpy(str, "OCTETSTR");
	        break;
	case TYPE_INTEGER:
       		strcpy(str, "INTEGER");
	        break;
	case TYPE_NETADDR:
       		strcpy(str, "NETADDR");
	        break;
	case TYPE_IPADDR:
       		strcpy(str, "IPADDR");
	        break;
	case TYPE_COUNTER:
       		strcpy(str, "COUNTER");
	        break;
	case TYPE_GAUGE:
       		strcpy(str, "GAUGE");
	        break;
	case TYPE_TIMETICKS:
       		strcpy(str, "TIMETICKS");
	        break;
	case TYPE_OPAQUE:
       		strcpy(str, "OPAQUE");
	        break;
	case TYPE_OTHER:
	case TYPE_NULL:
	case TYPE_COUNTER64:
	case TYPE_BITSTRING:
	case TYPE_NSAPADDRESS:
	case TYPE_UINTEGER:
        default: /* unsupported types for now */
		strcpy(str, "");
	return(FAILURE);
   }
   return SUCCESS;
}

/* does a destructive disection of <label1>...<labeln>.<iid> returning
   <labeln> and <iid> in seperate strings (note: will destructively
   alter input string, 'name') */
static int __get_last_label_iid (name, last_label, iid, fail_on_null_iid)
char * name;
char ** last_label;
char ** iid;
int fail_on_null_iid;
{
   char *lcp;
   char *icp;
   int len = strlen(name);
   int found_label = 0;

   *last_label = *iid = NULL;

   if (len == 0) return(FAILURE);

   lcp = icp = &(name[len]);

   while (1) {
      if (lcp == name) break;
      if (*lcp == '.') {
	if (found_label) {
	   lcp++;
           break;
        } else {
           icp = lcp;
        }
      }
      if (isalpha(*lcp)) found_label = 1;
      lcp--;
   }
   if (*icp) *(icp++) = '\0';

   if (!found_label || (!isdigit(*icp) && fail_on_null_iid)) return(FAILURE);

   *last_label = lcp; *iid = icp;

   return(SUCCESS);
}

/* does a depth first free of tree, returning next_peer */
static struct tree *__free_tree(tree)
struct tree * tree;
{
   struct tree *tp = tree->child_list;
   struct tree *next_peer = tree->next_peer;

   while (tp) {
     tp = __free_tree(tp);
   }

   if (tree->description) free(tree->description);
   free(tree);
   return(next_peer);
}


static int
__oid_cmp(oida_arr, oida_arr_len, oidb_arr, oidb_arr_len)
oid *oida_arr;
int oida_arr_len;
oid *oidb_arr;
int oidb_arr_len;
{

   for (;oida_arr_len && oidb_arr_len;
	oida_arr++, oida_arr_len--, oidb_arr++, oidb_arr_len--) {
	if (*oida_arr == *oidb_arr) continue;
	return(*oida_arr > *oidb_arr ? 1 : -1);
   }
   if (oida_arr_len == oidb_arr_len) return(0);
   return(oida_arr_len > oidb_arr_len ? 1 : -1);
}

static int
__tag2oid(tag, iid, oid_arr, oid_arr_len, type)
char * tag;
char * iid;
oid  * oid_arr;
int  * oid_arr_len;
int  * type;
{
   struct tree *tp;
   oid newname[64], *op;

   if (tag && *tag) tp = find_node(tag, Mib);

   if (tp) {

      if (type) *type = tp->type;

      if ((oid_arr == NULL) || (oid_arr_len == NULL)) return SUCCESS;

      /* code I don't really understand taken from get_node in snmp_client.c */
      for(op = newname + 63; op >= newname; op--){
        *op = tp->subid;
	tp = tp->parent;
	if (tp == NULL)
	   break;
      }
      if (newname + 64 - op > MAX_NAME_LEN) return FAILURE;
      *oid_arr_len = newname + 64 - op;
      bcopy(op, oid_arr, (newname + 64 - op) * sizeof(oid));
      if (iid && *iid) return __concat_oid_str(oid_arr, oid_arr_len, iid);
      else return SUCCESS;
   }
   if (oid_arr_len) *oid_arr_len = 0;
   return FAILURE;
}


static int
__concat_oid_str(doid_arr, doid_arr_len, soid_str)
oid *doid_arr;
int *doid_arr_len;
char * soid_str;
{
   char soid_buf[MAX_NAME_LEN*3];
   char *cp;

   strcpy(soid_buf, soid_str);
   cp = strtok(soid_buf,".");
   while (cp) {
     doid_arr[(*doid_arr_len)++] =  atoi(cp);
     cp = strtok(NULL,".");
   }
   return(SUCCESS);
}

#define SNMP_XLATE_MODE_OID2TAG 1
#define SNMP_XLATE_MODE_TAG2OID 0

static int
__translate_str(name_str, oid_str, mode)
char *name_str;
char *oid_str;
int  mode;
{
   char str_buf[2048];
   oid oid_arr[MAX_NAME_LEN];
   int oid_arr_len = MAX_NAME_LEN;
   char * label;
   char * iid;

   char *oid_strp;
   int  count;
   int result = FAILURE;

   switch (mode) {
     case SNMP_XLATE_MODE_TAG2OID:
       if (!get_node(name_str, oid_arr, &oid_arr_len)){
          warn("Unknown object descriptor %s\n", name_str);
       } else {
	 result = __sprint_num_objid(oid_str, oid_arr, oid_arr_len);
       }
       break;
     case SNMP_XLATE_MODE_OID2TAG:
        oid_arr_len = 0;
        __concat_oid_str(oid_arr, &oid_arr_len, oid_str);
        str_buf[0] = '\0'; label == NULL; iid = NULL; name_str[0] = '\0';
        sprint_objid(str_buf, oid_arr, oid_arr_len);
        if (((result=__get_last_label_iid(str_buf,
                               &label, &iid, NO_FAIL_ON_NULL_IID)) == SUCCESS)
            && label) {
	   strcpy(name_str, label);
	   if (iid && *iid) {
	     strcat(name_str, ".");
	     strcat(name_str, iid);
           }
        }
       break;
     default:
       fprintf(stderr, "Unknown translation mode %d\n", mode);
   }
   return(result);
}

/*
 * add a varbind to PDU
 */
static void
__add_var_val_str(pdu, name, name_length, val, len, type)
    struct snmp_pdu *pdu;
    oid *name;
    int name_length;
    char * val;
    int type;
{
    struct variable_list *vars;

    if (pdu->variables == NULL){
	pdu->variables = vars =
           (struct variable_list *)malloc(sizeof(struct variable_list));
    } else {
	for(vars = pdu->variables;
            vars->next_variable;
            vars = vars->next_variable)
	    /*EXIT*/;
	vars->next_variable =
           (struct variable_list *)malloc(sizeof(struct variable_list));
	vars = vars->next_variable;
    }

    vars->next_variable = NULL;
    vars->name = (oid *)malloc(name_length * sizeof(oid));
    bcopy((char *)name, (char *)vars->name, name_length * sizeof(oid));
    vars->name_length = name_length;
    switch (type) {
      case TYPE_INTEGER:
        vars->type = INTEGER;
        vars->val.integer = (long *)malloc(sizeof(long));
        *(vars->val.integer) = strtol(val,NULL,0);
        vars->val_len = sizeof(long);
        break;

      case TYPE_GAUGE:
        vars->type = GAUGE;
        goto UINT;
      case TYPE_COUNTER:
        vars->type = COUNTER;
        goto UINT;
      case TYPE_TIMETICKS:
        vars->type = TIMETICKS;
        goto UINT;
      case TYPE_UINTEGER:
        vars->type = UINTEGER;
UINT:
        vars->val.integer = (long *)malloc(sizeof(long));
        *(vars->val.integer) = strtoul(val,NULL,0);
        vars->val_len = sizeof(long);
        break;

      case TYPE_OCTETSTR:
      case TYPE_OPAQUE:
        vars->type = STRING;
        vars->val.string = (u_char *)malloc(len);
        vars->val_len = len;
        bcopy(val,(char *)vars->val.string, vars->val_len);
        break;

      case TYPE_IPADDR:
        vars->type = IPADDRESS;
        vars->val.integer = (long *)malloc(sizeof(long));
        *(vars->val.integer) = inet_addr(val);
        vars->val_len = sizeof(long);
        break;

      case TYPE_OBJID:
        vars->type = OBJID;
	vars->val_len = len;
	vars->val.objid = (oid *)malloc(vars->val_len);
/* NO!!! this needs to convert dotted decimal string array of longs BUG!!*/
	bcopy((char *)val, (char *)vars->val.objid, vars->val_len);
        break;

      default:
        vars->type = ASN_NULL;
	vars->val_len = 0;
	vars->val.string = NULL;
    }

}

#define NO_RETRY_NOSUCH 0
static int
__send_sync_pdu(ss,pdu,response_vars, retry_nosuch,
	        err_str_sv, err_num_sv, err_ind_sv)
struct snmp_session *ss;
struct snmp_pdu *pdu;
struct variable_list **response_vars;
int retry_nosuch;
SV * err_str_sv;
SV * err_num_sv;
SV * err_ind_sv;
{
   struct snmp_pdu *response;
   int status, count;
   struct variable_list *vars;
   char str_buf[2048];
   char err_buf[2048];
   char *label;
   char *iid;
   long len;
   long command = pdu->command;
   *response_vars = NULL;
retry:
   status = snmp_synch_response(ss, pdu, &response);

   if ((response == NULL) && (status == STAT_SUCCESS)) status = STAT_ERROR;

   switch (status) {
      case STAT_SUCCESS:
	 switch (response->errstat) {
	    case SNMP_ERR_NOERROR:
	       *response_vars = response->variables;/* thanks for the memory */
	       response->variables = NULL;
	       break;

            case SNMP_ERR_NOSUCHNAME:
	       for(count = 1, vars = response->variables;
                   vars && (count != response->errindex);
		   vars = vars->next_variable, count++); /*find bad varbind */

               if (vars) {
                  str_buf[0] = '\0'; label == NULL; iid = NULL;
                  sprint_objid(str_buf, vars->name, vars->name_length);
                  if ((__get_last_label_iid(str_buf, &label, &iid,
                                            FAIL_ON_NULL_IID) == SUCCESS)
	               && label && iid) {
                     sprintf(err_buf, "NOSUCHNAME(%s.%s):", label, iid);
                     sv_catpv(err_str_sv, err_buf);
                     sv_setiv(err_num_sv, response->errstat);
                     sv_setiv(err_ind_sv, response->errindex);
                  }
	       }
               if (retry_nosuch && (command == GET_REQ_MSG) &&
		   ((pdu = snmp_fix_pdu(response, GET_REQ_MSG)) != NULL)) {

                	goto retry;
               }

               break;

	    case SNMP_ERR_TOOBIG:
               sv_catpv(err_str_sv, "SNMP_ERR_TOOBIG:");
               sv_setiv(err_num_sv, response->errstat);
	       sv_setiv(err_ind_sv, response->errindex);
               break;
            case SNMP_ERR_BADVALUE:
               sv_catpv(err_str_sv, "SNMP_ERR_BADVALUE:");
               sv_setiv(err_num_sv, response->errstat);
	       sv_setiv(err_ind_sv, response->errindex);
               break;
	    case SNMP_ERR_READONLY:
               sv_catpv(err_str_sv, "SNMP_ERR_READONLY:");
               sv_setiv(err_num_sv, response->errstat);
	       sv_setiv(err_ind_sv, response->errindex);
               break;
	    case SNMP_ERR_GENERR:
               sv_catpv(err_str_sv, "SNMP_ERR_GENERR:");
               sv_setiv(err_num_sv, response->errstat);
	       sv_setiv(err_ind_sv, response->errindex);
               break;
	    case SNMP_ENDOFMIBVIEW:
               sv_catpv(err_str_sv, "SNMP_ENDOFMIBVIEW:");
               sv_setiv(err_num_sv, response->errstat);
	       sv_setiv(err_ind_sv, response->errindex);
	       break;
            /* V2 exceptions - return what you can from response */
	    case SNMP_NOSUCHINSTANCE:
               sv_catpv(err_str_sv, "SNMP_NOSUCHINSTANCE:");
               sv_setiv(err_num_sv, response->errstat);
	       sv_setiv(err_ind_sv, response->errindex);
               break;
	    case SNMP_NOSUCHOBJECT:
               sv_catpv(err_str_sv, "SNMP_NOSUCHOBJECT:");
               sv_setiv(err_num_sv, response->errstat);
	       sv_setiv(err_ind_sv, response->errindex);
               break;
            default:
               break;
	 }
         break;

      case STAT_TIMEOUT:
         sv_catpv(err_str_sv, "SNMP_TIMEOUT:");
         sv_setiv(err_num_sv, snmp_errno);
         break;
      case STAT_ERROR:
      /* status == STAT_ERROR snmp_errno == (GENERR|BAD_ADDRESS|BAD_SESSION) */
      /* GENERR here appears to be a catch all for undefined V2 related errs */
         sv_catpv(err_str_sv, "SNMP_ERROR:");
         sv_setiv(err_num_sv, snmp_errno);
         break;

      default:
         break;
   }

   if (response) snmp_free_pdu(response);

   return(status);
}

static int
not_here(s)
char *s;
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

static double
constant(name, arg)
char *name;
int arg;
{
    errno = 0;
    switch (*name) {
    case 'R':
	if (strEQ(name, "RECEIVED_MESSAGE"))
#ifdef RECEIVED_MESSAGE
	    return RECEIVED_MESSAGE;
#else
	    goto not_there;
#endif
	break;
    case 'S':
	if (strEQ(name, "SNMPERR_BAD_ADDRESS"))
#ifdef SNMPERR_BAD_ADDRESS
	    return SNMPERR_BAD_ADDRESS;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMPERR_BAD_LOCPORT"))
#ifdef SNMPERR_BAD_LOCPORT
	    return SNMPERR_BAD_LOCPORT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMPERR_BAD_SESSION"))
#ifdef SNMPERR_BAD_SESSION
	    return SNMPERR_BAD_SESSION;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMPERR_GENERR"))
#ifdef SNMPERR_GENERR
	    return SNMPERR_GENERR;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMPERR_TOO_LONG"))
#ifdef SNMPERR_TOO_LONG
	    return SNMPERR_TOO_LONG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_ADDRESS"))
#ifdef SNMP_DEFAULT_ADDRESS
	    return SNMP_DEFAULT_ADDRESS;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_COMMUNITY_LEN"))
#ifdef SNMP_DEFAULT_COMMUNITY_LEN
	    return SNMP_DEFAULT_COMMUNITY_LEN;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_ENTERPRISE_LENGTH"))
#ifdef SNMP_DEFAULT_ENTERPRISE_LENGTH
	    return SNMP_DEFAULT_ENTERPRISE_LENGTH;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_ERRINDEX"))
#ifdef SNMP_DEFAULT_ERRINDEX
	    return SNMP_DEFAULT_ERRINDEX;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_ERRSTAT"))
#ifdef SNMP_DEFAULT_ERRSTAT
	    return SNMP_DEFAULT_ERRSTAT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_PEERNAME"))
#ifdef SNMP_DEFAULT_PEERNAME
	    return 0;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_REMPORT"))
#ifdef SNMP_DEFAULT_REMPORT
	    return SNMP_DEFAULT_REMPORT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_REQID"))
#ifdef SNMP_DEFAULT_REQID
	    return SNMP_DEFAULT_REQID;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_RETRIES"))
#ifdef SNMP_DEFAULT_RETRIES
	    return SNMP_DEFAULT_RETRIES;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_TIME"))
#ifdef SNMP_DEFAULT_TIME
	    return SNMP_DEFAULT_TIME;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_TIMEOUT"))
#ifdef SNMP_DEFAULT_TIMEOUT
	    return SNMP_DEFAULT_TIMEOUT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SNMP_DEFAULT_VERSION"))
#ifdef SNMP_DEFAULT_VERSION
	    return SNMP_DEFAULT_VERSION;
#else
	    goto not_there;
#endif
	break;
    case 'T':
	if (strEQ(name, "TIMED_OUT"))
#ifdef TIMED_OUT
	    return TIMED_OUT;
#else
	    goto not_there;
#endif
	break;
    default:
	break;
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}


MODULE = SNMP		PACKAGE = SNMP		PREFIX = snmp

BOOT:
# first blank line terminates bootstrap code
Mib = 0;
snmp_set_quick_print(1);

double
constant(name,arg)
	char *		name
	int		arg


SnmpSession *
snmp_new_session(version, community, peer, port, retries, timeout)
        char *	version
        char *	community
        char *	peer
        int	port
        int	retries
        int	timeout
	CODE:
	{
	   SnmpSession session;
	   SnmpSession *ss;

           memset(&session, 0, sizeof(SnmpSession));

	   if (strcmp(version, "1") != 0) {
	      warn("SNMP v1 support only\n");
           }

           session.version = SNMP_VERSION_1;
           session.community_len = strlen((char *)community);
           session.community = (u_char *)community;
	   session.peername = peer;
	   session.remote_port = port;
           session.retries = retries; /* 5 */
           session.timeout = timeout; /* 1000000L */
           session.authenticator = NULL;

           snmp_synch_setup(&session);

           ss = snmp_open(&session);

           if (ss == NULL) {
	      warn("Couldn't open SNMP session");
           }

           RETVAL = ss;
	}
        OUTPUT:
        RETVAL


int
snmp_setmib(mib_file,force=0)
	char *		mib_file
	int		force
	CODE:
        {
	SV *verbose;

  fprintf(stderr,"hi in setmib %ld\n",Mib);
           if (((mib_file != NULL) && (*mib_file != '\0')) || force || !Mib) {
  fprintf(stderr,"hi in setmib %ld:%s\n",Mib,mib_file);
	      verbose = perl_get_sv("SNMP::verbose", 0x01 | 0x04);

              if (Mib) Mib = __free_tree(Mib);

              if (SvIV(verbose)) fprintf (stderr, "initializing MIB...");
              fflush(stderr);

              if ((mib_file == NULL) || (*mib_file == '\0')) {
                 init_mib();
              } else {
	         Mib = read_mib(mib_file);
              }

              if (Mib) {
                 if (SvIV(verbose)) fprintf(stderr, "done\n");
              } else {
                 if (SvIV(verbose)) fprintf(stderr, "failed\n");
              }
           }
           RETVAL = (I32)Mib;
        }
        OUTPUT:
        RETVAL

int
snmp_set(sess_ref, varlist_ref)
        SV *	sess_ref
        SV *	varlist_ref
	PPCODE:
	{
           AV *varlist;
           SV **varbind_ref;
           SV **varbind_tag_f;
           SV **varbind_iid_f;
           SV **varbind_val_f;
           AV *varbind;
	   I32 varlist_len;
	   I32 varlist_ind;
	   I32 varbind_len;
           SnmpSession *ss;
           struct snmp_pdu *pdu, *response;
           struct variable_list *vars;
           struct variable_list *response_vars;
           struct variable_list *last_vars;
	   oid *oid_arr;
	   int oid_arr_len = MAX_NAME_LEN;
           SV *tmp_sv;
           SV **sess_ptr_sv;
           SV **err_str_svp;
           SV **err_num_svp;
           SV **err_ind_svp;
           int status = 0;
           int type;

           oid_arr = (oid*)malloc(sizeof(oid) * MAX_NAME_LEN);

           if (oid_arr && SvROK(sess_ref) && SvROK(varlist_ref)) {

              sess_ptr_sv = hv_fetch((HV*)SvRV(sess_ref), "SessPtr", 7, 1);
	      ss = (SnmpSession *)SvIV((SV*)SvRV(*sess_ptr_sv));
              err_str_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorStr", 8, 1);
              err_num_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorNum", 8, 1);
              err_ind_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorInd", 8, 1);
              sv_setpv(*err_str_svp, "");
              sv_setiv(*err_num_svp, 0);
              sv_setiv(*err_ind_svp, 0);

              pdu = snmp_pdu_create(SET_REQ_MSG);

              varlist = (AV*) SvRV(varlist_ref);
              varlist_len = av_len(varlist);
	      for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);

	            varbind_tag_f = av_fetch(varbind, VARBIND_TAG_F, 0);
	            varbind_iid_f = av_fetch(varbind, VARBIND_IID_F, 0);
	            varbind_val_f = av_fetch(varbind, VARBIND_VAL_F, 0);

                    if (varbind_tag_f && varbind_iid_f && varbind_val_f &&
	                __tag2oid(SvPV(*varbind_tag_f, na),
                                        SvPV(*varbind_iid_f, na),
                                        oid_arr, &oid_arr_len, &type))
                        __add_var_val_str(pdu, oid_arr, oid_arr_len,
                                          SvPV(*varbind_val_f, na),
                                          SvCUR(*varbind_val_f), type);
                    else goto err;
                 } /* if var_ref is ok */
              } /* for all the vars */

	      status = __send_sync_pdu(ss, pdu, &response_vars,
				       NO_RETRY_NOSUCH,
                                       *err_str_svp, *err_num_svp, 
                                       *err_ind_svp);

	      XPUSHs(sv_2mortal(newSViv(snmp_errno)));
           } else {
err:
              XPUSHs(&sv_undef); /* no mem or bad args */
           }
	Safefree(oid_arr);
        }


void
snmp_get(sess_ref, retry_nosuch, varlist_ref)
        SV *	sess_ref
        int	retry_nosuch
        SV *	varlist_ref
	PPCODE:
	{
           AV *varlist;
           SV **varbind_ref;
           SV **varbind_tag_f;
           SV **varbind_iid_f;
           AV *varbind;
	   I32 varlist_len;
	   I32 varlist_ind;
	   I32 varbind_len;
           struct snmp_session *ss;
           struct snmp_pdu *pdu, *response;
           struct variable_list *vars;
           struct variable_list *response_vars;
           struct variable_list *last_vars;
	   oid *oid_arr;
	   int oid_arr_len = MAX_NAME_LEN;
           SV *tmp_sv;
           int type;
	   char tmp_type_str[MAX_TYPE_NAME_LEN];
	   char str_buf[2048];
           SV **sess_ptr_sv;
           SV **err_str_svp;
           SV **err_num_svp;
           SV **err_ind_svp;
           int status;

           oid_arr = (oid*)malloc(sizeof(oid) * MAX_NAME_LEN);

           if (oid_arr && SvROK(sess_ref) && SvROK(varlist_ref)) {

              sess_ptr_sv = hv_fetch((HV*)SvRV(sess_ref), "SessPtr", 7, 1);
	      ss = (SnmpSession *)SvIV((SV*)SvRV(*sess_ptr_sv));
              err_str_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorStr", 8, 1);
              err_num_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorNum", 8, 1);
              err_ind_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorInd", 8, 1);
              sv_setpv(*err_str_svp, "");
              sv_setiv(*err_num_svp, 0);
              sv_setiv(*err_ind_svp, 0);

              pdu = snmp_pdu_create(GET_REQ_MSG);

              varlist = (AV*) SvRV(varlist_ref);
              varlist_len = av_len(varlist);
	      for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);

	            varbind_tag_f = av_fetch(varbind, VARBIND_TAG_F, 0);
	            varbind_iid_f = av_fetch(varbind, VARBIND_IID_F, 0);

                    if (varbind_tag_f && varbind_iid_f &&
	                __tag2oid(SvPV(*varbind_tag_f, na),
                                        SvPV(*varbind_iid_f, na),
                                        oid_arr, &oid_arr_len, NULL))
                        snmp_add_null_var(pdu, oid_arr, oid_arr_len);
                 } /* if var_ref is ok */
              } /* for all the vars */

	      status = __send_sync_pdu(ss, pdu, &response_vars,
				       retry_nosuch,
                                       *err_str_svp,*err_num_svp,*err_ind_svp);

	      last_vars = response_vars;

	      for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);

		    varbind_tag_f = av_fetch(varbind, VARBIND_TAG_F, 0);
		    varbind_iid_f = av_fetch(varbind, VARBIND_IID_F, 0);
                    vars = NULL;
                    if (varbind_tag_f && varbind_iid_f &&
	                __tag2oid(SvPV(*varbind_tag_f, na),
                                        SvPV(*varbind_iid_f, na),
                                        oid_arr, &oid_arr_len, &type)) {

		       for (vars = last_vars; vars; vars=vars->next_variable) {
		          if (__oid_cmp(oid_arr, oid_arr_len, vars->name,
                                        vars->name_length) == 0) {
                            last_vars = vars->next_variable;
			    break;
                          }
                       }
                    }
		    if (vars) {
		       __get_type_str(type, tmp_type_str);
                       tmp_sv = newSVpv(tmp_type_str,strlen(tmp_type_str));
                       av_store(varbind, VARBIND_TYPE_F, tmp_sv);
                       sprint_value(str_buf,vars->name,vars->name_length,vars);
                       tmp_sv= newSVpv((char*)str_buf, strlen(str_buf));
                       av_store(varbind, VARBIND_VAL_F, tmp_sv);
                       XPUSHs(sv_mortalcopy(tmp_sv));
                    } else {
                       av_store(varbind, VARBIND_VAL_F, &sv_undef);
	      	       av_store(varbind, VARBIND_TYPE_F, &sv_undef);
                       XPUSHs(&sv_undef);
                    }
                 }
              }
              /* hey don't forget to free response vars */
              while (response_vars) {
	        vars = response_vars->next_variable;
                if (response_vars->name) free(response_vars->name);
                if (response_vars->val.string) free(response_vars->val.string);
                free(response_vars);
                response_vars = vars;
              }
           } else {
              XPUSHs(&sv_undef); /* no mem or bad args */
	   }
	Safefree(oid_arr);
	}

int
snmp_getnext(sess_ref, varlist_ref)
        SV *	sess_ref
        SV *	varlist_ref
	PPCODE:
	{
           AV *varlist;
           SV **varbind_ref;
           SV **varbind_tag_f;
           SV **varbind_iid_f;
           AV *varbind;
	   I32 varlist_len;
	   I32 varlist_ind;
	   I32 varbind_len;
           struct snmp_session *ss;
           struct snmp_pdu *pdu, *response;
           struct variable_list *vars;
           struct variable_list *response_vars;
           struct variable_list *last_vars;
	   oid *oid_arr;
	   int oid_arr_len = MAX_NAME_LEN;
           SV *tmp_sv;
           int type;
	   char tmp_type_str[MAX_TYPE_NAME_LEN];
           SV **sess_ptr_sv;
           SV **err_str_svp;
           SV **err_num_svp;
           SV **err_ind_svp;
           int status;
	   char str_buf[2048];
           char *label;
           char *iid;

           oid_arr = (oid*)malloc(sizeof(oid) * MAX_NAME_LEN);

           if (oid_arr && SvROK(sess_ref) && SvROK(varlist_ref)) {

              sess_ptr_sv = hv_fetch((HV*)SvRV(sess_ref), "SessPtr", 7, 1);
	      ss = (SnmpSession *)SvIV((SV*)SvRV(*sess_ptr_sv));
              err_str_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorStr", 8, 1);
              err_num_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorNum", 8, 1);
              err_ind_svp = hv_fetch((HV*)SvRV(sess_ref), "ErrorInd", 8, 1);
              sv_setpv(*err_str_svp, "");
              sv_setiv(*err_num_svp, 0);
              sv_setiv(*err_ind_svp, 0);

              pdu = snmp_pdu_create(GETNEXT_REQ_MSG);

              varlist = (AV*) SvRV(varlist_ref);
              varlist_len = av_len(varlist);
	      for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);
	            varbind_tag_f = av_fetch(varbind, VARBIND_TAG_F, 0);
	            varbind_iid_f = av_fetch(varbind, VARBIND_IID_F, 0);
                    __tag2oid(
                             (varbind_tag_f ? SvPV(*varbind_tag_f, na) : NULL),
                             (varbind_iid_f ? SvPV(*varbind_iid_f, na) : NULL),
                                        oid_arr, &oid_arr_len, NULL);
                    snmp_add_null_var(pdu, oid_arr, oid_arr_len);
                 } /* if var_ref is ok */
              } /* for all the vars */

	      status = __send_sync_pdu(ss, pdu, &response_vars,
				       NO_RETRY_NOSUCH,
                                       *err_str_svp, *err_num_svp,
				       *err_ind_svp);

	      last_vars = response_vars;

	      for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);

                    vars = last_vars;

		    if (vars) {
                       str_buf[0] = '\0'; label == NULL; iid = NULL;
                       sprint_objid(str_buf, vars->name, vars->name_length);
                       if ((__get_last_label_iid(str_buf, &label, &iid,
                                                 FAIL_ON_NULL_IID) == FAILURE)
	                   || !label || !iid) goto err;
		       type=TYPE_NULL;
		       __tag2oid(label,NULL,NULL,NULL,&type);

                       av_store(varbind, VARBIND_TAG_F,
                                 newSVpv(label, strlen(label)));
                       av_store(varbind, VARBIND_IID_F,
                                 newSVpv(iid, strlen(iid)));
		       __get_type_str(type, tmp_type_str);
                       tmp_sv = newSVpv(tmp_type_str, strlen(tmp_type_str));
	      	       av_store(varbind, VARBIND_TYPE_F, tmp_sv);

                       sprint_value(str_buf,vars->name,vars->name_length,vars);
                       tmp_sv = newSVpv((char*)str_buf, strlen(str_buf));
                       av_store(varbind, VARBIND_VAL_F, tmp_sv);
                       XPUSHs(sv_mortalcopy(tmp_sv));
                    } else {
err:
                       av_store(varbind, VARBIND_IID_F, &sv_undef);
                       av_store(varbind, VARBIND_VAL_F, &sv_undef);
	      	       av_store(varbind, VARBIND_TYPE_F, &sv_undef);
                       XPUSHs(&sv_undef);
                    }
                    if (last_vars) last_vars = last_vars->next_variable;
                 }
              }
              /* hey don't forget to free response vars */
              while (response_vars) {
	        vars = response_vars->next_variable;
                if (response_vars->name) free(response_vars->name);
                if (response_vars->val.string) free(response_vars->val.string);
                free(response_vars);
                response_vars = vars;
              }
           } else {
              XPUSHs(&sv_undef); /* no mem or bad args */
	   }
	Safefree(oid_arr);
	}

char *
snmp_get_type(tag)
	char *		tag
	CODE:
	{
	   struct tree *tp  = NULL;
	   static char type_str[MAX_TYPE_NAME_LEN];
           char *ret = NULL;

           if (tag && *tag) tp = find_node(tag, Mib);
           if (tp) __get_type_str(tp->type, ret = type_str);
	   RETVAL = ret;
	}
	OUTPUT:
        RETVAL

char *
snmp_map_enum(tag)
	char *		tag
	CODE:
	{
	   struct tree *tp  = NULL;
	   static char type_str[MAX_TYPE_NAME_LEN];
           char *ret = NULL;

           if (tag && *tag) tp = find_node(tag, Mib);
           if (tp) __get_type_str(tp->type, ret = type_str);
	   RETVAL = ret;
	}
	OUTPUT:
        RETVAL

char *
snmp_translate(var,mode)
	char *		var
	int		mode
	CODE:
	{
	   char str_buf[2048];
           int status = FAILURE;

	   switch (mode) {
              case SNMP_XLATE_MODE_TAG2OID:
	       status = __translate_str(var, str_buf, mode);
               break;
              case SNMP_XLATE_MODE_OID2TAG:
	       status = __translate_str(str_buf, var, mode);
               break;
              default:
           }
	   RETVAL = (status == SUCCESS ? str_buf : NULL);
	}
        OUTPUT:
        RETVAL

MODULE = SNMP	PACKAGE = SnmpSessionPtr	PREFIX = snmp_session_
void
snmp_session_DESTROY(sess_ptr)
	SnmpSession *sess_ptr
	CODE:
	  /* printf("Now in SnmpSessionPtr::DESTROY\n"); */
          snmp_close( sess_ptr );


#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <sys/types.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <ctype.h>
#ifdef I_SYS_TIME
#include <sys/time.h>
#endif
#include <netdb.h>
#include <stdlib.h>

#ifndef __P
#define __P(x) x
#endif

#ifndef in_addr_t
#define in_addr_t u_long
#endif

#ifdef HAS_MEMCPY
#define bcopy(s,d,l) memcpy((d),(s),(l))
#endif

#ifdef WIN32
#define SOCK_STARTUP winsock_startup()
#define SOCK_CLEANUP winsock_cleanup()
#define DLL_IMPORT   __declspec( dllimport )
#else
#define SOCK_STARTUP
#define SOCK_CLEANUP
#define DLL_IMPORT
#endif

DLL_IMPORT extern struct tree *Mib;
DLL_IMPORT extern int snmp_errno;

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "snmp_impl.h"
#include "snmp.h"
#include "parse.h"
#include "mib.h"

#define SUCCESS 1
#define FAILURE 0

#define VARBIND_TAG_F 0
#define VARBIND_IID_F 1
#define VARBIND_VAL_F 2
#define VARBIND_TYPE_F 3

#define TYPE_UNKNOWN 0
#define MAX_TYPE_NAME_LEN 16

static int __is_numeric_oid _((char*));
static int __is_leaf _((struct tree*));
static int __translate_appl_type _((char*));
static int __translate_asn_type _((int));
static int __sprint_value _((char *, struct variable_list*, struct tree *,
                             int, int));
static int __sprint_num_objid _((char *, oid *, int));
static int __scan_num_objid _((char *, oid *, int *));
static int __get_type_str _((int, char *));
static int __get_label_iid _((char *, char **, char **, int));
static int __oid_cmp _((oid *, int, oid *, int));
static struct tree * __oid2tp _((oid*, int, struct tree *, int*));
static struct tree * __tag2oid _((char *, char *, oid  *, int  *, int *));
static int __concat_oid_str _((oid *, int *, char *));
static void __add_var_val_str _((struct snmp_pdu *, oid *, int, char *,
                                 int, int));
static int __send_sync_pdu _((struct snmp_session *, struct snmp_pdu *,
                           struct snmp_pdu **, int , SV *, SV *, SV *));
#define USE_LONG_NAMES 2
#define FAIL_ON_NULL_IID 1
#define NO_FAIL_ON_NULL_IID 0

typedef struct snmp_session SnmpSession;

static int __is_numeric_oid (oidstr)
char* oidstr;
{
  if (!oidstr) return 0;
  for (; *oidstr; oidstr++) {
     if (isalpha(*oidstr)) return 0;
  }
  return(1);
}

static int __is_leaf (tp)
struct tree* tp;
{
   char buf[MAX_TYPE_NAME_LEN];
   return (tp && __get_type_str(tp->type,buf));
}

static int
__translate_appl_type(typestr)
char* typestr;
{
	if (!strncmp(typestr,"INTEGER",3))
            return(TYPE_INTEGER);
	if (!strcmp(typestr,"COUNTER")) /* check it all in case counter64 */
            return(TYPE_COUNTER);
	if (!strncmp(typestr,"GAUGE",3))
            return(TYPE_GAUGE);
	if (!strncmp(typestr,"IPADDR",3))
            return(TYPE_IPADDR);
	if (!strncmp(typestr,"OCTETSTR",3))
            return(TYPE_OCTETSTR);
	if (!strncmp(typestr,"TICKS",3))
            return(TYPE_TIMETICKS);
	if (!strncmp(typestr,"OPAQUE",3))
            return(TYPE_OPAQUE);
	if (!strncmp(typestr,"OBJECTID",3))
            return(TYPE_OBJID);
	if (!strncmp(typestr,"NETADDR",3))
	    return(TYPE_NETADDR);
	if (!strncmp(typestr,"COUNTER64",3))
	    return(TYPE_COUNTER64);

        return(TYPE_UNKNOWN);
}

static int
__translate_asn_type(type)
int type;
{
   switch (type) {
        case ASN_INTEGER:
            return(TYPE_INTEGER);
	    break;
	case ASN_OCTET_STR:
            return(TYPE_OCTETSTR);
	    break;
	case ASNT_OPAQUE:
            return(TYPE_OPAQUE);
	    break;
	case ASN_OBJECT_ID:
            return(TYPE_OBJID);
	    break;
	case TIMETICKS:
            return(TYPE_TIMETICKS);
	    break;
	case GAUGE:
            return(TYPE_GAUGE);
	    break;
	case COUNTER:
            return(TYPE_COUNTER);
	    break;
	case IPADDRESS:
            return(TYPE_IPADDR);
	    break;
	case ASN_NULL:
            return(TYPE_NULL);
	    break;
	case UINTEGER:
            return(TYPE_UINTEGER);
	    break;
	default:
            return(TYPE_OTHER);
            break;
        }
}

#define USE_ENUMS 1
#define USE_SPRINT_VALUE 2
static int __sprint_value (buf, var, tp, type, flag)
char * buf;
struct variable_list * var;
struct tree * tp;
int type;
int flag;
{
   int len = 0;
   u_char* ip;

   buf[0] = '\0';
   if (flag == USE_SPRINT_VALUE) {
	sprint_value(buf, var->name, var->name_length, var);
	len = strlen(buf);
   } else {
     switch (var->type) {
        case ASN_INTEGER:
           if (flag == USE_ENUMS) {
              /* !!!! NOTE not implemented yet NOTE!!!!*/
              sprintf(buf,"%ld", *var->val.integer);
              len = strlen(buf);
           } else {
              sprintf(buf,"%ld", *var->val.integer);
              len = strlen(buf);
           }
           break;

        case GAUGE:
        case COUNTER:
        case TIMETICKS:
        case UINTEGER:
           sprintf(buf,"%lu", (unsigned long) *var->val.integer);
           len = strlen(buf);
           break;

        case ASN_OCTET_STR:
        case ASNT_OPAQUE:
           bcopy((char*)var->val.string, buf, var->val_len);
           len = var->val_len;
           break;

        case IPADDRESS:
          ip = (u_char*)var->val.string;
          sprintf(buf, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
          len = strlen(buf);
          break;

        case OBJID:
          __sprint_num_objid(buf, (oid *)(var->val.objid),
                             var->val_len/sizeof(oid));
          len = strlen(buf);
          break;

        case COUNTER64:
        case ASN_BIT_STR:
        case NSAP:
        default:

     }
   }
   return(len);
}

static int __sprint_num_objid (buf, objid, len)
char *buf;
oid *objid;
int len;
{
   int i;
   buf[0] = '\0';
   for (i=0; i < len; i++) {
	sprintf(buf,".%ld",*objid++);
	buf += strlen(buf);
   }
   return SUCCESS;
}

static int __scan_num_objid (buf, objid, len)
char *buf;
oid *objid;
int *len;
{
   char *cp;
   *len = 0;
   if (*buf == '.') buf++;
   cp = buf;
   while (*buf) {
      if (*buf++ == '.') {
         *objid++ = atoi(cp);
         (*len)++;
         cp = buf;
      } else {
         if (isalpha(*buf)) return FAILURE;
      }
   }
   *objid++ = atoi(cp);
   (*len)++;
   return SUCCESS;
}

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
       		strcpy(str, "TICKS");
	        break;
	case TYPE_OPAQUE:
       		strcpy(str, "OPAQUE");
	        break;
	case TYPE_COUNTER64:
       		strcpy(str, "COUNTER64");
	        break;
	case TYPE_OTHER:
	case TYPE_NULL:
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
static int __get_label_iid (name, last_label, iid, flag)
char * name;
char ** last_label;
char ** iid;
int flag;
{
   char *lcp;
   char *icp;
   int len = strlen(name);
   int found_label = 0;

   *last_label = *iid = NULL;

   if (len == 0) return(FAILURE);

   lcp = icp = &(name[len]);

   while (lcp > name) {
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

   if (!found_label || (!isdigit(*(icp+1)) && (flag & FAIL_ON_NULL_IID)))
      return(FAILURE);

   if (*icp) *(icp++) = '\0';
   *last_label = (flag & USE_LONG_NAMES ? name : lcp);
   *iid = icp;

   return(SUCCESS);
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

static struct tree *
__tag2oid(tag, iid, oid_arr, oid_arr_len, type)
char * tag;
char * iid;
oid  * oid_arr;
int  * oid_arr_len;
int  * type;
{
   struct tree *tp = NULL;
   struct tree *rtp = NULL;
   oid newname[MAX_OID_LEN], *op;
   int newname_len = 0;

   if (type) *type = TYPE_UNKNOWN;
   if (oid_arr_len) *oid_arr_len = 0;
   if (!tag || !*tag) return NULL;

   if (strchr(tag,'.')) { /* if multi part tag - either numeric or textual */
      if (__scan_num_objid(tag, newname, &newname_len) ||
          read_objid(tag, newname, &newname_len)) {
         rtp = tp = get_tree(newname, newname_len, Mib);
         if (type) *type = tp->type;
         if ((oid_arr == NULL) || (oid_arr_len == NULL)) return rtp;
         bcopy((char*)newname,oid_arr,newname_len*sizeof(oid));
         *oid_arr_len = newname_len;
         if (iid && *iid) __concat_oid_str(oid_arr, oid_arr_len, iid);
         return(rtp);
      }
   } else { /* else it is a leaf */
      rtp = tp = find_node(tag, Mib);
      if (tp) {
         if (type) *type = tp->type;
         if ((oid_arr == NULL) || (oid_arr_len == NULL)) return rtp;
         /* code taken from get_node in snmp_client.c */
         for(op = newname + MAX_OID_LEN - 1; op >= newname; op--){
           *op = tp->subid;
	   tp = tp->parent;
	   if (tp == NULL)
	      break;
         }
         *oid_arr_len = newname + MAX_OID_LEN - op;
         bcopy(op, oid_arr, (newname + MAX_OID_LEN - op) * sizeof(oid));
         if (iid && *iid) __concat_oid_str(oid_arr, oid_arr_len, iid);
         return rtp;
      }
   }
   return NULL;
}
/* searches down the mib tree for the given oid
   returns the last found tp and its index in lastind
 */
static struct tree *
__oid2tp (oidp, len, subtree, lastind)
oid* oidp;
int len;
struct tree * subtree;
int* lastind;
{
    struct tree    *return_tree = NULL;


    for (; subtree; subtree = subtree->next_peer) {
	if (*oidp == subtree->subid){
	    goto found;
	}
    }
    *lastind=0;
    return NULL;

found:
    if (len > 1){
       return_tree =
          __oid2tp(oidp + 1, len - 1, subtree->child_list, lastind);
       *lastind++;
    } else {
       *lastind=1;
    }
    if (return_tree)
	return return_tree;
    else
	return subtree;
}

/* function: __concat_oid_str
 *
 * This function converts a dotted-decimal string, soid_str, to an array
 * of oid types and concatenates them on doid_arr begining at the index
 * specified by doid_arr_len.
 *
 * returns : SUCCESS, FAILURE
 */
static int
__concat_oid_str(doid_arr, doid_arr_len, soid_str)
oid *doid_arr;
int *doid_arr_len;
char * soid_str;
{
   char soid_buf[MAX_NAME_LEN*3];
   char *cp;

   if (!soid_str || !*soid_str) return SUCCESS; /* successfully added nothing */
   if (*soid_str == '.') soid_str++;
   strcpy(soid_buf, soid_str);
   cp = strtok(soid_buf,".");
   while (cp) {
     doid_arr[(*doid_arr_len)++] =  atoi(cp);
     cp = strtok(NULL,".");
   }
   return(SUCCESS);
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
    oid oidbuf[MAX_OID_LEN];

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
        read_objid(val, oidbuf, &(vars->val_len));
	vars->val.objid = (oid *)malloc(vars->val_len * sizeof(oid));
	bcopy((char *)oidbuf, (char *)vars->val.objid,
	      vars->val_len * sizeof(oid));
        break;

      default:
        vars->type = ASN_NULL;
	vars->val_len = 0;
	vars->val.string = NULL;
    }

}

#define NO_RETRY_NOSUCH 0
/* takes ss and pdu as input and updates the 'response' argument */
/* the input 'pdu' argument will be freed */
static int
__send_sync_pdu(ss, pdu, response, retry_nosuch,
	        err_str_sv, err_num_sv, err_ind_sv)
struct snmp_session *ss;
struct snmp_pdu *pdu;
struct snmp_pdu **response;
int retry_nosuch;
SV * err_str_sv;
SV * err_num_sv;
SV * err_ind_sv;
{
   int status, count;
   struct variable_list *vars;
   char str_buf[2048];
   char err_buf[2048];
   char *label;
   char *iid;
   long len;
   long command = pdu->command;
   *response = NULL;
retry:

   status = snmp_synch_response(ss, pdu, response);

   if ((*response == NULL) && (status == STAT_SUCCESS)) status = STAT_ERROR;

   switch (status) {
      case STAT_SUCCESS:
	 switch ((*response)->errstat) {
	    case SNMP_ERR_NOERROR:
	       break;

            case SNMP_ERR_NOSUCHNAME:
	       for(count = 1, vars = (*response)->variables;
                   vars && (count != (*response)->errindex);
		   vars = vars->next_variable, count++); /*find bad varbind */

               if (vars) {
                  str_buf[0] = '\0'; label == NULL; iid = NULL;
                  sprint_objid(str_buf, vars->name, vars->name_length);

                  if ((__get_label_iid(str_buf, &label, &iid,
                                            FAIL_ON_NULL_IID) == SUCCESS)
	               && label && iid) {
                     sprintf(err_buf, "NOSUCHNAME(%s.%s):", label, iid);
                     sv_catpv(err_str_sv, err_buf);
                     sv_setiv(err_num_sv, (*response)->errstat);
                     sv_setiv(err_ind_sv, (*response)->errindex);
                  }
	       }
               if (retry_nosuch && (command == GET_REQ_MSG) &&
		   ((pdu = snmp_fix_pdu(*response, GET_REQ_MSG)) != NULL)) {
			/* may need to free response here */
                	goto retry;
               }

               break;

	    case SNMP_ERR_TOOBIG:
               sv_catpv(err_str_sv, "SNMP_ERR_TOOBIG:");
               sv_setiv(err_num_sv, (*response)->errstat);
	       sv_setiv(err_ind_sv, (*response)->errindex);
               break;
            case SNMP_ERR_BADVALUE:
               sv_catpv(err_str_sv, "SNMP_ERR_BADVALUE:");
               sv_setiv(err_num_sv, (*response)->errstat);
	       sv_setiv(err_ind_sv, (*response)->errindex);
               break;
	    case SNMP_ERR_READONLY:
               sv_catpv(err_str_sv, "SNMP_ERR_READONLY:");
               sv_setiv(err_num_sv, (*response)->errstat);
	       sv_setiv(err_ind_sv, (*response)->errindex);
               break;
	    case SNMP_ERR_GENERR:
               sv_catpv(err_str_sv, "SNMP_ERR_GENERR:");
               sv_setiv(err_num_sv, (*response)->errstat);
	       sv_setiv(err_ind_sv, (*response)->errindex);
               break;
	    case SNMP_ENDOFMIBVIEW:
               sv_catpv(err_str_sv, "SNMP_ENDOFMIBVIEW:");
               sv_setiv(err_num_sv, (*response)->errstat);
	       sv_setiv(err_ind_sv, (*response)->errindex);
	       break;
            /* V2 exceptions - return what you can from response */
	    case SNMP_NOSUCHINSTANCE:
               sv_catpv(err_str_sv, "SNMP_NOSUCHINSTANCE:");
               sv_setiv(err_num_sv, (*response)->errstat);
	       sv_setiv(err_ind_sv, (*response)->errindex);
               break;
	    case SNMP_NOSUCHOBJECT:
               sv_catpv(err_str_sv, "SNMP_NOSUCHOBJECT:");
               sv_setiv(err_num_sv, (*response)->errstat);
	       sv_setiv(err_ind_sv, (*response)->errindex);
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
SOCK_STARTUP;
Mib = 0;
snmp_set_quick_print(1);
init_mib_internals();

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
	   SnmpSession *ss = NULL;
           SV* verbose;

           verbose = perl_get_sv("SNMP::verbose", 0x01 | 0x04);

           memset(&session, 0, sizeof(SnmpSession));

	   if (!strcmp(version, "1")) {
		session.version = SNMP_VERSION_1;
           } else if (!strcmp(version, "2") || !strcmp(version, "2c")) {
		session.version = SNMP_VERSION_2c;
           } else {
		if (SvIV(verbose))
                   warn("Unsupported SNMP version (%s)\n", version);
                goto end;
	   }

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
	      if (SvIV(verbose))
                 warn("Couldn't open SNMP session");
           }
        end:
           RETVAL = ss;
	}
        OUTPUT:
        RETVAL


int
snmp_add_mib_dir(mib_dir,force=0)
	char *		mib_dir
	int		force
	CODE:
        {
	SV *verbose;
	int result;
        verbose = perl_get_sv("SNMP::verbose", 0x01 | 0x04);
        if (mib_dir && *mib_dir) {
	   result = add_mibdir(mib_dir);
        }
        if (result) {
           if (SvIV(verbose)) warn("Added mib dir %s\n", mib_dir);
        } else {
           if (SvIV(verbose)) warn("Failed to add %s\n", mib_dir);
        }
        RETVAL = (I32)result;
        }
        OUTPUT:
        RETVAL


int
snmp_read_mib(mib_file, force=0)
	char *		mib_file
	int		force
	CODE:
        {
	SV *verbose;

        verbose = perl_get_sv("SNMP::verbose", 0x01 | 0x04);

        if (SvIV(verbose)) warn("reading MIB: %s",(mib_file ? mib_file : ""));

        /* if (Mib && force) __free_tree(Mib); needs more work to cleanup */

        if ((mib_file == NULL) || (*mib_file == '\0')) {
           if (Mib == NULL) {
		init_mib();
	   }
        } else {
	   Mib = read_mib(mib_file);
        }
        if (Mib) {
           if (SvIV(verbose)) warn("done\n");
        } else {
           if (SvIV(verbose)) warn("failed\n");
        }
        RETVAL = (I32)Mib;
        }
        OUTPUT:
        RETVAL


int
snmp_read_module(module)
	char *		module
	CODE:
        {
	SV *verbose;

        verbose = perl_get_sv("SNMP::verbose", 0x01 | 0x04);

        if (!strcmp(module,"ALL")) {
           Mib = read_all_mibs();
        } else {
	   Mib = read_module(module);
        }
        if (Mib) {
           if (SvIV(verbose)) warn("Read %s\n", module);
        } else {
           if (SvIV(verbose)) warn("Failed reading %s\n", module);
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
           SV **varbind_type_f;
           AV *varbind;
	   I32 varlist_len;
	   I32 varlist_ind;
	   I32 varbind_len;
           SnmpSession *ss;
           struct snmp_pdu *pdu, *response;
           struct variable_list *vars;
           struct variable_list *last_vars;
           struct tree *tp;
	   oid *oid_arr;
	   int oid_arr_len = MAX_NAME_LEN;
           SV *tmp_sv;
           SV **sess_ptr_sv;
           SV **err_str_svp;
           SV **err_num_svp;
           SV **err_ind_svp;
           int status = 0;
           int type;
           SV* verbose;
           verbose = perl_get_sv("SNMP::verbose", 0x01 | 0x04);


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

                    tp=__tag2oid((varbind_tag_f?SvPV(*varbind_tag_f,na):NULL),
                                 (varbind_iid_f?SvPV(*varbind_iid_f,na):NULL),
                                 oid_arr, &oid_arr_len, &type);
                    if (oid_arr_len == 0) {
                       if (SvIV(verbose))
                        warn("error: set: unable to determine oid for object");
                       continue;
                    }
                    if (type == TYPE_UNKNOWN) {
                      varbind_type_f = av_fetch(varbind,VARBIND_TYPE_F,0);
                      type = __translate_appl_type(
                              (*varbind_type_f?SvPV(*varbind_type_f,na):NULL));
                      if (type == TYPE_UNKNOWN) {
                         if (SvIV(verbose))
                            warn("error: set: no type found for object");
                         continue;
                      }
                    }
                    __add_var_val_str(pdu, oid_arr, oid_arr_len,
                                  (varbind_val_f?SvPV(*varbind_val_f,na):NULL),
                                  (varbind_val_f?SvCUR(*varbind_val_f):0),
                                  type);
                 } /* if var_ref is ok */
              } /* for all the vars */

	      status = __send_sync_pdu(ss, pdu, &response,
				       NO_RETRY_NOSUCH,
                                       *err_str_svp, *err_num_svp,
                                       *err_ind_svp);

              if (response) snmp_free_pdu(response);

	      XPUSHs(sv_2mortal(newSViv(snmp_errno)));
           } else {
err:
              /* BUG!!! need to return an error value */
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
           struct variable_list *last_vars;
           struct tree *tp;
           int len;
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
           int sprintval_flag;
           SV* verbose;
           verbose = perl_get_sv("SNMP::verbose", 0x01 | 0x04);

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
	      if (SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseEnums", 8, 1)))
                 sprintval_flag = USE_ENUMS;
	      if (SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseSprintValue", 14, 1)))
                 sprintval_flag = USE_SPRINT_VALUE;

              pdu = snmp_pdu_create(GET_REQ_MSG);

              varlist = (AV*) SvRV(varlist_ref);
              varlist_len = av_len(varlist);
	      for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);

	            varbind_tag_f = av_fetch(varbind, VARBIND_TAG_F, 0);
	            varbind_iid_f = av_fetch(varbind, VARBIND_IID_F, 0);

                    tp=__tag2oid((varbind_tag_f?SvPV(*varbind_tag_f,na):"0"),
                                 (varbind_iid_f?SvPV(*varbind_iid_f,na):NULL),
                                 oid_arr, &oid_arr_len, NULL);
                    if (oid_arr_len) {
                       snmp_add_null_var(pdu, oid_arr, oid_arr_len);
                    } else {
                       if (SvIV(verbose))
                        warn("error: get: unable to determine oid for object");
                       snmp_add_null_var(pdu, oid_arr, oid_arr_len);
                    }
                 } /* if var_ref is ok */
              } /* for all the vars */

	      status = __send_sync_pdu(ss, pdu, &response,
				       retry_nosuch,
                                       *err_str_svp,*err_num_svp,*err_ind_svp);

              last_vars = (response ? response->variables : NULL);

	      for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);

		    varbind_tag_f = av_fetch(varbind, VARBIND_TAG_F, 0);
		    varbind_iid_f = av_fetch(varbind, VARBIND_IID_F, 0);

                    vars = NULL;
	            tp=__tag2oid((varbind_tag_f?SvPV(*varbind_tag_f,na):NULL),
                                 (varbind_iid_f?SvPV(*varbind_iid_f,na):NULL),
                                 oid_arr, &oid_arr_len, &type);

		    for (vars = last_vars; vars; vars=vars->next_variable) {
		       if (__oid_cmp(oid_arr, oid_arr_len, vars->name,
                                     vars->name_length) == 0) {
                          if (type == TYPE_UNKNOWN)
                             type = __translate_asn_type(vars->type);
                          last_vars = vars->next_variable;
			  break;
                       }
                    }
		    if (vars) {
		       __get_type_str(type, tmp_type_str);
                       tmp_sv = newSVpv(tmp_type_str,strlen(tmp_type_str));
                       av_store(varbind, VARBIND_TYPE_F, tmp_sv);
                       len=__sprint_value(str_buf,vars,tp,type,sprintval_flag);
                       tmp_sv= newSVpv((char*)str_buf, len);
                       av_store(varbind, VARBIND_VAL_F, tmp_sv);
                       XPUSHs(sv_mortalcopy(tmp_sv));
                    } else {
                       av_store(varbind, VARBIND_VAL_F, &sv_undef);
	      	       av_store(varbind, VARBIND_TYPE_F, &sv_undef);
                       XPUSHs(&sv_undef);
                    }
                 }
              }
              if (response) snmp_free_pdu(response);
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
           struct variable_list *last_vars;
           struct tree *tp;
           int len;
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
           int getlabel_flag = FAIL_ON_NULL_IID;
           int sprintval_flag;
           SV* verbose;
           verbose = perl_get_sv("SNMP::verbose", 0x01 | 0x04);

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
	      if (SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseLongNames", 12, 1)))
                 getlabel_flag &= USE_LONG_NAMES;
	      if (SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseEnums", 8, 1)))
                 sprintval_flag = USE_ENUMS;
	      if (SvIV(*hv_fetch((HV*)SvRV(sess_ref),"UseSprintValue", 14, 1)))
                 sprintval_flag = USE_SPRINT_VALUE;

              pdu = snmp_pdu_create(GETNEXT_REQ_MSG);

              varlist = (AV*) SvRV(varlist_ref);
              varlist_len = av_len(varlist);
	      for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);
	            varbind_tag_f = av_fetch(varbind, VARBIND_TAG_F, 0);
	            varbind_iid_f = av_fetch(varbind, VARBIND_IID_F, 0);
                    __tag2oid((varbind_tag_f ? SvPV(*varbind_tag_f,na):"0"),
                              (varbind_iid_f ? SvPV(*varbind_iid_f,na):NULL),
                              oid_arr, &oid_arr_len, NULL);
                    if (oid_arr_len) {
                       snmp_add_null_var(pdu, oid_arr, oid_arr_len);
                    } else {
                       /*BUG!!!if we skip one, the response will be off by 1*/
                       if (SvIV(verbose))
                          warn("getnext: unable to determine oid for object");
                       snmp_add_null_var(pdu, oid_arr, oid_arr_len);
                    }
                 } /* if var_ref is ok */
              } /* for all the vars */

	      status = __send_sync_pdu(ss, pdu, &response,
				       NO_RETRY_NOSUCH,
                                       *err_str_svp, *err_num_svp,
				       *err_ind_svp);

              last_vars = (response ? response->variables : NULL);

	      for(varlist_ind = 0; varlist_ind <= varlist_len; varlist_ind++) {
                 varbind_ref = av_fetch(varlist, varlist_ind, 0);
                 if (SvROK(*varbind_ref)) {
                    varbind = (AV*) SvRV(*varbind_ref);

                    vars = last_vars;

		    if (vars) {
                       tp =
                         get_symbol(vars->name,vars->name_length,Mib,str_buf);
                       if (__is_leaf(tp)) {
                          __get_label_iid(str_buf,&label,&iid,getlabel_flag);
                          type = tp->type;
                       } else {
                          type = __translate_asn_type(vars->type);
                       }

                       av_store(varbind, VARBIND_TAG_F,
                                 newSVpv(label, strlen(label)));
                       av_store(varbind, VARBIND_IID_F,
                                 newSVpv(iid, strlen(iid)));
		       __get_type_str(type, tmp_type_str);
                       tmp_sv = newSVpv(tmp_type_str, strlen(tmp_type_str));
	      	       av_store(varbind, VARBIND_TYPE_F, tmp_sv);
                       len=__sprint_value(str_buf,vars,tp,type,sprintval_flag);
                       tmp_sv = newSVpv((char*)str_buf, len);
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

              if (response) snmp_free_pdu(response);

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


void
snmp_dump_packet(flag)
	int		flag
	CODE:
	{
	   snmp_set_dump_packet(flag);
	}


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

#define SNMP_XLATE_MODE_OID2TAG 1
#define SNMP_XLATE_MODE_TAG2OID 0

char *
snmp_translate_obj(var,mode,use_long)
	char *		var
	int		mode
	int		use_long
	CODE:
	{
	   char str_buf[2048];
	   oid oid_arr[MAX_NAME_LEN];
           int oid_arr_len = MAX_NAME_LEN;
           char * label;
           char * iid;
           int status = FAILURE;
           SV* verbose;

           verbose = perl_get_sv("SNMP::verbose", 0x01 | 0x04);

           str_buf[0] = '\0';
  	   switch (mode) {
              case SNMP_XLATE_MODE_TAG2OID:
		if (!get_node(var, oid_arr, &oid_arr_len)) {
		   if (SvIV(verbose)) warn("Unknown OID %s\n",var);
                } else {
                   status = __sprint_num_objid(str_buf, oid_arr, oid_arr_len);
                }
                RETVAL = str_buf;
                break;
             case SNMP_XLATE_MODE_OID2TAG:
		oid_arr_len = 0;
		__concat_oid_str(oid_arr, &oid_arr_len, var);
		str_buf[0] = '\0';
                label = NULL;
                iid = NULL;
		sprint_objid(str_buf, oid_arr, oid_arr_len);
		if (!use_long) {
		  if (((status=__get_label_iid(str_buf,
		       &label, &iid, NO_FAIL_ON_NULL_IID)) == SUCCESS)
		      && label) {
		     strcpy(str_buf, label);
		     if (iid && *iid) {
		       strcat(str_buf, ".");
		       strcat(str_buf, iid);
		     }
 	          }
	        }
                RETVAL = str_buf;
                break;
             default:
	       if (SvIV(verbose)) warn("unknown translation mode: %s\n", mode);
      	       RETVAL = NULL;
           }
	}
        OUTPUT:
        RETVAL

void
snmp_sock_cleanup()
	CODE:
	{
	   SOCK_CLEANUP;
	}

MODULE = SNMP	PACKAGE = SnmpSessionPtr	PREFIX = snmp_session_
void
snmp_session_DESTROY(sess_ptr)
	SnmpSession *sess_ptr
	CODE:
	{
           snmp_close( sess_ptr );
	}









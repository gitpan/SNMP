/*
* file: snmp_impl.h
*/

/*
 * Definitions for SNMP implementation.
 *
 *
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/

#include<stdio.h>

/*
 * Error codes:
 */
/*
 * These must not clash with SNMP error codes (all positive).
 */
#define PARSE_ERROR	-1
#define BUILD_ERROR	-2

#define COMMUNITY_MAX_LEN	64
#define MAX_NAME_LEN		128  /* number of subid's in a objid */

#ifndef NULL
#define NULL 0
#endif

#ifndef TRUE
#define TRUE	1
#endif
#ifndef FALSE
#define FALSE	0
#endif

struct packet_info {
    int 	version;
    u_char 	pdutype;

    /* community based authentication */
    u_char	community[COMMUNITY_MAX_LEN + 1];
    int		community_len;
    int		community_id;

    /* snmp security based authentication */
    oid	        srcParty[64];
    oid		dstParty[64];
    oid		context[64];
    int		srcPartyLength;
    int		dstPartyLength;
    int		contextLength;
    struct partyEntry *srcp, *dstp;
    struct contextEntry *cxp;

    u_char	*packet_end;
};

#define READ	    1
#define WRITE	    0

#define RESERVE1    0
#define RESERVE2    1
#define COMMIT      2
#define ACTION	    3
#define FREE        4

/* See important comment in snmp_vars.c relating to a change
   in the way the access control word is interpreted */
#define RONLY	0xAAAA	/* read access for everyone */
#define RWRITE	0xFABB	/* add write access for community private */
                        /* & write access for V2 GLOBAL stuff -- Wes */
#define NOACCESS 0x0000	/* no access for anybody */

#define INTEGER	    ASN_INTEGER
#define STRING	    ASN_OCTET_STR
#define OBJID	    ASN_OBJECT_ID
#define NULLOBJ	    ASN_NULL
#define BITSTRING   ASN_BIT_STR  /* HISTORIC - don't use */

/* defined types (from the SMI, RFC 1157) */
#define IPADDRESS   (ASN_APPLICATION | 0)
#define COUNTER	    (ASN_APPLICATION | 1)
#define GAUGE	    (ASN_APPLICATION | 2)
#define UNSIGNED    (ASN_APPLICATION | 2)  /* RFC 1902 - same as GAUGE */
#define TIMETICKS   (ASN_APPLICATION | 3)
#define ASNT_OPAQUE (ASN_APPLICATION | 4)  /* changed so no conflict with other includes */

/* defined types (from the SMI, RFC 1442) */
#define NSAP	    (ASN_APPLICATION | 5)  /* historic - don't use */
#define COUNTER64   (ASN_APPLICATION | 6)
#define UINTEGER    (ASN_APPLICATION | 7)  /* historic - don't use */

struct trapVar {
    oid	    *varName;
    int	    varNameLen;
    u_char  varType;
    int	    varLen;
    u_char  *varVal;
    struct trapVar *next;  
};

#ifdef DODEBUG
/* changed to ERROR_MSG to eliminate conflict with other includes */
#define ERROR_MSG(string)	snmp_detail = string
#else
#define ERROR_MSG(string)
#endif

/* from snmp.c*/
extern u_char	sid[];	/* size SID_MAX_LEN */
extern char *snmp_detail;


/*
 * For calling secauth_build, FIRST_PASS is an indication that a new nonce
 * and lastTimeStamp should be recorded.  LAST_PASS is an indication that
 * the packet should be checksummed and encrypted if applicable, in
 * preparation for transmission.
 * 0 means do neither, FIRST_PASS | LAST_PASS means do both.
 * For secauth_parse, FIRST_PASS means decrypt the packet, otherwise leave it
 * alone.  LAST_PASS is ignored.
 */
#define FIRST_PASS	1
#define	LAST_PASS	2
u_char	*snmp_comstr_parse __P((u_char *, int *, u_char *, int *, long *));
u_char	*snmp_comstr_build __P((u_char *, int *, u_char *, int *, int *, int));

u_char	*snmp_party_parse __P((u_char *, int *, struct packet_info *,
                                 oid *, int *, oid *, int *, oid *, int *, int));
u_char	*snmp_party_build __P((u_char *, int *, struct packet_info *, int,
                                 oid *, int, oid *, int, oid *, int, int *, int));


int has_access __P((u_char, int, int, int));

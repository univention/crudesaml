/* $Id: saml.h,v 1.5 2011/04/03 05:22:45 manu Exp $ */
/*
 * Copyright (c) 2009,2011 Emmanuel Dreyfus
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

#define MAYBE_COMPRESS 1
#define SAML_MINLEN 128

struct saml_trusted_sp {
	const char *provider_id;
	SLIST_ENTRY(saml_trusted_sp) next;
};

typedef struct {
        LassoServer *lasso_server;
        const char *uid_attr;
        time_t grace;
	int flags;
	SLIST_HEAD(saml_trusted_sp_head, saml_trusted_sp) trusted_sp;
} saml_glob_context_t;

/* saml_glob_context_t flags */
#define SGC_CHECK_ASSERTION_TIMEFRAME	0x1
#define SGC_CHECK_SESSION_TIMEFRAME	0x2
#define SGC_COMPRESSED_ASSERTION	0x4
#define SGC_DEFAULT_FLAGS 		0x3 /* check assertion and session */

typedef struct {
        saml_glob_context_t *glob_context;
        char *userid;
        char *idp;
} saml_serv_context_t;

void saml_log(void *, int, const char *, ...);
void saml_error(void *, int, const char *, ...);
int saml_strdup(void *, const char *, char **, int *);
int saml_retcode(int);

int saml_check_all_assertions(saml_serv_context_t *, 
			      void *, const char **, char *, int);

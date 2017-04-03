/* $Id: pam_saml.c,v 1.5 2009/07/11 17:38:37 manu Exp $ */

/*
 * Copyright (c) 2009 Emmanuel Dreyfus
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
__RCSID("$Id: pam_saml.c,v 1.5 2009/07/11 17:38:37 manu Exp $");
#endif
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <pwd.h>
#include <sys/param.h>
#include <sys/queue.h>

#include <lasso/lasso.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#include "saml.h"

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

void
saml_log(void *param, int pri, const char *fmt, ...)
{
	va_list ap;
	
	va_start(ap, fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
}

void
saml_error(void *param, int pri, const char *fmt, ...)
{
	va_list ap;
	
	if (pri == 0)
		pri = LOG_ERR;

	va_start(ap, fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
}

int
saml_strdup(params, src, dst, len)
	void *params;
	const char *src;
	char **dst;
	int *len;
{
	*dst = strdup(src);
	if (*dst == NULL)
		return -1;
	
	if (len != NULL)
		*len = strlen(*dst);

	return 0;
}

int
saml_retcode(code)
	int code;
{
	int retcode;

	switch(code) {
	case 0:
		retcode = PAM_SUCCESS;
		break;
	case EINVAL:
		retcode = PAM_CRED_ERR;
		break;
	case EACCES:
		retcode = PAM_AUTH_ERR;
		break;
	case ENOMEM:
	default:
		retcode = PAM_SYSTEM_ERR;
		break;
	}

	return retcode;
}


static saml_glob_context_t *gctx = NULL;

static int
pam_global_context_init(ac, av)
	int ac;
	const char **av;
{
	int error;
	int i;
	const char *cacert = NULL;
	const char *uid_attr = "uid";

	if (gctx != NULL)
		return PAM_SUCCESS;

	if ((gctx = malloc(sizeof(*gctx))) == NULL) {
		syslog(LOG_ERR, "malloc() failed: %s", strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	memset(gctx, 0, sizeof(*gctx));

	/*
	 * Initialize lasso
	 */
	if (lasso_init() != 0) {
		syslog(LOG_ERR, "lasso_init() failed");
		return PAM_SYSTEM_ERR;
	}

	SLIST_INIT(&gctx->trusted_sp);
	gctx->grace = (time_t)600;
	gctx->lasso_server = lasso_server_new_from_buffers(NULL, NULL, 
							  NULL, NULL);
	if (gctx->lasso_server == NULL) {
		syslog(LOG_ERR, "lasso_server_new_from_buffers() failed");
		error =  PAM_SYSTEM_ERR;
		goto cleanup;
	}

	/*
	 * Get options 
	 */
#define SETARG(argv,prop) 					\
	(strncmp((argv), (prop "="), strlen(prop "=")) == 0) ? 	\
	(argv) + strlen(prop "=") : NULL

	for (i = 0; i < ac; i++) {
		const char *data;

		if ((data = SETARG(av[i], "userid")) != NULL) {
			uid_attr = data;
			continue;
		}

		if ((data = SETARG(av[i], "grace")) != NULL) {
			gctx->grace = atoi(data);
			continue;
		}

		if ((data = SETARG(av[i], "trusted_sp")) != NULL) {
			struct saml_trusted_sp *item;

			if ((item = malloc(sizeof(*item))) == NULL) {
				syslog(LOG_ERR,
				       "malloc() failed: %s", strerror(errno));
				error = PAM_SYSTEM_ERR;
				goto cleanup;
			}

			SLIST_INSERT_HEAD(&gctx->trusted_sp, item, next);

			if ((item->provider_id = strdup(data)) == NULL) {
				syslog(LOG_ERR,
				       "strdup() failed: %s", strerror(errno));
				error = PAM_SYSTEM_ERR;
				goto cleanup;
			}

			continue;
		}

		if ((cacert = SETARG(av[i], "cacert")) != NULL) {
			if (access(cacert, R_OK) != 0) {
				syslog(LOG_ERR,
				       "Unable to read CA bundle \"%s\"",
				       cacert);
				error = PAM_SYSTEM_ERR;
				goto cleanup;
			}
			continue;
		}
	}

	for (i = 0; i < ac; i++) {
		const char *idp;

		if ((idp = SETARG(av[i], "idp")) == NULL) 
			continue;

		if (access(idp, R_OK) != 0) {
			syslog(LOG_ERR,
			       "Unable to read IdP metadata file \"%s\"", 
			       idp);
			error = PAM_SYSTEM_ERR;
			goto cleanup;
		}

		if (lasso_server_add_provider(gctx->lasso_server,
					      LASSO_PROVIDER_ROLE_IDP,
					      idp, NULL, cacert) != 0) {
			syslog(LOG_ERR,
			       "Failed to load metadata from \"%s\"", idp);
			error = PAM_SYSTEM_ERR;
			goto cleanup;
		}

		syslog(LOG_DEBUG, "Loaded metadata from \"%s\"", idp);
	}

	if ((gctx->uid_attr = strdup(uid_attr)) == NULL) {
		syslog(LOG_ERR, "strdup failed: %s", strerror(errno));
		goto cleanup;
	}

	return PAM_SUCCESS;

cleanup:
	if (gctx != NULL) {
		struct saml_trusted_sp *item;

		if (gctx->uid_attr != NULL) {
			free((void *)gctx->uid_attr);
			gctx->uid_attr = NULL;
		}

		while ((item = SLIST_FIRST(&gctx->trusted_sp)) != NULL) {
			SLIST_REMOVE_HEAD(&gctx->trusted_sp, next);
			free(item);
		}

		if (gctx->lasso_server != NULL) {
			lasso_server_destroy(gctx->lasso_server);
			gctx->lasso_server = NULL;
		}

		lasso_shutdown();
		free(gctx);
		gctx = NULL;
	}
	
	return error;	
}

PAM_EXTERN int
pam_sm_authenticate(pamh, flags, ac, av)
	pam_handle_t *pamh;
	int flags;
	int ac;
	const char **av;
{
	saml_serv_context_t ctx;
	struct passwd *pwd;
	struct passwd pwres;
	char pwbuf[1024];
	const char *user;
	const char *host;
	const char *saml_user;
	char *saml_msg;
	int error;

	/* Check host, and skip SAML check if it is listed  */
	if (pam_get_item(pamh, PAM_RHOST, 
			 (const void **)&host) == PAM_SUCCESS) {
		int i;

		for (i = 0; i < ac; i++) {
			const char *from = "only_from=";
			const char *list;
			char *last;
			char *p;

			if (strncmp(av[i], from, strlen(from)) != 0)
				continue;

			/* 
			 * We found a list of hosts for which SAML 
			 * check must be available
			 */
			list = av[i] + strlen(from);

			for ((p = strtok_r((char *)list, ",", &last));
			     (p != NULL);
			     (p = strtok_r(NULL, ",", &last)))
				if (strcmp(p, host) == 0)
					break;

			/* 
			 * Remote host is not in the list, 
			 * no SAML check performed.
			 */
			if (p == NULL)
				return PAM_IGNORE;
		}
	}

	/* identify user */
	if ((error = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_get_user() failed: %s", 
		       pam_strerror(pamh, error));
		return error;
	}

	if (getpwnam_r(user, &pwres, pwbuf, sizeof(pwbuf), &pwd) != 0) {
		syslog(LOG_ERR, "getpwnam_r(%s) failed: %s", 
		       user, strerror(errno));
		return PAM_TRY_AGAIN;
	}

	if (pwd == NULL)
		syslog(LOG_WARNING, "inexistant user %s", user);

	if ((error = pam_get_item(pamh, PAM_AUTHTOK, 
				  (const void **)&saml_msg)) != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_get_item(PAM_AUTHTOK) failed: %s",
		       pam_strerror(pamh, error));
		return error;
	}

	if (saml_msg == NULL) {
		struct pam_message msg;
		struct pam_message *msgp;
		struct pam_response *resp;
		struct pam_conv *conv;

		if ((error = pam_get_item(pamh, PAM_CONV, 
		    (const void **) &conv)) != PAM_SUCCESS) {
			syslog(LOG_ERR, "pam_get_item(PAM_CONV) failed: %s",
			       pam_strerror(pamh, error));
			return error;
		}

		msg.msg_style = PAM_PROMPT_ECHO_OFF;
		msg.msg = "SAML message: ";
		msgp = &msg;
		resp = NULL;
		if ((error = conv->conv(1, (const struct pam_message **)&msgp, 
		    &resp, conv->appdata_ptr)) != PAM_SUCCESS) {
			syslog(LOG_ERR, "PAM conv error: %s",
			       pam_strerror(pamh, error));
			return error;
		}
			
		if (resp == NULL) 
			return PAM_CONV_ERR;

		saml_msg = resp[0].resp;
		resp[0].resp = NULL;
		free(resp);
		pam_set_item(pamh, PAM_AUTHTOK, saml_msg);
	}

	/* Is it big enough to make sense? */
	if (strlen(saml_msg) < SAML_MINLEN)
		return PAM_AUTH_ERR;

	/* We are now committed to check the SAML assertion */
	if ((error = pam_global_context_init(ac, av)) != PAM_SUCCESS)
		return error;

	memset(&ctx, 0, sizeof(ctx));
	ctx.glob_context = gctx;
	error = saml_check_all_assertions(&ctx, NULL, 
					  &saml_user, saml_msg,
					  MAYBE_COMPRESS);

	if ((error != 0) || (saml_user == NULL)) {
		error = PAM_AUTH_ERR;
		goto out;
	}

	if (strcmp(user, saml_user) != 0) {
		error = PAM_AUTH_ERR;
		syslog(LOG_INFO, "saml assertion user \"%s\", "
				 "requested user \"%s\"", saml_user, user);
		goto out;
	}

#if 0
	if ((error = pam_set_item(pamh, PAM_USER, user)) != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_set_item(PAM_USER) failed: %s",
		       pam_strerror(pamh, error));
		goto out;
	}
#endif

	error = PAM_SUCCESS;
out:
	if (ctx.userid != NULL)
		free(ctx.userid);
		
	if (ctx.idp != NULL)
		free(ctx.idp);
		
	return error;
}

/* ARGSUSED0 */
PAM_EXTERN int
pam_sm_setcred(pamh, flags, ac, av)
	pam_handle_t *pamh;
	int flags;
	int ac;
	const char **av;
{ 
	return PAM_SUCCESS; 
}

/* ARGSUSED0 */
PAM_EXTERN int
pam_sm_acct_mgmt(pamh, flags, ac, av)
	pam_handle_t *pamh;
	int flags;
	int ac;
	const char **av;
{ 
	return PAM_SUCCESS; 
}

/* ARGSUSED0 */
PAM_EXTERN int
pam_sm_open_session(pamh, flags, ac, av)
	pam_handle_t *pamh;
	int flags;
	int ac;
	const char **av;
{ 
	return PAM_SUCCESS; 
}

/* ARGSUSED0 */
PAM_EXTERN int
pam_sm_close_session(pamh, flags, ac, av)
	pam_handle_t *pamh;
	int flags;
	int ac;
	const char **av;
{ 
	return PAM_SUCCESS; 
}

/* ARGSUSED0 */
PAM_EXTERN int
pam_sm_chauthtok(pamh, flags, ac, av)
	pam_handle_t *pamh;
	int flags;
	int ac;
	const char **av;
{ 
	return PAM_SUCCESS; 
}

#ifdef PAM_STATIC
struct pam_module _modstruct = {
	"pam_saml",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok
};
#endif /* PAM_STATIC */

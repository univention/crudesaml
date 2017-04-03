/* $Id: cy2_saml.c,v 1.9 2012/11/07 16:21:52 manu Exp $ */

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

#include "config.h"
 
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id: cy2_saml.c,v 1.9 2012/11/07 16:21:52 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <sasl/sasl.h>
#include <sasl/saslplug.h>
#include <sasl/saslutil.h>

#include <lasso/lasso.h>

#include "saml.h"

#include "plugin_common.h"


typedef struct {
	char *out;
	unsigned int len;
} saml_client_context;

static saml_glob_context_t server_glob_context;

void
saml_log(void *params, int pri, const char *fmt, ...)
{      
	sasl_server_params_t *sasl_params;
	va_list ap;

	sasl_params = (sasl_server_params_t *)params;
	switch (pri) {
	case LOG_DEBUG:
		pri = SASL_LOG_DEBUG;
		break;
	case LOG_NOTICE:
		pri = SASL_LOG_NOTE;
		break;
	default:
		pri = SASL_LOG_ERR;
		break;
	}

	va_start(ap, fmt);
	sasl_params->utils->log(sasl_params->utils->conn, 
				pri, fmt, va_arg(ap, char *));
	va_end(ap);
}      

void
saml_error(void *params, int pri, const char *fmt, ...)
{      
	sasl_server_params_t *sasl_params;
	va_list ap;

	sasl_params = (sasl_server_params_t *)params;

	va_start(ap, fmt);
	sasl_params->utils->seterror(sasl_params->utils->conn, 
				     0, fmt, va_arg(ap, char *));
	va_end(ap);
}      

int
saml_strdup(params, src, dst, len)
	void *params;
	const char *src;
	char **dst;
	int *len;
{
	sasl_server_params_t *sasl_params;

	sasl_params = (sasl_server_params_t *)params;
	return _plug_strdup(sasl_params->utils, src, dst, len);
}

int
saml_retcode(code)
	int code;
{
	int retcode;

	switch(code) {
	case 0:
		retcode = SASL_OK;
		break;
	case EINVAL:
		retcode = SASL_BADPARAM;
		break;
	case EACCES:
		retcode = SASL_BADAUTH;
		break;
	case ENOMEM:
	default:
		retcode = SASL_FAIL;
		break;
	}

	return retcode;
}

static int
saml_server_mech_new(glob_context, params, challenge, challen, conn_context)
	void *glob_context;
	sasl_server_params_t *params;
	const char *challenge;
	unsigned int challen;
	void **conn_context;
{
	saml_serv_context_t *ctx;

	if (conn_context == NULL) {
		params->utils->seterror(params->utils->conn, 0, 
				 	"NULL conn_context");
        	return SASL_BADPARAM;
	}
 
	if ((ctx = params->utils->malloc(sizeof(*ctx))) == NULL) {
		params->utils->seterror(params->utils->conn, 0, 
				 	"out of memory");
        	return SASL_NOMEM;
	}	

	ctx->glob_context = glob_context;
	ctx->userid = NULL;
	ctx->idp = NULL;
	*conn_context = ctx;

	return SASL_OK;
}
 
static int
saml_server_mech_step(conn_context, params, clientin, clientinlen, 
		      serverout, serveroutlen, oparams)
	void *conn_context;
	sasl_server_params_t *params;
	const char *clientin;
	unsigned int clientinlen;
	const char **serverout;
	unsigned int *serveroutlen;
	sasl_out_params_t *oparams;
{
	saml_serv_context_t *ctx = (saml_serv_context_t *)conn_context;
	saml_glob_context_t *gctx;
	const char *authen;
	const char *userid;
	const char *saml_msg_ptr;
	char *saml_msg = NULL;
	unsigned int saml_len;
	unsigned int lup = 0;
	int flags; 
	int error;

	/* Sanity checks */
	if ((ctx == NULL) ||
	    (params == NULL) ||
	    (params->utils == NULL) ||
	    (params->utils->conn == NULL) ||
	    (params->utils->getcallback == NULL) ||
	    (serverout == NULL) ||
	    (serveroutlen == NULL) ||
	    (oparams == NULL)) {
		params->utils->seterror(params->utils->conn, 0, 
				        "Bad parameters");
		return SASL_BADPARAM;
	}

	gctx = ctx->glob_context;

	/* Limit */
	if (clientinlen > 65536) {
		params->utils->seterror(params->utils->conn, 0, 
				        "client data too big (%d)",
					clientinlen);
		return SASL_BADPROT;
	}


	*serverout = NULL;
	*serveroutlen = 0;

	authen = clientin;
	while ((lup < clientinlen) && (clientin[lup] != 0)) ++lup;
	if (lup >= clientinlen) {
		params->utils->seterror(params->utils->conn, 0, 
				        "Found only authen");
		return SASL_BADPROT;
	}	
        
	lup++;
	saml_msg_ptr = clientin + lup;
	while ((lup < clientinlen) && (clientin[lup] != 0)) ++lup;
	saml_len = (unsigned int)(clientin + lup - saml_msg_ptr);
	if (lup != clientinlen) {
		params->utils->seterror(params->utils->conn, 0, 
				        "Unexpected data (%d vs %d)",
					lup, clientinlen);
		return SASL_BADPROT;
	}

	/*
	 * Make sure it is NULL-terminated
	 */
	if ((saml_msg = params->utils->malloc(saml_len + 1)) == NULL) {
		params->utils->seterror(params->utils->conn, 0, 
				        "Out of memory (%d bytes)", 
					saml_len + 1);
		return SASL_NOMEM;
	}
	memcpy(saml_msg, saml_msg_ptr, saml_len);
	saml_msg[saml_len] = '\0';

	/*
	 * Validate SAML assertion, retreive authid
	 */
        flags = (gctx->flags & SGC_COMPRESSED_ASSERTION) ? MAYBE_COMPRESS : 0;
	if ((error = saml_check_all_assertions(ctx, params, 
	    &userid, saml_msg, flags)) != SASL_OK)
		goto out;

	if (userid == NULL) {
		params->utils->seterror(params->utils->conn, 
					0, "No userid found");
		error = SASL_NOAUTHZ;
		goto out;
	}

	/* Canonicalize Userid if we have one */
	if ((authen != NULL) && (*authen != '\0')) {
		if ((error = params->canon_user(params->utils->conn, 
		    authen, 0, SASL_CU_AUTHZID, oparams)) != SASL_OK) 
			goto out;
		if ((error = params->canon_user(params->utils->conn, userid, 0,
		    SASL_CU_AUTHID, oparams)) != SASL_OK) 
			goto out;
	} else {
		if ((error = params->canon_user(params->utils->conn, userid, 0,
		    SASL_CU_AUTHID|SASL_CU_AUTHZID, oparams)) != SASL_OK) 
			goto out;
	}
	
	oparams->doneflag = 1;
	oparams->mech_ssf = 0;
	oparams->maxoutbuf = 0;
	oparams->encode_context = NULL;
	oparams->encode = NULL;
	oparams->decode_context = NULL;
	oparams->decode = NULL;
	oparams->param_version = 0;
	
out:
	if (saml_msg != NULL) {
		params->utils->erasebuffer(saml_msg, strlen(saml_msg));
		params->utils->free(saml_msg);
		return error;
	}

	return SASL_OK;
}

static void
saml_server_mech_dispose(conn_context, utils)
	void *conn_context;
	const sasl_utils_t *utils;
{
	saml_serv_context_t *ctx = (saml_serv_context_t *)conn_context;

	if (ctx != NULL) {
		if (ctx->userid != NULL)
			utils->free(ctx->userid);

		if (ctx->idp != NULL)
			utils->free(ctx->idp);

		utils->free(ctx);
	}

	return;
}

static void
saml_server_mech_free(glob_context, utils)
	void *glob_context;
	const sasl_utils_t *utils;
{
	struct saml_trusted_sp *item;
	saml_glob_context_t *gctx;

	gctx = (saml_glob_context_t *)glob_context;

	/* 
	 * Do not free gctx->uid_attr, it is static 
	 */

	while ((item = SLIST_FIRST(&gctx->trusted_sp)) != NULL) {
		SLIST_REMOVE_HEAD(&gctx->trusted_sp, next);
		free(item);
	}

	if (gctx->lasso_server != NULL) {
		lasso_server_destroy(gctx->lasso_server);
		gctx->lasso_server = NULL;
	}

	lasso_shutdown();

	/* 
	 * Do not free (saml_glob_context_t *)glob_context, it is static!
	 */

	return;
}


static sasl_server_plug_t saml_server_plugin = {
	"SAML",			/* mech_name */
	0,			/* max_ssf */
	SASL_SEC_NOANONYMOUS,	/* security_flags */
	SASL_FEAT_WANT_CLIENT_FIRST |
	SASL_FEAT_ALLOWS_PROXY, /* features */
	&server_glob_context,	/* glob_context */		
	&saml_server_mech_new,	/* mech_new */
	&saml_server_mech_step, /* mech_step */
	&saml_server_mech_dispose,/* mech_dispose */
	&saml_server_mech_free,	/* mech_free */
	NULL,			/* setpass */
	NULL,			/* user_query */
	NULL,			/* idle */
	NULL,			/* mech_avail */
	NULL			/* spare */
};

int
sasl_server_plug_init(utils, maxvers, outvers, pluglist, plugcount)
	const sasl_utils_t *utils;
	int maxvers;
	int *outvers;
	sasl_server_plug_t **pluglist;
	int *plugcount;
{
	saml_glob_context_t *gctx;
	const char *cacert;
	const char *idp;
	const char *grace;
	const char *flag;
	char propname[1024];
	int propnum = 0;

	if (maxvers < SASL_SERVER_PLUG_VERSION) {
		utils->seterror(utils->conn, 0, "SAML version mismatch");
		return SASL_BADVERS;
	}	

	*outvers = SASL_SERVER_PLUG_VERSION;
	*pluglist = &saml_server_plugin;
	*plugcount = 1;

	if (lasso_init() != 0) {
		utils->seterror(utils->conn, 0, "lasso_init() failed");
		return SASL_FAIL;
	}

	gctx = (saml_glob_context_t *)saml_server_plugin.glob_context;

	gctx->flags = SGC_DEFAULT_FLAGS;

	gctx->lasso_server = lasso_server_new_from_buffers(NULL, NULL, 
							   NULL, NULL);
	if (gctx->lasso_server == NULL) {
		utils->seterror(utils->conn, 0, 
			        "lasso_server_new failed");
		return SASL_FAIL;
	}

	/*
	 * Shall we attempt to uncompress assertion?
	 */
	if (((utils->getopt(utils->getopt_context, "SAML", 
	    		    "saml_compressed_assertion", 
			    &flag, NULL)) == 0) &&
	     (flag != NULL) && (*flag != '\0')) {
		if (atoi(flag))
			gctx->flags |= SGC_COMPRESSED_ASSERTION;
		else
			gctx->flags &= ~SGC_COMPRESSED_ASSERTION;
	}

	/*
	 * Attribute to be used for userid
	 */
	if (((utils->getopt(utils->getopt_context, "SAML", 
	    		    "saml_userid", &gctx->uid_attr, NULL)) != 0) || 
	     (gctx->uid_attr == NULL) || (*gctx->uid_attr == '\0'))
		gctx->uid_attr = "uid"; 

	/*
	 * Grace delay for clock skews
	 */
	if (((utils->getopt(utils->getopt_context, "SAML", 
	    		    "saml_grace", &grace, NULL)) != 0) ||
	     (grace == NULL) ||
	     (*grace == '\0'))
		gctx->grace = (time_t)600;
	else
		gctx->grace = atoi(grace);

	/*
	 * Validation options
	 */
	if (((utils->getopt(utils->getopt_context, "SAML", 
	    		    "saml_check_assertion_timeframe", 
			    &flag, NULL)) == 0) &&
	     (flag != NULL) && (*flag != '\0')) {
		if (atoi(flag))
			gctx->flags |= SGC_CHECK_ASSERTION_TIMEFRAME;
		else
			gctx->flags &= ~SGC_CHECK_ASSERTION_TIMEFRAME;
	}

	if (((utils->getopt(utils->getopt_context, "SAML", 
	    		    "saml_check_session_timeframe", 
			    &flag, NULL)) == 0) &&
	     (flag != NULL) && (*flag != '\0')) {
		if (atoi(flag))
			gctx->flags |= SGC_CHECK_SESSION_TIMEFRAME;
		else
			gctx->flags &= ~SGC_CHECK_SESSION_TIMEFRAME;
	}
		

	/*
	 * Path to the CA bundle
	 */
	(void)utils->getopt(utils->getopt_context, "SAML", 
	    		    "saml_cacert", &cacert, NULL);
	if ((cacert != NULL) && (access(cacert, R_OK) != 0)) {
		utils->log(NULL, SASL_LOG_ERR,
			   "Unable to read CA bundle \"%s\"", cacert); 
		return SASL_FAIL;
	}

	/*
	 * Load the trusted SP Id
	 */
	propnum = 0;
	SLIST_INIT(&gctx->trusted_sp);
	do {
		const char *trusted_sp;
		struct saml_trusted_sp *item;

		(void)snprintf(propname, sizeof(propname), 
			       "saml_trusted_sp%d", propnum);
		propnum++;
		
		if (utils->getopt(utils->getopt_context, "SAML", 
				  propname, &trusted_sp, NULL) != 0) 
			break;

		if ((item = utils->malloc(sizeof(*item))) == NULL) {
			utils->seterror(utils->conn, 0, 
				        "cannot allocate memory");
			return SASL_NOMEM;
		}
		
		item->provider_id = trusted_sp;
		SLIST_INSERT_HEAD(&gctx->trusted_sp, item, next);
	} while (1 /*CONSTCOND*/);

	/* 
	 * Load the IdP metadata files
	 */
	propnum = 0;
	do {
		(void)snprintf(propname, sizeof(propname), 
			       "saml_idp%d", propnum);
		propnum++;
	
		if (utils->getopt(utils->getopt_context, "SAML", 
				  propname, &idp, NULL) != 0) 
			break;
		
		if ((idp == NULL) || (*idp == '\0'))
			continue;

		if (access(idp, R_OK) != 0) {
			utils->log(NULL, SASL_LOG_ERR,
				   "Unable to read IdP metadata file \"%s\"",
				   idp); 
			continue;
		}

		if (lasso_server_add_provider(gctx->lasso_server, 
					      LASSO_PROVIDER_ROLE_IDP,
					      idp, NULL, cacert) != 0) {
			utils->log(NULL, SASL_LOG_ERR,
				   "Failed to load metadata from \"%s\"", idp);
			continue;
		}

		utils->log(NULL, SASL_LOG_NOTE, 
			   "Loaded metadata from \"%s\"", idp);
	} while (1 /*CONSTCOND*/);

	return SASL_OK;
}


static int
saml_client_mech_new(glob_context, params, conn_context)
	void *glob_context;
	sasl_client_params_t *params;
	void **conn_context;
{
	saml_client_context *text;

	if ((text = params->utils->malloc(sizeof(*text))) == NULL) {
		params->utils->seterror(params->utils->conn, 0, 
				        "cannot allocate client context");
		return SASL_NOMEM;
	}

	memset(text, 0, sizeof(*text));
	*conn_context = text;
	
	return SASL_OK;	
}

static int
saml_client_mech_step(conn_context, params, serverin, serverinlen, 
		      prompt_need, clientout, clientoutlen, oparams)
	void *conn_context;
	sasl_client_params_t *params;
	const char *serverin;
	unsigned serverinlen;
	sasl_interact_t **prompt_need;
	const char **clientout;
	unsigned *clientoutlen;
	sasl_out_params_t *oparams;
{
	saml_client_context *text = (saml_client_context *)conn_context;
	const char *user = NULL;
	sasl_secret_t *saml_msg = NULL;
	unsigned int free_saml_msg = 0;
	int user_result = SASL_OK;
	int pass_result = SASL_OK;
	int result;
	char *cp;

	/* Sanity checks */
	if ((params == NULL) ||
	    (params->utils == NULL) ||
	    (params->utils->conn == NULL) ||
	    (params->utils->getcallback == NULL) ||
	    (clientout == NULL) ||
	    (clientoutlen == NULL) ||
	    (oparams == NULL)) {
		params->utils->seterror(params->utils->conn,
					0, "Bad parameters");
		return SASL_BADPARAM;
	}

	if (serverinlen != 0) {
		params->utils->seterror(params->utils->conn,
					0, "Bad protocol");
		return SASL_BADPROT;
	}

	*clientout = NULL;
	*clientoutlen = 0;

	if (params->props.min_ssf > params->external_ssf) {
		params->utils->seterror(params->utils->conn, 0, 
				        "SSF too weak for SAML plugin");
		return SASL_TOOWEAK;
	}

	/* Try to get user */
	user_result = _plug_get_simple(params->utils, SASL_CB_USER, 
				       0, &user, prompt_need);
	if ((user_result != SASL_OK) && (user_result != SASL_INTERACT))
		return user_result;

	/* Try to get SAML assertion */
	pass_result = _plug_get_password(params->utils, &saml_msg,
				         &free_saml_msg, prompt_need);
	if ((pass_result != SASL_OK) && (pass_result != SASL_INTERACT))
		return user_result;

	/* free prompts we got */
	if (prompt_need && *prompt_need) {
		params->utils->free(*prompt_need);
		*prompt_need = NULL;
	}

	if ((user_result == SASL_INTERACT) || 
	    (pass_result == SASL_INTERACT)) {
		/* make the prompt list */
		result = _plug_make_prompts(params->utils, prompt_need,
			user_result == SASL_INTERACT ?
			"Please enter your authorization name" :
			NULL, NULL,
			NULL, NULL,
			pass_result == SASL_INTERACT ?
			"Please enter base64 encoded SAML assertion" : NULL, 
			NULL,
			NULL, NULL, NULL, NULL, NULL, NULL);

		if (result != SASL_OK)
			goto out;

		return SASL_INTERACT;
	}

	if (saml_msg == NULL) {
		params->utils->seterror(params->utils->conn, 0, 
					"Bad parameter (no SAML message)");
		return SASL_BADPARAM;
	}

	/* Placeholder for later */
	if ((result = params->canon_user(params->utils->conn, "anonymous", 0,
				         SASL_CU_AUTHID, oparams)) != SASL_OK)
			goto out;

	if (user != NULL && *user != '\0') {
		result = params->canon_user(params->utils->conn, user, 
					    0, SASL_CU_AUTHZID, oparams);
	} else {
		result = params->canon_user(params->utils->conn, "anonymous",
					    0, SASL_CU_AUTHZID, oparams);
	}

	if (result != SASL_OK)	
		goto out;

	/* send authorized id NUL password */
	*clientoutlen = ((user && *user ? strlen(user) : 0) +
			1 + saml_msg->len);

	/* remember the extra NUL on the end for stupid clients */
	result = _plug_buf_alloc(params->utils, &(text->out),
				 &(text->len), *clientoutlen + 1);
	if (result != SASL_OK)
		goto out;

	memset(text->out, 0, *clientoutlen + 1);
	cp = text->out;
	if (user != NULL && *user != '\0') {
		size_t len;
		
		len = strlen(user);
		memcpy(cp, user, len);
		cp += len;
	}
	memcpy(++cp, saml_msg->data, saml_msg->len);

	*clientout = text->out;

	/* set oparams */
	oparams->doneflag = 1;
	oparams->mech_ssf = 0;
	oparams->maxoutbuf = 0;
	oparams->encode_context = NULL;
	oparams->encode = NULL;
	oparams->decode_context = NULL;
	oparams->decode = NULL;
	oparams->param_version = 0;
	
	result = SASL_OK; 
out:
	if (free_saml_msg)
		_plug_free_secret(params->utils, &saml_msg);

	return result;
}

static void
saml_client_mech_dispose(conn_context, utils)
	void *conn_context;
	const sasl_utils_t *utils;
{
	saml_client_context *text = (saml_client_context *)conn_context;

	if (text == NULL)
		return;

	if (text->out != NULL)
		utils->free(text->out);
	utils->free(text);
}

static sasl_client_plug_t saml_client_plugin = {
	"SAML",			/* mech_name */
	0,			/* max_ssf */
	SASL_SEC_NOANONYMOUS,	/* security_flags */
	SASL_FEAT_WANT_CLIENT_FIRST |
	SASL_FEAT_ALLOWS_PROXY, /* features */
	NULL,			/* required_prompts */
	NULL,			/* glob_context */		
	&saml_client_mech_new,	/* mech_new */
	&saml_client_mech_step, /* mech_step */
	&saml_client_mech_dispose,/* mech_dispose */
	NULL,			/* mech_free */
	NULL,			/* idle */
	NULL,			/* spare */
	NULL			/* spare */
};

int
sasl_client_plug_init(utils, maxvers, outvers, pluglist, plugcount)
	const sasl_utils_t *utils;
	int maxvers;
	int *outvers;
	sasl_client_plug_t **pluglist;
	int *plugcount;
{
	if (maxvers < SASL_CLIENT_PLUG_VERSION) {
		utils->seterror(utils->conn, 0, "SAML version mismatch");
		return SASL_BADVERS;
	}	

	*outvers = SASL_CLIENT_PLUG_VERSION;
	*pluglist = &saml_client_plugin;
	*plugcount = 1;

	return SASL_OK;
}


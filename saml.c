/* $Id: saml.c,v 1.12 2013/11/27 16:21:22 manu Exp $ */

/*
 * Copyright (c) 2009-2010 Emmanuel Dreyfus
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
__RCSID("$Id: saml.c,v 1.12 2013/11/27 16:21:22 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <syslog.h>
#include <errno.h>
#include <zlib.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <time.h>

#include <sasl/saslutil.h>	/* XXX for sasl_decode64 */

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <lasso/lasso.h>
#include <lasso/xml/saml-2.0/saml2_assertion.h>
#include <lasso/xml/saml-2.0/saml2_name_id.h>
#include <lasso/xml/saml-2.0/saml2_authn_statement.h>
#include <lasso/xml/saml-2.0/saml2_audience_restriction.h>
#include <lasso/xml/saml-2.0/saml2_attribute_statement.h>
#include <lasso/xml/saml-2.0/saml2_attribute.h>
#include <lasso/xml/saml-2.0/saml2_attribute_value.h>
#include <lasso/xml/misc_text_node.h>

#include "saml.h"

static int
saml_check_assertion_uid(ctx, params, lasso_assertion)
	saml_serv_context_t *ctx;
	void *params;
	LassoSaml2Assertion *lasso_assertion;
{
	saml_glob_context_t *gctx = ctx->glob_context;
	GList *i;
	char *found = NULL;
	int error;

	for (i = g_list_first(lasso_assertion->AttributeStatement);
	     i != NULL;
	     i = g_list_next(i)) {
		GList *j;
		LassoSaml2AttributeStatement *attribute_statement;
		
		attribute_statement = LASSO_SAML2_ATTRIBUTE_STATEMENT(i->data);
		if (attribute_statement == NULL)
			continue;

		for (j = g_list_first(attribute_statement->Attribute);
		     j != NULL;
		     j = g_list_next(j)) {
			GList *k;
			LassoSaml2Attribute *attribute;

			attribute = LASSO_SAML2_ATTRIBUTE(j->data);
			if (attribute == NULL || attribute->Name == NULL) 
				continue;

			saml_log(params, LOG_DEBUG,
				 "assertion contains %s; searching for %s ",
				 attribute->Name, gctx->uid_attr);
			if (strcmp(attribute->Name, gctx->uid_attr) != 0)
				continue;

			for (k =  g_list_first(attribute->AttributeValue);
			     k != NULL;
			     k = g_list_next(k)) {
				LassoSaml2AttributeValue *value;
				LassoMiscTextNode *text;

				value = LASSO_SAML2_ATTRIBUTE_VALUE(k->data);
				if ((value == NULL) || (value->any == NULL))
					continue;

				/* Assume single text node */
				if(!LASSO_IS_MISC_TEXT_NODE(value->any->data))
					continue;

				text = LASSO_MISC_TEXT_NODE(value->any->data);

				if (text->content == NULL)
					continue;

				found = text->content;
				goto out;
			}
		}
	}
	
out:
	if (found == NULL) {
		saml_error(params, 0,
			   "assertion contains no %s", gctx->uid_attr);
		return EACCES;
	}

	if ((error = saml_strdup(params, found, &ctx->userid, NULL)) != 0) 
		return error;

	return 0;

}

extern char *strptime(const char *s, const char *format, struct tm *tm);

static time_t
saml_get_date(date)
	const char *date;
{
	struct tm tm;
	/*
	 * semik Shibboleth SP &| IDP uses format 2013-11-27T09:28:30.464Z
	 * Melon seems to use 2013-11-27T12:14:46Z .. both hopefully in UTC
	 */
	const char *format = "%Y-%m-%dT%T";

	if (strptime(date, format, &tm) == NULL)
		return (time_t)-1;

	return (timegm(&tm));
}

static int
saml_check_assertion_dates(ctx, params, lasso_assertion)
	saml_serv_context_t *ctx;
	void *params;
	LassoSaml2Assertion *lasso_assertion;
{
	time_t limit, now;
	time_t grace = ctx->glob_context->grace;
	struct tm now_tm;
	char now_str[1024];
	GList *i;

	now = time(NULL);
	(void)gmtime_r(&now, &now_tm);
	(void)strftime(now_str, sizeof(now_str), "%Y-%m-%dT%H:%M:%SZ", &now_tm);

	if (!(ctx->glob_context->flags & SGC_CHECK_ASSERTION_TIMEFRAME))
		goto skip_assertion_timeframe_check;

	if (lasso_assertion->Conditions != NULL) {
		char *not_before = NULL;
		char *not_after = NULL;

		not_before = lasso_assertion->Conditions->NotBefore;
		not_after = lasso_assertion->Conditions->NotOnOrAfter;
		
		if ((not_before != NULL) && (*not_before != '\0')) {
			limit = saml_get_date(not_before);
			saml_log(params, LOG_DEBUG,
				 "SAML assertion condition "
				 "NotBefore = %ld (%s)",
				 limit, not_before);

			if (limit == (time_t)-1) {
				saml_error(params, 0, 
					   "Invalid condition NotBefore %s",
					   not_before);
				return EINVAL;
			}

			if (now < limit - grace) {
				saml_error(params, 0, 
					   "condition NotBefore %s, "
					   "current time is %s",
					   not_before, now_str);
				return EACCES;
			}
		}

		if ((not_after != NULL) && (*not_after != '\0')) {
			limit = saml_get_date(not_after);
			saml_log(params, LOG_DEBUG,
				 "SAML assertion condition "
				 "NotOnOrAfter = %ld (%s)",
				 limit, not_after);

			if (limit == (time_t)-1) {
				saml_error(params, 0, "Invalid condition "
					   "NotOnOrAfter %s", not_after);
				return EINVAL;
			}

			if (now > limit + grace) {
				saml_error(params, 0, 
					   "condition NotOnOrAfter %s, "
					   "current time is %s",
					   not_after, now_str);
				return EACCES;
			}
		}
	}
skip_assertion_timeframe_check:

	if (!(ctx->glob_context->flags & SGC_CHECK_SESSION_TIMEFRAME))
		goto skip_session_timeframe_check;

	for(i = lasso_assertion->AuthnStatement;
	    i != NULL;
	    i = g_list_next(i)) {
		LassoSaml2AuthnStatement *as;
		char *not_before = NULL;
		char *not_after = NULL;

		if (!LASSO_IS_SAML2_AUTHN_STATEMENT(i->data))
			continue;

		as = LASSO_SAML2_AUTHN_STATEMENT(i->data);
		not_before = as->AuthnInstant;
		not_after = as->SessionNotOnOrAfter;

		if ((not_before != NULL) && (*not_before != '\0')) {
			limit = saml_get_date(not_before);
			saml_log(params, LOG_DEBUG,
				 "SAML assertion AuthnStatement "
				 "AuthnInstant = %ld", limit);

			if (limit == (time_t)-1) {
				saml_error(params, 0, 
					   "invalid authn AuthnInstant %s",
					   not_before);
				return EINVAL;
			}

			if (now < limit - grace) {
				saml_error(params, 0, 
					   "authn AuthnInstant %s, "
					   "current time is %s",
					   not_before, now_str);
				return EACCES;
			}
		}

		if ((not_after != NULL) && (*not_after != '\0')) {
			limit = saml_get_date(not_after);
			saml_log(params, LOG_DEBUG,
				 "SAML assertion AuthnStatement "
				 "SessionNotOnOrAfter = %ld", limit);

			if (limit == (time_t)-1) {
				saml_error(params, 0, "invalid authn "
					   "SessionNotOnOrAfter %s",
					   not_after);
				return EINVAL;
			}

			if (now > limit + grace) {
				saml_error(params, 0, 
					   "authn SessionNotOnOrAfter %s, "
					   "current time is %s",
					   not_after, now_str);
				return EACCES;
			}
		}
	}

skip_session_timeframe_check:
	return 0;
}

static int
saml_check_assertion_audience(ctx, params, lasso_assertion)
	saml_serv_context_t *ctx;
	void *params;
	LassoSaml2Assertion *lasso_assertion;
{
	GList *i;

	/* If trusted list is empty, then the check always succeeds */
	if (SLIST_EMPTY(&ctx->glob_context->trusted_sp))
		return 0;

	if (lasso_assertion->Conditions == NULL) {
		saml_error(params, 0, "No conditions in assertion");
		return EACCES;
	}

	if (lasso_assertion->Conditions->AudienceRestriction == NULL) {
		saml_error(params, 0, "No AudienceRestriction in assertion");
		return EACCES;
	}

	for(i = lasso_assertion->Conditions->AudienceRestriction;
	    i != NULL;
	    i = g_list_next(i)) {
		struct saml_trusted_sp *sp;		
		LassoSaml2AudienceRestriction *ar;

		if (!LASSO_IS_SAML2_AUDIENCE_RESTRICTION(i->data))
			continue;

		ar = LASSO_SAML2_AUDIENCE_RESTRICTION(i->data);

		if (ar->Audience == NULL)
			continue;

		saml_log(params, LOG_DEBUG, 
			 "SAML assertion audience %s",
			 ar->Audience);

		SLIST_FOREACH(sp, &ctx->glob_context->trusted_sp, next) 
			if (strcmp(sp->provider_id, ar->Audience) == 0)
				return 0;

		saml_log(params, LOG_ERR, 
			 "Assertion audience \"%s\" untrusted",
			 ar->Audience);
	}

	saml_error(params, 0, "Untrusted assertion audience");

	return EACCES;
}

static int
saml_check_assertion_signature(ctx, params, node, issuer, doc)
	saml_serv_context_t *ctx;
	void *params;
	xmlNode *node;
	char *issuer;
	xmlDoc *doc;
{
	saml_glob_context_t *gctx = ctx->glob_context;
	LassoProvider *idp;
	int error; 

	if ((idp = g_hash_table_lookup(gctx->lasso_server->providers, 
				       issuer)) == NULL) {
		saml_error(params, 0, 
			   "SAML assertion issuer %s is unknown", issuer);
		return EACCES;
	}

	/*
	 * The assertion may be unsigned, but enclosed into a 
	 * signed <samlp:Response> therefore, we iterate until 
	 * we reach the root, looking for a signature. That will 
	 * not work if the issuer of the <samlp:Response> is not 
	 * the issuer of the <saml:Assertion>
	 */
	do {
		error = lasso_provider_verify_saml_signature(idp, node, doc);
		if (error == 0)
			return 0;

		if (node->parent == NULL)
			break;
		node = node->parent;

	} while ((node != node->parent) && (node != NULL));

	saml_error(params, 0, "SAML assertion signature verification "
		   "failure (error %d)", error);
	return EACCES;
}

static int
saml_check_one_assertion(ctx, params, userid, assertion, doc)
	saml_serv_context_t *ctx;
	void *params;
	const char **userid;
	xmlNodePtr assertion;
	xmlDoc *doc;
{
	LassoNode *lasso_node = NULL;
	LassoSaml2Assertion *lasso_assertion = NULL;
	LassoSaml2NameID *issuer = NULL;
	char *idp = NULL;
	int error;

	if ((lasso_node = lasso_node_new_from_xmlNode(assertion)) == NULL) {
		saml_error(params, 0, "lasso_node_new_from_xmlNode failed");
		error = EINVAL;
		goto out;
	}

	lasso_assertion = LASSO_SAML2_ASSERTION(lasso_node);
	if ((lasso_assertion == NULL) || (lasso_assertion->Issuer == NULL)) {
		saml_error(params, 0, "SAML assertion contains no Issuer");
		error = EINVAL;
		goto out;
	}

	issuer = LASSO_SAML2_NAME_ID(lasso_assertion->Issuer);
	if ((issuer == NULL) || (issuer->content == NULL)) {
		saml_error(params, 0, "SAML assertion contains no Issuer");
		error = EINVAL;
		goto out;
	}
	
	idp = issuer->content;
	saml_log(params, LOG_DEBUG, "SAML assertion issuer is %s", idp);
	
	/* Check signature */
	if ((error = saml_check_assertion_signature(ctx, params, assertion, 
						    idp, doc)) != 0)
		goto out;

	/* Check SP */
	if ((error = saml_check_assertion_audience(ctx, params, 
						   lasso_assertion)) != 0)
		goto out;

	/* Check dates */
	if ((error = saml_check_assertion_dates(ctx, 
						params, lasso_assertion)) != 0)
		goto out;
	
	/* Check uid */
	if ((error = saml_check_assertion_uid(ctx, 
					      params, lasso_assertion)) != 0)
		goto out;
	
	/* Save the IdP */
	if ((error = saml_strdup(params, idp, &ctx->idp, NULL)) != 0) 
		goto out;

	*userid = ctx->userid;
out:
	if (lasso_node != NULL)
		lasso_node_destroy(lasso_node);

	return error;
}

int
saml_check_all_assertions(ctx, params, userid, saml_msg, flags)
	saml_serv_context_t *ctx;
	void *params;
	const char **userid;
	char *saml_msg;
	int flags;
{
        unsigned int len;
	int error;
	unsigned char saml_msg_copy[65536];
	unsigned long dlen;
	xmlDocPtr doc = NULL;
	xmlXPathContextPtr xpctx = NULL;
	xmlXPathObjectPtr xpobj = NULL;
	int i;

	if (saml_msg == NULL) {
		saml_error(params, 0, "No SAML message");
		return saml_retcode(EINVAL);
	}

	/* 
	 * The message must be long enough to hold an assertion 
	 */
	len = strlen(saml_msg);
	if (len < SAML_MINLEN)
		return saml_retcode(EINVAL);

	/*
	 * Remove any trailing cruft (space, newlines)
	 */
	while (len > 0 && !isgraph((int)saml_msg[len - 1]))
		saml_msg[len--] = '\0';

	if (sasl_decode64(saml_msg, len, saml_msg, len, &len) != 0) {
		saml_error(params, 0, "Cannot base64-decode message");
		return saml_retcode(EINVAL);
	}
	saml_msg[len] = '\0';

	/* 
	 * Attempt to decompress it, just in case
	 */
	dlen = sizeof(saml_msg_copy) - 2;
	if ((flags & MAYBE_COMPRESS) &&
	    (uncompress(saml_msg_copy, &dlen, (unsigned char *)saml_msg,
			len + 1) == Z_OK)) {
		saml_msg_copy[dlen] = '\0';
		saml_msg = (char *)saml_msg_copy;
	}
	
	if ((doc = xmlParseDoc((const xmlChar *)saml_msg)) == NULL) {
		saml_error(params, 0, "Cannot parse message");
		error = EINVAL;
		goto out;
	}

	if ((xpctx = xmlXPathNewContext(doc)) == NULL) {
		saml_error(params, 0, "xmlXPathNewContext failed");
		error = ENOMEM;;
		goto out;
	}
	
	if (xmlXPathRegisterNs(xpctx, (const xmlChar *)"saml", 
	   (const xmlChar *)"urn:oasis:names:tc:SAML:2.0:assertion") != 0) {
		saml_error(params, 0, "wxmlXPathRegisterNs failed");
		error = ENOMEM;;
	}

	if ((xpobj = xmlXPathEvalExpression((const xmlChar *)
	    "//saml:Assertion[@ID]", xpctx)) == NULL) {
		saml_error(params, 0, "xmlXPathEvalExpression failed");
		error = EINVAL;
		goto out;
	}

	if (xpobj->nodesetval->nodeNr == 0) {
		saml_error(params, 0, "No assertion found");
		error = EINVAL;
		goto out;
	}

	error = EINVAL;
	for (i = 0; i <  xpobj->nodesetval->nodeNr; i++) {
		xmlNodePtr node;

		node = xpobj->nodesetval->nodeTab[i];		
		error = saml_check_one_assertion(ctx, params, userid, node, doc);
		if (error == 0)
			goto out;
	}

out:
	if (doc != NULL)
		xmlFreeDoc(doc);
	if (xpctx != NULL)
		xmlXPathFreeContext(xpctx);
	if (xpobj != NULL)
		xmlXPathFreeObject(xpobj);
		
	return saml_retcode(error);
}

/* based on mod_mime_magic.c of apache server 2.0 */

/*
 *
Copyright (c) 2010 QUE Hongyu

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

 */

/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * mod_mime_magic: MIME type lookup via file magic numbers
 * Copyright (c) 1996-1997 Cisco Systems, Inc.
 *
 * This software was submitted by Cisco Systems to the Apache Software Foundation in July
 * 1997.  Future revisions and derivatives of this source code must
 * acknowledge Cisco Systems as the original contributor of this module.
 * All other licensing and usage conditions are those of the Apache Software Foundation.
 *
 * Some of this code is derived from the free version of the file command
 * originally posted to comp.sources.unix.  Copyright info for that program
 * is included below as required.
 * ---------------------------------------------------------------------------
 * - Copyright (c) Ian F. Darwin, 1987. Written by Ian F. Darwin.
 *
 * This software is not subject to any license of the American Telephone and
 * Telegraph Company or of the Regents of the University of California.
 *
 * Permission is granted to anyone to use this software for any purpose on any
 * computer system, and to alter it and redistribute it freely, subject to
 * the following restrictions:
 *
 * 1. The author is not responsible for the consequences of use of this
 * software, no matter how awful, even if they arise from flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources, credits
 * must appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 * misrepresented as being the original software.  Since few users ever read
 * sources, credits must appear in the documentation.
 *
 * 4. This notice may not be removed or altered.
 * -------------------------------------------------------------------------
 *
 * For compliance with Mr Darwin's terms: this has been very significantly
 * modified from the free "file" command.
 * - all-in-one file for compilation convenience when moving from one
 *   version of Apache to the next.
 * - Memory allocation is done through the Apache API's apr_pool_t structure.
 * - All functions have had necessary Apache API request or server
 *   structures passed to them where necessary to call other Apache API
 *   routines.  (i.e. usually for logging, files, or memory allocation in
 *   itself or a called function.)
 * - struct magic has been converted from an array to a single-ended linked
 *   list because it only grows one record at a time, it's only accessed
 *   sequentially, and the Apache API has no equivalent of realloc().
 * - Functions have been changed to get their parameters from the server
 *   configuration instead of globals.  (It should be reentrant now but has
 *   not been tested in a threaded environment.)
 * - Places where it used to print results to stdout now saves them in a
 *   list where they're used to set the MIME type in the Apache request
 *   record.
 * - Command-line flags have been removed since they will never be used here.
 *
 * Ian Kluft <ikluft@cisco.com>
 * Engineering Information Framework
 * Central Engineering
 * Cisco Systems, Inc.
 * San Jose, CA, USA
 *
 * Initial installation          July/August 1996
 * Misc bug fixes                May 1997
 * Submission to Apache Software Foundation    July 1997
 *
 */

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "plugin.h"
#include "stat_cache.h"
#include "response.h"

#define CONFIG_MIMEMAGIC_FILE "mimemagic.file"
#define CONFIG_MIMEMAGIC_OVERRIDE_GLOBAL_MIMETYPE "mimemagic.override-global-mimetype"

#define NBYTE           4
#define NSHORT          5
#define NLONG           4
#define NSTRING         6
#define NDATE           4
#define NBESHORT        7
#define NBELONG         6
#define NBEDATE         6
#define NLESHORT        7
#define NLELONG         6
#define NLEDATE         6

/* limits how much work we do to figure out text files */
#define HOWMANY 1024
#define MAXDESC 50   /* max leng of text description */
#define MAXstring 64    /* max leng of "string" types */

struct magic
{
	struct magic *next;     /* link to next entry */
	int lineno;             /* line number from magic file */
	
	short flag;
#define INDIR  1            /* if '>(...)' appears,  */
#define UNSIGNED 2          /* comparison is unsigned */
	short cont_level;       /* level of ">" */
	
	struct
	{
		char type;          /* byte short long */
		long offset;        /* offset from indirection */
	} in;
	
	long offset;            /* offset to magic number */
	unsigned char reln;     /* relation (0=eq, '>'=gt, etc) */
	char type;              /* int, short, long or string. */
	char vallen;            /* length of string value, if any */
#define BYTE      1
#define SHORT     2
#define LONG      4
#define STRING    5
#define DATE      6
#define BESHORT   7
#define BELONG    8
#define BEDATE    9
#define LESHORT  10
#define LELONG   11
#define LEDATE   12
	
	union VALUETYPE
	{
		unsigned char b;
		unsigned short h;
		unsigned long l;
		char s[MAXstring];
		unsigned char hs[2];   /* 2 bytes of a fixed-endian "short" */
		unsigned char hl[4];   /* 2 bytes of a fixed-endian "long" */
	} value;                   /* either number or string */
	
	unsigned long mask;        /* mask before comparison with value */
	char nospflag;             /* supress space character */
	
	/* NOTE: this string is suspected of overrunning - find it! */
	char desc[MAXDESC];        /* description */
};

typedef struct
{
	buffer *magic_file;
	struct magic *magics;
	int override_global_mimetype;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

/* init the plugin data */
static void *
mod_mimemagic_init(void)
{
	plugin_data *p;
	p = calloc(1, sizeof(*p));

	return p;
}

static handler_t
mod_mimemagic_free(server *srv, void *p_d)
{
	plugin_data *p = p_d;
	size_t i;
	struct magic *m;

	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {

		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (!s) continue;

			buffer_free(s->magic_file);
			m = s->magics;

			while(m) {
				s->magics = m->next;
				free(m);
				m = s->magics;
			}

			free(s);
		}
		free(p->config_storage);
	}

	free(p);

	return HANDLER_GO_ON;
}

#define EATAB { while (isspace(*l))  ++l;}

/* Single hex char to int; -1 if not a hex char. */
static int
hextoint(int c)
{
	if (isdigit(c))
	    return c - '0';
	if ((c >= 'a') && (c <= 'f'))
	    return c + 10 - 'a';
	if ((c >= 'A') && (c <= 'F'))
	    return c + 10 - 'A';
	return -1;
}

/*
 * extend the sign bit if the comparison is to be signed
 */
static unsigned long
magic_signextend(struct magic *m, unsigned long v)
{
	if (!(m->flag & UNSIGNED)) {
		switch (m->type) {
			/*
			 * Do not remove the casts below.  They are vital. When later
			 * compared with the data, the sign extension must have happened.
			 */
		case BYTE:
			v = (char) v;
			break;
		case SHORT:
		case BESHORT:
		case LESHORT:
			v = (short) v;
			break;
		case DATE:
		case BEDATE:
		case LEDATE:
		case LONG:
		case BELONG:
		case LELONG:
			v = (long) v;
			break;
		case STRING:
			break;
		default:
			return -1;
		}
	}
	return v;
}

/*
 * Convert a string containing C character escapes.  Stop at an unescaped
 * space or tab. Copy the converted version to "p", returning its length in
 * *slen. Return updated scan pointer as function result.
 */
static char *
magic_getstr(register char *s, register char *p, int plen, int *slen)
{
	char *origp = p;
	char *pmax = p + plen - 1;
	register int c;
	register int val;

	while ((c = *s++) != '\0') {
		if (isspace(c))
			break;
		if (p >= pmax)
			break;

		if (c == '\\') {
			switch (c = *s++) {
			case '\0':
				goto out;

			default:
				*p++ = (char) c;
				break;

			case 'n':
				*p++ = '\n';
				break;

			case 'r':
				*p++ = '\r';
				break;

			case 'b':
				*p++ = '\b';
				break;

			case 't':
				*p++ = '\t';
				break;

			case 'f':
				*p++ = '\f';
				break;

			case 'v':
				*p++ = '\v';
				break;

				/* \ and up to 3 octal digits */
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
				val = c - '0';
				c = *s++;  /* try for 2 */
				if (c >= '0' && c <= '7') {
					val = (val << 3) | (c - '0');
					c = *s++;  /* try for 3 */
					if (c >= '0' && c <= '7')
						val = (val << 3) | (c - '0');
					else
						--s;
				} else {
					--s;
				}
				*p++ = (char) val;
				break;

				/* \x and up to 3 hex digits */
			case 'x':
				val = 'x';			/* Default if no digits */
				c = hextoint(*s++);   /* Get next char */
				if (c >= 0) {
					val = c;
					c = hextoint(*s++);
					if (c >= 0) {
						val = (val << 4) + c;
						c = hextoint(*s++);
						if (c >= 0) {
							val = (val << 4) + c;
						} else {
							--s;
						}
					} else {
						--s;
					}
				} else {
					--s;
				}
				*p++ = (char) val;
				break;
			}
		} else {
			*p++ = (char) c;
		}
	}
  out:
	*p = '\0';
	*slen = p - origp;
	return s;
}

/*
 * Read a numeric value from a pointer, into the value union of a magic
 * pointer, according to the magic type.  Update the string pointer to point
 * just after the number read.  Return 0 for success, non-zero for failure.
 */
static int
magic_getvalue(struct magic *m, char **p)
{
	int slen;

	if (m->type == STRING) {
		*p = magic_getstr(*p, m->value.s, sizeof(m->value.s), &slen);
		m->vallen = slen;
	} else if (m->reln != 'x') {
		m->value.l = magic_signextend(m, strtol(*p, p, 0));
	}
	return 0;
}

/*
 * parse one line from magic file, put into magic[index++] if valid
 */
static struct magic *
magic_parse(char *l, int lineno)
{
	struct magic *m;
	char *t, *s;

	/* allocate magic structure entry */
	m = (struct magic *) calloc(1, sizeof(struct magic));
	if (m == NULL) return NULL;

	/* append to linked list */
	m->next = NULL;

	/* set values in magic structure */
	m->flag = 0;
	m->cont_level = 0;
	m->lineno = lineno;

	while (*l == '>') {
		++l;  /* step over */
		m->cont_level++;
	}

	if (m->cont_level != 0 && *l == '(') {
		++l;  /* step over */
		m->flag |= INDIR;
	}

	/* get offset, then skip over it */
	m->offset = (int) strtol(l, &t, 0);
	if (l == t) {
		/*
	    ap_log_error(APLOG_MARK, APLOG_ERR, 0, serv,
	                MODNAME ": offset %s invalid", l);
			*/
	}
	l = t;

	if (m->flag & INDIR) {
		m->in.type = LONG;
		m->in.offset = 0;
		
		/*
		 * read [.lbs][+-]nnnnn)
		 */
		if (*l == '.') {
			switch (*++l) {
			case 'l':
				m->in.type = LONG;
				break;
			case 's':
				m->in.type = SHORT;
				break;
			case 'b':
				m->in.type = BYTE;
				break;
			default:
				break;
			}
			l++;
		}
		s = l;
		if (*l == '+' || *l == '-')
			l++;
		if (isdigit((unsigned char) *l)) {
			m->in.offset = strtol(l, &t, 0);
			if (*s == '-')
				m->in.offset = -m->in.offset;
		} else {
			t = l;
		}

		l = t;
	}

	while (isdigit((unsigned char) *l))
		++l;
	EATAB;

	if (*l == 'u') {
		++l;
		m->flag |= UNSIGNED;
	}

	/* get type, skip it */
	if (strncmp(l, "byte", NBYTE) == 0) {
		m->type = BYTE;
		l += NBYTE;
	} else if (strncmp(l, "short", NSHORT) == 0) {
		m->type = SHORT;
		l += NSHORT;
	} else if (strncmp(l, "long", NLONG) == 0) {
		m->type = LONG;
		l += NLONG;
	} else if (strncmp(l, "string", NSTRING) == 0) {
		m->type = STRING;
		l += NSTRING;
	} else if (strncmp(l, "date", NDATE) == 0) {
		m->type = DATE;
		l += NDATE;
	} else if (strncmp(l, "beshort", NBESHORT) == 0) {
		m->type = BESHORT;
		l += NBESHORT;
	} else if (strncmp(l, "belong", NBELONG) == 0) {
		m->type = BELONG;
		l += NBELONG;
	} else if (strncmp(l, "bedate", NBEDATE) == 0) {
		m->type = BEDATE;
		l += NBEDATE;
	} else if (strncmp(l, "leshort", NLESHORT) == 0) {
		m->type = LESHORT;
		l += NLESHORT;
	} else if (strncmp(l, "lelong", NLELONG) == 0) {
		m->type = LELONG;
		l += NLELONG;
	} else if (strncmp(l, "ledate", NLEDATE) == 0) {
		m->type = LEDATE;
		l += NLEDATE;
	} else {
		free(m);
		return NULL;
	}

	/* New-style anding: "0 byte&0x80 =0x80 dynamically linked" */
	if (*l == '&') {
		++l;
		m->mask = magic_signextend(m, strtol(l, &l, 0));
	}
	else
		m->mask = ~0L;
	EATAB;

	switch (*l) {
	case '>':
	case '<':
		/* Old-style anding: "0 byte &0x80 dynamically linked" */
	case '&':
	case '^':
	case '=':
		m->reln = *l;
		++l;
		break;
	case '!':
		if (m->type != STRING) {
			m->reln = *l;
			++l;
			break;
		}
		/* FALL THROUGH */
	default:
		if (*l == 'x' && isspace(l[1])) {
			m->reln = *l;
			++l;
			goto GetDesc;  /* Bill The Cat */
		}
		m->reln = '=';
		break;
	}
	EATAB;

	if (magic_getvalue(m, &l)) {
		free(m);
		return NULL;
	}
	/*
	 * now get last part - the description
	 */
  GetDesc:
	EATAB;
	if (l[0] == '\b') {
		++l;
		m->nospflag = 1;
	} else if ((l[0] == '\\') && (l[1] == 'b')) {
		++l;
		++l;
		m->nospflag = 1;
	} else {
		m->nospflag = 0;
	}
	strncpy(m->desc, l, sizeof(m->desc) - 1);
	m->desc[sizeof(m->desc) - 1] = '\0';

	return m;
}

/*
 * apprentice - load configuration from the magic file r
 *  API request record
 */
static struct magic *
magic_apprentice(const char *file)
{
	char line[BUFSIZ + 1];
	int errs = 0;
	int lineno;
	struct magic *tail = NULL, *m, *root = NULL;
	FILE *f;

	if (file == NULL || file[0] == '\0') return NULL;

	f = fopen(file, "rb");
	if (f == NULL) return NULL;

	/* parse it */
	for (lineno = 1; fgets(line, BUFSIZ, f) != NULL; lineno++) {
		int ws_offset;
		char *last = line + strlen(line) - 1; /* guaranteed that len >= 1 since an
	                                           * "empty" line contains a '\n'
	                                           */

		/* delete newline and any other trailing whitespace */
		while (last >= line
			   && isspace(*last)) {
			*last = '\0';
			--last;
		}

		/* skip leading whitespace */
		ws_offset = 0;
		while (line[ws_offset] && isspace(line[ws_offset])) {
			ws_offset++;
		}

		/* skip blank lines */
		if (line[ws_offset] == 0) {
			continue;
		}

		/* comment, do not parse */
		if (line[ws_offset] == '#')
			continue;

		/* parse it */
		m = magic_parse(line + ws_offset, lineno);
		if (m == NULL)
			++errs;
		else {
			m->next = NULL;
			if (root == NULL) {
				root = tail = m;
			} else {
				tail->next = m;
				tail = m;
			}
		}
	}

	fclose(f);

	return root;
}

/*
 * Convert the byte order of the data we are looking at
 */
static int
magic_mconvert(union VALUETYPE *p, struct magic *m)
{
	char *rt;

	switch (m->type) {
	case BYTE:
	case SHORT:
	case LONG:
	case DATE:
		return 1;
	case STRING:
		/* Null terminate and eat the return */
		p->s[sizeof(p->s) - 1] = '\0';
		if ((rt = strchr(p->s, '\n')) != NULL)
			*rt = '\0';
		return 1;
	case BESHORT:
		p->h = (short) ((p->hs[0] << 8) | (p->hs[1]));
		return 1;
	case BELONG:
	case BEDATE:
		p->l = (long)
			((p->hl[0] << 24) | (p->hl[1] << 16) | (p->hl[2] << 8) | (p->hl[3]));
		return 1;
	case LESHORT:
		p->h = (short) ((p->hs[1] << 8) | (p->hs[0]));
		return 1;
	case LELONG:
	case LEDATE:
		p->l = (long)
			((p->hl[3] << 24) | (p->hl[2] << 16) | (p->hl[1] << 8) | (p->hl[0]));
		return 1;
	default:
		return 0;
	}
}

/* return 1 if found */
static int
magic_mget(union VALUETYPE *p, unsigned char *s, struct magic *m, uint32_t nbytes)
{
	long offset = m->offset;

	if (offset + sizeof(union VALUETYPE) > nbytes) return 0;

	memcpy(p, s + offset, sizeof(union VALUETYPE));

	if (!magic_mconvert(p, m)) return 0;

	if (m->flag & INDIR) {
		switch (m->in.type) {
		case BYTE:
			offset = p->b + m->in.offset;
			break;
		case SHORT:
			offset = p->h + m->in.offset;
			break;
		case LONG:
			offset = p->l + m->in.offset;
			break;
		}

		if (offset + sizeof(union VALUETYPE) > nbytes)
					  return 0;

		memcpy(p, s + offset, sizeof(union VALUETYPE));

		if (!magic_mconvert(p, m))
			return 0;
	}
	return 1;
}

/* return 1 if matched */
static int
magic_mcheck(union VALUETYPE *p, struct magic *m)
{
	register unsigned long l = m->value.l;
	register unsigned long v;
	int matched;

	if ((m->value.s[0] == 'x') && (m->value.s[1] == '\0')) {
		return 1;
	}

	switch (m->type) {
	case BYTE:
		v = p->b;
		break;

	case SHORT:
	case BESHORT:
	case LESHORT:
		v = p->h;
		break;

	case LONG:
	case BELONG:
	case LELONG:
	case DATE:
	case BEDATE:
	case LEDATE:
		v = p->l;
		break;

	case STRING:
		l = 0;
		/*
		 * What we want here is: v = strncmp(m->value.s, p->s, m->vallen);
		 * but ignoring any nulls.  bcmp doesn't give -/+/0 and isn't
		 * universally available anyway.
		 */
		v = 0;
		{
			register unsigned char *a = (unsigned char *) m->value.s;
			register unsigned char *b = (unsigned char *) p->s;
			register int len = m->vallen;

			while (--len >= 0)
				if ((v = *b++ - *a++) != 0)
					break;
		}
		break;
	default:
		/*  bogosity, pretend that it just wasn't a match */
		return 0;
	}

	v = magic_signextend(m, v) & m->mask;

	switch (m->reln) {
	case 'x':
		matched = 1;
		break;

	case '!':
		matched = v != l;
		break;

	case '=':
		matched = v == l;
		break;

	case '>':
		if (m->flag & UNSIGNED) {
			matched = v > l;
		} else {
			matched = (long) v > (long) l;
		}
		break;

	case '<':
		if (m->flag & UNSIGNED) {
			matched = v < l;
		} else {
			matched = (long) v < (long) l;
		}
		break;

	case '&':
		matched = (v & l) == l;
		break;

	case '^':
		matched = (v & l) != l;
		break;

	default:
		/* bogosity, pretend it didn't match */
		matched = 0;
		break;
	}

	return matched;
}

/*
 * Go through the whole list, stopping if you find a match.  Process all the
 * continuations of that match before returning.
 *
 * We support multi-level continuations:
 *
 * At any time when processing a successful top-level match, there is a current
 * continuation level; it represents the level of the last successfully
 * matched continuation.
 *
 * Continuations above that level are skipped as, if we see one, it means that
 * the continuation that controls them - i.e, the lower-level continuation
 * preceding them - failed to match.
 *
 * Continuations below that level are processed as, if we see one, it means
 * we've finished processing or skipping higher-level continuations under the
 * control of a successful or unsuccessful lower-level continuation, and are
 * now seeing the next lower-level continuation and should process it.  The
 * current continuation level reverts to the level of the one we're seeing.
 *
 * Continuations at the current level are processed as, if we see one, there's
 * no lower-level continuation that may have failed.
 *
 * If a continuation matches, we bump the current continuation level so that
 * higher-level continuations are processed.
 */
static int
magic_match(unsigned char *s, int nbytes, struct magic *root, char *result)
{
	int cont_level = 0;
	int need_separator = 0, r = 0;
	union VALUETYPE p;
	struct magic *m;

	if (s == NULL || root == NULL || result == NULL) return 0;

	for (m = root; m; m = m->next) {
		/* check if main entry matches */
		if (!magic_mget(&p, s, m, nbytes) ||
			!magic_mcheck(&p, m)) {
			struct magic *m_cont;

			/*
			 * main entry didn't match, flush its continuations
			 */
			if (!m->next || (m->next->cont_level == 0)) {
				continue;
			}

			m_cont = m->next;
			while (m_cont && (m_cont->cont_level != 0)) {
				/*
				 * this trick allows us to keep *m in sync when the continue
				 * advances the pointer
				 */
				m = m_cont;
				m_cont = m_cont->next;
			}
			continue;
		}

		/* if we get here, the main entry rule was a match */
		/* this will be the last run through the loop */

		/* print the match */
		// magic_mprint(r, &p, m);

		/*
		 * If we printed something, we'll need to print a blank before we
		 * print something else.
		 */
		if (m->desc[0]) {
			need_separator = 1;
			strcpy(result, m->desc);
		}
		/* and any continuations that match */
		cont_level++;

		m = m->next;
		while (m && (m->cont_level != 0)) {
			if (cont_level >= m->cont_level) {
				if (cont_level > m->cont_level) {
					/*
					 * We're at the end of the level "cont_level"
					 * continuations.
					 */
					cont_level = m->cont_level;
				}

				if (magic_mget(&p, s, m, nbytes) &&
					magic_mcheck(&p, m)) {
					/*
					 * This continuation matched. Print its message, with a
					 * blank before it if the previous item printed and this
					 * item isn't empty.
					 */
					/* space if previous printed */
					if (need_separator
						&& (m->nospflag == 0)
						&& (m->desc[0] != '\0')
						) {
						strcat(result, " ");
						need_separator = 0;
					}

					strcat(result, m->desc);

					if (m->desc[0])
						need_separator = 1;

					/*
					 * If we see any continuations at a higher level, process
					 * them.
					 */
					cont_level++;
				}
			}

			/* move to next continuation record */
			m = m->next;
		}
		/* found match */
		r = strlen(result);
		return r;
	}
	return 0;  /* no match at all */
}

static handler_t
mod_mimemagic_set_defaults(server *srv, void *p_d)
{
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
		{ CONFIG_MIMEMAGIC_FILE, NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
		{ CONFIG_MIMEMAGIC_OVERRIDE_GLOBAL_MIMETYPE, NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 1 */
		{ NULL, NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};


	if (!p) return HANDLER_ERROR;

	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		array *ca;

		s = calloc(1, sizeof(plugin_config));
		s->magic_file = buffer_init();
		s->magics = NULL;
		s->override_global_mimetype = 0;

		cv[0].destination = s->magic_file;
		cv[1].destination = &(s->override_global_mimetype);

		p->config_storage[i] = s;
		ca = ((data_config *)srv->config_context->data[i])->value;

		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}

		if (s->magic_file->used) {
			/* magic file is set */
			s->magics = magic_apprentice(s->magic_file->ptr);
			if (s->magics == NULL) {
				log_error_write(srv, __FILE__, __LINE__, "sbs",
				       	"parse magic file", s->magic_file, "failed");
			}
		}

	}

	return HANDLER_GO_ON;
}

#define PATCH_OPTION(x) p->conf.x = s->x;

static int
mod_mimemagic_patch_connection(server *srv, connection *con, plugin_data *p)
{
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH_OPTION(magics);
	PATCH_OPTION(override_global_mimetype);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MIMEMAGIC_FILE))) {
				PATCH_OPTION(magics);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MIMEMAGIC_OVERRIDE_GLOBAL_MIMETYPE))) {
				PATCH_OPTION(override_global_mimetype);
			}
		}
	}

	return 0;
}

handler_t
mod_mimemagic_subrequest(server *srv, connection *con, void *p_d)
{
	plugin_data *p = p_d;
	stat_cache_entry *sce = NULL;
	FILE *fp = NULL;
	char result[1024];
	unsigned char buf[HOWMANY + 1];  /* one extra for terminating '\0' */
	uint32_t nbytes = 0; /* number of bytes read from a datafile */
	int r;

	/* someone else has done a decision for us */
	if (con->http_status != 0) return HANDLER_GO_ON;
	if (con->uri.path->used == 0) return HANDLER_GO_ON;
	if (con->physical.path->used == 0) return HANDLER_GO_ON;

	/* someone else has handled this request */
	if (con->mode != DIRECT) return HANDLER_GO_ON;
	if (con->file_finished) return HANDLER_GO_ON;

	/* we only handle GET, POST and HEAD */
	switch(con->request.http_method) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_POST:
	case HTTP_METHOD_HEAD:
		break;
	default:
		return HANDLER_GO_ON;
	}

	mod_mimemagic_patch_connection(srv, con, p);

	if (p->conf.magics == NULL) return HANDLER_GO_ON;

	if (con->conf.log_request_handling)
		log_error_write(srv, __FILE__, __LINE__,  "s",  "-- handling in mod_mimemagic_subrequest");

	if (HANDLER_ERROR == stat_cache_get_entry(srv, con, con->physical.path, &sce)) {
		/* file doesn't exist */
		return HANDLER_GO_ON;
	}

	/* we only handline regular files */
#ifdef HAVE_LSTAT
	if ((sce->is_symlink == 1) && !con->conf.follow_symlink) {
		return HANDLER_GO_ON;
	}
#endif
	if (!S_ISREG(sce->st.st_mode)) return HANDLER_GO_ON;

	/* set response content-type, if not set already */
	if ((p->conf.override_global_mimetype || buffer_is_empty(sce->content_type)) &&
		(NULL == array_get_element(con->response.headers, "Content-Type"))) {
		fp = fopen(con->physical.path->ptr, "rb");
		if (fp == NULL) return HANDLER_GO_ON;

		/*
		 * try looking at the first HOWMANY bytes
		 */
		nbytes = sizeof(buf) - 1;
		r = fread(buf, 1, nbytes, fp);
		fclose(fp);
		if (r > 0) {
			buf[r++] = '\0';
			result[0] = '\0';
			r = magic_match(buf, r, p->conf.magics, result);
			if (r > 0) response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), result, r);
		}
	}

	return HANDLER_GO_ON;
}

int
mod_mimemagic_plugin_init(plugin *p)
{
	p->version = LIGHTTPD_VERSION_ID;
	p->name = buffer_init_string("mimemagic");

	p->init = mod_mimemagic_init;
	p->handle_subrequest_start = mod_mimemagic_subrequest;
	p->set_defaults = mod_mimemagic_set_defaults;
	p->cleanup = mod_mimemagic_free;

	p->data = NULL;

	return 0;
}

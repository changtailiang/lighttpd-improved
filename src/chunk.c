/**
 * the network chunk-API
 *
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "chunk.h"
#include "server.h"
#include "log.h"

chunkqueue *chunkqueue_init(void) {
	chunkqueue *cq;

	cq = calloc(1, sizeof(*cq));

	cq->first = NULL;
	cq->last = NULL;

	cq->unused = NULL;

	return cq;
}

static chunk *chunk_init(void) {
	chunk *c;

	c = calloc(1, sizeof(*c));

	c->mem = buffer_init();
	c->file.name = buffer_init();
	c->file.fd = -1;
	c->file.mmap.start = MAP_FAILED;
	c->next = NULL;

	return c;
}

static void chunk_free(chunk *c) {
	if (!c) return;

	buffer_free(c->mem);
	buffer_free(c->file.name);
	if (c->file.fd > 0) close(c->file.fd);

	free(c);
}

void chunkqueue_free(chunkqueue *cq) {
	chunk *c, *pc;

	if (!cq) return;

	for (c = cq->first; c; ) {
		pc = c;
		c = c->next;
		chunk_free(pc);
	}

	for (c = cq->unused; c; ) {
		pc = c;
		c = c->next;
		chunk_free(pc);
	}

	free(cq);
}

static chunk *chunkqueue_get_unused_chunk(chunkqueue *cq) {
	chunk *c;

	/* check if we have a unused chunk */
	if (!cq->unused) {
		c = chunk_init();
	} else {
		/* take the first element from the list (a stack) */
		c = cq->unused;
		cq->unused = c->next;
		c->next = NULL;
		cq->unused_chunks--;
	}

	return c;
}

static int chunkqueue_prepend_chunk(chunkqueue *cq, chunk *c) {
	c->next = cq->first;
	cq->first = c;

	if (cq->last == NULL) {
		cq->last = c;
	}

	return 0;
}

static int chunkqueue_append_chunk(chunkqueue *cq, chunk *c) {
	if (cq->last) {
		cq->last->next = c;
	}
	cq->last = c;

	if (cq->first == NULL) {
		cq->first = c;
	}

	return 0;
}

void chunkqueue_reset(chunkqueue *cq) {
	chunk *c;

	/* mark all read written */
	for (c = cq->first; c; c = c->next) {
		switch(c->type) {
		case MEM_CHUNK:
			c->offset = c->mem->used - 1;
			break;
		case FILE_CHUNK:
			c->offset = c->file.length;
			break;
		default:
			break;
		}
	}

	chunkqueue_remove_finished_chunks(cq);
	cq->bytes_in = 0;
	cq->bytes_out = 0;
}

int chunkqueue_append_file(chunkqueue *cq, buffer *fn, off_t offset, off_t len) {
	chunk *c;

	if (len == 0) return 0;

	c = chunkqueue_get_unused_chunk(cq);

	c->type = FILE_CHUNK;

	buffer_copy_string_buffer(c->file.name, fn);
	c->file.start = offset;
	c->file.length = len;
	c->offset = 0;

	chunkqueue_append_chunk(cq, c);

	return 0;
}

int chunkqueue_append_shared_buffer(chunkqueue *cq, buffer *mem) {
	chunk *c;

	if (mem->used == 0) return 0;

	c = chunkqueue_get_unused_chunk(cq);
	c->type = MEM_CHUNK;
	c->offset = 0;
	buffer_free(c->mem); // free just allocated buffer
	c->mem = mem; // use shared buffer
	mem->ref_count ++;

	chunkqueue_append_chunk(cq, c);

	return 0;
}

int chunkqueue_append_buffer(chunkqueue *cq, buffer *mem) {
	chunk *c;

	if (mem->used == 0) return 0;

	c = chunkqueue_get_unused_chunk(cq);
	c->type = MEM_CHUNK;
	c->offset = 0;
	buffer_copy_string_buffer(c->mem, mem);

	chunkqueue_append_chunk(cq, c);

	return 0;
}

int chunkqueue_append_buffer_weak(chunkqueue *cq, buffer *mem) {
	chunk *c;

	if (mem->used == 0) return 0;

	c = chunkqueue_get_unused_chunk(cq);
	c->type = MEM_CHUNK;
	c->offset = 0;
	if (c->mem) buffer_free(c->mem);
	c->mem = mem;

	chunkqueue_append_chunk(cq, c);

	return 0;
}

int chunkqueue_prepend_buffer(chunkqueue *cq, buffer *mem) {
	chunk *c;

	if (mem->used == 0) return 0;

	c = chunkqueue_get_unused_chunk(cq);
	c->type = MEM_CHUNK;
	c->offset = 0;
	buffer_copy_string_buffer(c->mem, mem);

	chunkqueue_prepend_chunk(cq, c);

	return 0;
}


int chunkqueue_append_mem(chunkqueue *cq, const char * mem, size_t len) {
	chunk *c;

	if (len == 0) return 0;

	c = chunkqueue_get_unused_chunk(cq);
	c->type = MEM_CHUNK;
	c->offset = 0;
	buffer_copy_string_len(c->mem, mem, len - 1);

	chunkqueue_append_chunk(cq, c);

	return 0;
}

int chunkqueue_append_chunkqueue(chunkqueue *cq, chunkqueue *src) {
	if(src == NULL) return 0;
	chunkqueue_append_chunk(cq, src->first);
	cq->last = src->last;
	src->first = NULL;
	src->last = NULL;

	return 0;
}

buffer * chunkqueue_get_prepend_buffer(chunkqueue *cq) {
	chunk *c;

	c = chunkqueue_get_unused_chunk(cq);

	c->type = MEM_CHUNK;
	c->offset = 0;
	buffer_reset(c->mem);

	chunkqueue_prepend_chunk(cq, c);

	return c->mem;
}

buffer *chunkqueue_get_append_buffer(chunkqueue *cq) {
	chunk *c;

	c = chunkqueue_get_unused_chunk(cq);

	c->type = MEM_CHUNK;
	c->offset = 0;
	buffer_reset(c->mem);

	chunkqueue_append_chunk(cq, c);

	return c->mem;
}

int chunkqueue_set_tempdirs(chunkqueue *cq, array *tempdirs) {
	if (!cq) return -1;

	cq->tempdirs = tempdirs;

	return 0;
}

chunk *chunkqueue_get_append_tempfile(chunkqueue *cq) {
	chunk *c;
	buffer *template = buffer_init_string("/var/tmp/lighttpd-upload-XXXXXX");

	c = chunkqueue_get_unused_chunk(cq);

	c->type = FILE_CHUNK;
	c->offset = 0;

	if (cq->tempdirs && cq->tempdirs->used) {
		size_t i;

		/* we have several tempdirs, only if all of them fail we jump out */

		for (i = 0; i < cq->tempdirs->used; i++) {
			data_string *ds = (data_string *)cq->tempdirs->data[i];

			buffer_copy_string_buffer(template, ds->value);
			BUFFER_APPEND_SLASH(template);
			buffer_append_string_len(template, CONST_STR_LEN("lighttpd-upload-XXXXXX"));

			if (-1 != (c->file.fd = mkstemp(template->ptr))) {
				/* only trigger the unlink if we created the temp-file successfully */
				c->file.is_temp = 1;
				break;
			}
		}
	} else {
		if (-1 != (c->file.fd = mkstemp(template->ptr))) {
			/* only trigger the unlink if we created the temp-file successfully */
			c->file.is_temp = 1;
		}
	}

	buffer_copy_string_buffer(c->file.name, template);
	c->file.length = 0;

	chunkqueue_append_chunk(cq, c);

	buffer_free(template);

	return c;
}


off_t chunkqueue_length(chunkqueue *cq) {
	off_t len = 0;
	chunk *c;

	for (c = cq->first; c; c = c->next) {
		switch (c->type) {
		case MEM_CHUNK:
			len += c->mem->used ? c->mem->used - 1 : 0;
			break;
		case FILE_CHUNK:
			len += c->file.length;
			break;
		default:
			break;
		}
	}

	return len;
}

off_t chunkqueue_written(chunkqueue *cq) {
	off_t len = 0;
	chunk *c;

	for (c = cq->first; c; c = c->next) {
		switch (c->type) {
		case MEM_CHUNK:
		case FILE_CHUNK:
			len += c->offset;
			break;
		default:
			break;
		}
	}

	return len;
}

int chunkqueue_is_empty(chunkqueue *cq) {
	return cq->first ? 0 : 1;
}

int chunkqueue_remove_finished_chunks(chunkqueue *cq) {
	chunk *c;

	for (c = cq->first; c; c = cq->first) {
		int is_finished = 0;

		switch (c->type) {
		case MEM_CHUNK:
			if (c->mem->used == 0 || (c->offset == (off_t)c->mem->used - 1)) is_finished = 1;
			break;
		case FILE_CHUNK:
			if (c->offset == c->file.length) is_finished = 1;
			break;
		default:
			break;
		}

		if (!is_finished) break;

		cq->first = c->next;
		if (c == cq->last) cq->last = NULL;

#if 0
		/* keep at max 4 chunks in the 'unused'-cache */
		if (cq->unused_chunks > 1) {
			chunk_free(c);
		} else {
			c->next = cq->unused;
			cq->unused = c;
			cq->unused_chunks++;
		}
#else
		chunk_free(c);
#endif
	}

	return 0;
}

static int chunk_encode_append_len(chunkqueue *cq, size_t len) {
	size_t i, olen = len, j;
	buffer *b;
	
	/*b = srv->tmp_chunk_len;*/
	/*b = buffer_init();*/
	b = chunkqueue_get_append_buffer(cq);
	
	if (len == 0) {
		buffer_copy_string_len(b, CONST_STR_LEN("0"));
	} else {
		for (i = 0; i < 8 && len; i++) {
			len >>= 4;
		}
		
		/* i is the number of hex digits we have */
		buffer_prepare_copy(b, i + 1);
		
		for (j = i-1, len = olen; j+1 > 0; j--) {
			b->ptr[j] = (len & 0xf) + (((len & 0xf) <= 9) ? '0' : 'a' - 10);
			len >>= 4;
		}
		b->used = i;
		b->ptr[b->used++] = '\0';
	}
		
	buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
	/*
	chunkqueue_append_buffer(cq, b);
	buffer_free(b);
	*/
	
	return 0;
}


int chunk_encode_append_file(chunkqueue *cq, buffer *fn, off_t offset, off_t len) {
	if (!cq) return -1;
	if (len == 0) return 0;
	
	chunk_encode_append_len(cq, len);
	
	chunkqueue_append_file(cq, fn, offset, len);
	
	chunkqueue_append_mem(cq, "\r\n", 2 + 1);
	
	return 0;
}

int chunk_encode_append_buffer(chunkqueue *cq, buffer *mem) {
	if (!cq) return -1;
	if (mem->used <= 1) return 0;
	
	chunk_encode_append_len(cq, mem->used - 1);
	
	chunkqueue_append_buffer(cq, mem);
	
	chunkqueue_append_mem(cq, "\r\n", 2 + 1);
	
	return 0;
}

int chunk_encode_append_mem(chunkqueue *cq, const char * mem, size_t len) {
	if (!cq) return -1;
	if (len <= 1) return 0;
	
	chunk_encode_append_len(cq, len - 1);
	
	chunkqueue_append_mem(cq, mem, len);
	
	chunkqueue_append_mem(cq, "\r\n", 2 + 1);
	
	return 0;
}

int chunk_encode_append_queue(chunkqueue *cq, chunkqueue *src) {
	int len = chunkqueue_length(src);
	if (!cq) return -1;
	if (len == 0) return 0;
	
	chunk_encode_append_len(cq, len);
	
	chunkqueue_append_chunkqueue(cq, src);
	
	chunkqueue_append_mem(cq, "\r\n", 2 + 1);
	
	return 0;
}

int chunk_encode_end(chunkqueue *cq) {
	chunk_encode_append_len(cq, 0);
	chunkqueue_append_mem(cq, "\r\n", 2 + 1);
	return 0;
}


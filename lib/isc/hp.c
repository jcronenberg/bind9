/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*
 * Hazard Pointer implementation.
 *
 * This work is based on C++ code available from:
 * https://github.com/pramalhe/ConcurrencyFreaks/
 *
 * Copyright (c) 2014-2016, Pedro Ramalhete, Andreia Correia
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Concurrency Freaks nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER>
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <inttypes.h>

#include <isc/atomic.h>
#include <isc/hp.h>
#include <isc/string.h>
#include <isc/mem.h>
#include <isc/util.h>

#define HP_MAX_THREADS 128
#define HP_MAX_HPS 4			/* This is named 'K' in the HP paper */
#define CLPAD (128 / sizeof(uintptr_t))
#define HP_THRESHOLD_R 0		/* This is named 'R' in the HP paper */

/* Maximum number of retired objects per thread */
#define MAX_RETIRED (HP_MAX_THREADS * HP_MAX_HPS)

#define TID_UNKNOWN -1

static atomic_int_fast32_t tid_v_base;
static bool tid_v_initialized;

#if defined(HAVE_TLS)
#if defined(HAVE_THREAD_LOCAL)
#include <threads.h>
static thread_local int tid_v = TID_UNKNOWN;
#elif defined(HAVE___THREAD)
static __thread int tid_v = TID_UNKNOWN;
#elif defined(HAVE___DECLSPEC_THREAD)
static __declspec( thread ) int tid_v = TID_UNKNOWN;
#else  /* if defined(HAVE_THREAD_LOCAL) */
#error "Unknown method for defining a TLS variable!"
#endif /* if defined(HAVE_THREAD_LOCAL) */
#else  /* if defined(HAVE_TLS) */
#error "Thread-local storage support is required!"
#endif /* if defined(HAVE_TLS) */

typedef struct retirelist {
	int			size;
	uintptr_t		list[MAX_RETIRED];
} retirelist_t;

struct isc_hp {
	int			max_hps;
	isc_mem_t		*mctx;
	atomic_uintptr_t	*hp[HP_MAX_THREADS];
	retirelist_t		*rl[HP_MAX_THREADS];
	isc_hp_deletefunc_t	*deletefunc;
};

static inline int
tid() {
	if (!tid_v_initialized) {
		atomic_init(&tid_v_base, 0);
		tid_v_initialized = true;
	}
	if (tid_v == TID_UNKNOWN) {
		tid_v = atomic_fetch_add(&tid_v_base, 1);
		REQUIRE(tid_v < HP_MAX_THREADS);
	}

	return (tid_v);
}

isc_hp_t *
isc_hp_new(isc_mem_t *mctx, size_t max_hps, isc_hp_deletefunc_t *deletefunc) {
	isc_hp_t *hp = isc_mem_get(mctx, sizeof(*hp));

	if (max_hps == 0) {
		max_hps = HP_MAX_HPS;
	}

	*hp = (isc_hp_t){
		.max_hps = max_hps,
		.deletefunc = deletefunc
	};

	isc_mem_attach(mctx, &hp->mctx);

	for (int i = 0; i < HP_MAX_THREADS; i++) {
		hp->hp[i] = isc_mem_get(mctx, CLPAD * 2 * sizeof(hp->hp[i][0]));
		hp->rl[i] = isc_mem_get(mctx, sizeof(*hp->rl[0]));
		*hp->rl[i] = (retirelist_t) { .size = 0 };

		for (int j = 0; j < hp->max_hps; j++) {
			atomic_init(&hp->hp[i][j], 0);
		}
	}

	return (hp);
}

void
isc_hp_destroy(isc_hp_t *hp) {
	for (int i = 0; i < HP_MAX_THREADS; i++) {
		isc_mem_put(hp->mctx, hp->hp[i],
			    CLPAD * 2 * sizeof(uintptr_t));

		for (int j = 0; j < hp->rl[i]->size; j++) {
			void *data = (void *)hp->rl[i]->list[j];
			hp->deletefunc(data);
		}

		isc_mem_put(hp->mctx, hp->rl[i], sizeof(*hp->rl[0]));
	}

	isc_mem_putanddetach(&hp->mctx, hp, sizeof(*hp));
}

void
isc_hp_clear(isc_hp_t *hp) {
	for (int i = 0; i < hp->max_hps; i++) {
		atomic_store_release(&hp->hp[tid()][i], 0);
	}
}

void isc_hp_clear_one(isc_hp_t *hp, int ihp) {
	atomic_store_release(&hp->hp[tid()][ihp], 0);
}

uintptr_t
isc_hp_protect(isc_hp_t *hp, int ihp, atomic_uintptr_t *atom) {
	uintptr_t n = 0;
	uintptr_t ret;
	while ((ret = atomic_load(atom)) != n) {
		atomic_store(&hp->hp[tid()][ihp], ret);
		n = ret;
	}
	return (ret);
}

uintptr_t
isc_hp_protect_ptr(isc_hp_t *hp, int ihp, atomic_uintptr_t ptr) {
	atomic_store(&hp->hp[tid()][ihp], atomic_load(&ptr));
	return (atomic_load(&ptr));
}

uintptr_t
isc_hp_protect_release(isc_hp_t *hp, int ihp, atomic_uintptr_t ptr) {
	atomic_store_release(&hp->hp[tid()][ihp], atomic_load(&ptr));
	return (atomic_load(&ptr));
}

void
isc_hp_retire(isc_hp_t *hp, uintptr_t ptr) {
	hp->rl[tid()]->list[hp->rl[tid()]->size++] = ptr;
	INSIST(hp->rl[tid()]->size < MAX_RETIRED);

	if (hp->rl[tid()]->size < HP_THRESHOLD_R) {
		return;
	}

	for (int iret = 0; iret < hp->rl[tid()]->size; iret++) {
		uintptr_t obj = hp->rl[tid()]->list[iret];
		bool can_delete = true;
		for (int itid = 0;
		     itid < HP_MAX_THREADS && can_delete;
		     itid++)
		{
			for (int ihp = hp->max_hps-1; ihp >= 0; ihp--) {
				if (atomic_load(&hp->hp[itid][ihp]) == obj) {
					can_delete = false;
					break;
				}
			}
		}

		if (can_delete) {
			size_t bytes = (hp->rl[tid()]->size - iret) *
				sizeof(hp->rl[tid()]->list[0]);
			memmove(&hp->rl[tid()]->list[iret],
				&hp->rl[tid()]->list[iret + 1],
				bytes);
			hp->rl[tid()]->size--;
			hp->deletefunc((void *)obj);
		}
	}
}

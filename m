Return-Path: <kasan-dev+bncBDXYDPH3S4OBB6FASTFQMGQESKS2YKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C445D138E9
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:13 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-64b9ee8a07esf7384602a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231033; cv=pass;
        d=google.com; s=arc-20240605;
        b=gu1KXZgslY8mxMK0neTAisvRl2pdKBkrnL45uNy5275c30e3/+80Pi5EbGmNbH0t2s
         xwmRLhGSLVvzgjZUFXu9QMP0NpL/NIkKyl8mybCXoEeywRQPU3e9jW1X0SfiUcSfDK0M
         Pp2ufFKIeHgHgRTAm4XvdZy7RIDqpX+TQsKbb/UgrrjxeLikqabVpIVssU7EQRQLR6r6
         1QVF7gQHHldxuF8eUQV4rWfi5b85yNvcun16Buv4eb0ObhclrBC9se6dUWuzXfDHNHH3
         Ribx7jesjiXCyLtjpjpCUCy4KIctlg+j63SHsB3gc2t+vUMoKl6RCe2s+iCUp0iXdQxk
         Ve+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=Rhn1qT1fzCzsNYFGObot196psSLP4eMxE4qqMfs8RnE=;
        fh=lp2EN43z8iiUZIEjA3QvB4TjC3EezVOLInmlYnEwUqs=;
        b=P1XXrhw945R/jiI8lO1QpadbmAnlF9enzbJYVUJEAc4xlU/SFgsjyrM9BXZi8K04cC
         fXTfszxxw7FuD/K/24jJ2Qm5jYmTnbe9olp+9bPdHeZLssstYb9F73NXaX+KT0n3anuI
         YItCLY7QgB130HccjnV0H0coNfTr/OEyGSZP/V1Njzz0F9xVbOFE4K0vv8iwtlmk1Pj/
         iT69Qi4R3BheoxV/HoTswPdKnzX+IpOYiF0bYMjGcROUgbdjWUyvbGPoTECwCnqWEAxC
         lRlh8u9afR19zI14y+4HMiHgxIaSB1alzRFrV3L2l6P6KL9PKVh3SdDXmN4MPoUok/Cd
         biFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231033; x=1768835833; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Rhn1qT1fzCzsNYFGObot196psSLP4eMxE4qqMfs8RnE=;
        b=Z+l7MQiRnh8LoSNtGpXq+RwJscut6jz/TtH+Lmm95AQdK87WV5Td0teW95EPVEQD9R
         xIkMVNx74RaFiyeUnZiw/nt7XOAp4IZEWtxFFBma4ZnetG9Xw9OFkGoZd62RnR2ScW3l
         7vSMiH6XiVEIZ4nCLUkg0naEN6J6OfBwFUzEjfQ6LY0MTQBu63zpVjYJcLKa7hRZsOBZ
         8x9WeWvVgljwvrSDMQIFL1Yk30z/2DXDutJ9zpjV3Ckt7KWL1ppxICCuyfkivtOvvmh6
         xpA7p/g5jwLszVwaC/55jI8GvA1bCatFwdv7e0ky6MWS/O0X6G4DuuM3DsnlRPfH6Jhb
         tz9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231033; x=1768835833;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Rhn1qT1fzCzsNYFGObot196psSLP4eMxE4qqMfs8RnE=;
        b=FZJv5MBw8gxjG3NYvNp34saaQwqX4RgbXS5pj8tuquyvH10zfSpo1M66+IXrgzyiJT
         e03souw7zMA0NQuubtqwvon0FuFR7NYNJ2vQ/houFDL/VvYghsHR9SZi2hBaO0sk/LSR
         sR3cDqeXgfc+7HvGxtvHR5C3pLclOEaAp83w5grttoiXPzgizQwqOH7aeKfu+JYhi8CJ
         0WlO1F/FDvojTBnUb1sarhOtDyosP2pbqBRl1A7uYzSuyn8LwDTELlaBcArZmFM+gpdz
         B822jaa/7ptqp5J0ajPqDdmMJde3mT23N5IZ8fum/176JjvBChEF7ilonabIwM90qnOA
         NLBw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXLc/hgNAGV+UgW2ezIzye9M+fFWEVGxAl6G4KkCn8jDjQoI4IRIwvKckZPW/ql/hwZk+2I5g==@lfdr.de
X-Gm-Message-State: AOJu0YxLbC9Xar+NI9NHedtPKp8vs65GUDvuX1qSa9Ai1v5qoX6sKsqh
	CWTU2TDs4L0MnE9TTVdS7LDxfjljwwjOJ+bMbQunt2tzRvVrS63M7jCh
X-Google-Smtp-Source: AGHT+IFrhSvAEcLXGCWlMgtSkwQNPAsdnN7LfqsQF3ng2jicvnZCxhjheMuKZyAS51Q+o1XKSnXK4g==
X-Received: by 2002:a05:6402:27c8:b0:64c:fc09:c972 with SMTP id 4fb4d7f45d1cf-65097e50de2mr16560594a12.17.1768231032752;
        Mon, 12 Jan 2026 07:17:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EetL6q9NwxCC9ehHou97JatkwW9gBCCFJHAVSx3YnM6Q=="
Received: by 2002:aa7:dd06:0:b0:64c:7925:f275 with SMTP id 4fb4d7f45d1cf-650748d4084ls6603711a12.1.-pod-prod-09-eu;
 Mon, 12 Jan 2026 07:17:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUAx9I4kRn8Wm9y+LXB/EQH7vCQUoJJIae0BZKCqT770Dhd2b/gNGRLV9gMG8XiOjZjOBsfiUGfHPU=@googlegroups.com
X-Received: by 2002:a05:6402:1d52:b0:64b:4c70:a5f0 with SMTP id 4fb4d7f45d1cf-65097e5fdc3mr15348841a12.24.1768231030444;
        Mon, 12 Jan 2026 07:17:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231030; cv=none;
        d=google.com; s=arc-20240605;
        b=IcJV5tuZoKh0VX3IjEZOcbT12dqPWP+kLqRNkp3/KbhfKrDTyq0s4SYG0KkiBSrOxd
         VFF2ikBG6DQbo1nU6DDtBwFjrEvJob98Kj3V+JM2qyNwgaWCJmS2GBVu8S2VwbeisYLL
         jeiVvfjindYnBq7AkpFyGZOy4DURLS4jBhZOlVZtSO6W11GygWH++tefA5AheRxLnAJx
         P6iWbLyxnXo0ZvLCxr4E4aeh8GwVuwxrc1jS02/4KLmrHSIT4i/RAhP0+258FCvmxYxH
         K0+h+E29tdNtepI2XdPJ/60tBPuT1b71DoMHHucrv5ICUNBZ4Lq/nDFj4gFKadeMA25s
         ulxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=3D6Q2UMRMppGYaGqHyGHa2Wmv5A/RsbrdBLVyVB9TuE=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=M1MQz0MGUUK9fXaIXcCqyuDRXW1atbGuQ6hAKBgDDNVp6zyVaCoNAxPX/DosU1lVzT
         V2vaTQiPv3z6WyZQdkk8m+Zh7YE7k4dLBAfTXyVZrzHrpKqUN/2fpKrBwlDN1UkSH9n6
         3TGzcwtBTP8eluylHHckcRY0zx4ADVQ7lFqLEWumk0BMX+cHeUTVaygiLXt3YDYy/83l
         t96oCkkue686bQIJ1l6CTxOrDs8x2BKhSxN/sv+mX1H24HUeGeaG57bqIWZHx+Zj26BE
         n1DCjTcDEVJwEUopzEsqCvcjP8YklBwHaIVXWFKz21B9yJF3Ke4pZK9fpV7BALJfHPWf
         uyUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d5b8e44si366214a12.2.2026.01.12.07.17.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:10 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 509AB33690;
	Mon, 12 Jan 2026 15:16:58 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 34D493EA65;
	Mon, 12 Jan 2026 15:16:58 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id CBKTDGoQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:58 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:17:02 +0100
Subject: [PATCH RFC v2 08/20] slab: add optimized sheaf refill from partial
 list
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-8-98225cfb50cf@suse.cz>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
In-Reply-To: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
To: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
 Uladzislau Rezki <urezki@gmail.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, 
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
 bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.3
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Score: -4.00
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: 509AB33690
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Level: 
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

At this point we have sheaves enabled for all caches, but their refill
is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
slabs - now a redundant caching layer that we are about to remove.

The refill will thus be done from slabs on the node partial list.
Introduce new functions that can do that in an optimized way as it's
easier than modifying the __kmem_cache_alloc_bulk() call chain.

Extend struct partial_context so it can return a list of slabs from the
partial list with the sum of free objects in them within the requested
min and max.

Introduce get_partial_node_bulk() that removes the slabs from freelist
and returns them in the list.

Introduce get_freelist_nofreeze() which grabs the freelist without
freezing the slab.

Introduce alloc_from_new_slab() which can allocate multiple objects from
a newly allocated slab where we don't need to synchronize with freeing.
In some aspects it's similar to alloc_single_from_new_slab() but assumes
the cache is a non-debug one so it can avoid some actions.

Introduce __refill_objects() that uses the functions above to fill an
array of objects. It has to handle the possibility that the slabs will
contain more objects that were requested, due to concurrent freeing of
objects to those slabs. When no more slabs on partial lists are
available, it will allocate new slabs. It is intended to be only used
in context where spinning is allowed, so add a WARN_ON_ONCE check there.

Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
only refilled from contexts that allow spinning, or even blocking.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 284 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++-----
 1 file changed, 264 insertions(+), 20 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index f2de44f8bda4..b568801edec2 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -246,6 +246,9 @@ struct partial_context {
 	gfp_t flags;
 	unsigned int orig_size;
 	void *object;
+	unsigned int min_objects;
+	unsigned int max_objects;
+	struct list_head slabs;
 };
 
 static inline bool kmem_cache_debug(struct kmem_cache *s)
@@ -2638,9 +2641,9 @@ static void free_empty_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf)
 	stat(s, SHEAF_FREE);
 }
 
-static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
-				   size_t size, void **p);
-
+static unsigned int
+__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
+		 unsigned int max);
 
 static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
 			 gfp_t gfp)
@@ -2651,8 +2654,8 @@ static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
 	if (!to_fill)
 		return 0;
 
-	filled = __kmem_cache_alloc_bulk(s, gfp, to_fill,
-					 &sheaf->objects[sheaf->size]);
+	filled = __refill_objects(s, &sheaf->objects[sheaf->size], gfp,
+			to_fill, to_fill);
 
 	sheaf->size += filled;
 
@@ -3510,6 +3513,63 @@ static inline void put_cpu_partial(struct kmem_cache *s, struct slab *slab,
 #endif
 static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags);
 
+static bool get_partial_node_bulk(struct kmem_cache *s,
+				  struct kmem_cache_node *n,
+				  struct partial_context *pc)
+{
+	struct slab *slab, *slab2;
+	unsigned int total_free = 0;
+	unsigned long flags;
+
+	/* Racy check to avoid taking the lock unnecessarily. */
+	if (!n || data_race(!n->nr_partial))
+		return false;
+
+	INIT_LIST_HEAD(&pc->slabs);
+
+	spin_lock_irqsave(&n->list_lock, flags);
+
+	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
+		struct freelist_counters flc;
+		unsigned int slab_free;
+
+		if (!pfmemalloc_match(slab, pc->flags))
+			continue;
+
+		/*
+		 * determine the number of free objects in the slab racily
+		 *
+		 * due to atomic updates done by a racing free we should not
+		 * read an inconsistent value here, but do a sanity check anyway
+		 *
+		 * slab_free is a lower bound due to subsequent concurrent
+		 * freeing, the caller might get more objects than requested and
+		 * must deal with it
+		 */
+		flc.counters = data_race(READ_ONCE(slab->counters));
+		slab_free = flc.objects - flc.inuse;
+
+		if (unlikely(slab_free > oo_objects(s->oo)))
+			continue;
+
+		/* we have already min and this would get us over the max */
+		if (total_free >= pc->min_objects
+		    && total_free + slab_free > pc->max_objects)
+			break;
+
+		remove_partial(n, slab);
+
+		list_add(&slab->slab_list, &pc->slabs);
+
+		total_free += slab_free;
+		if (total_free >= pc->max_objects)
+			break;
+	}
+
+	spin_unlock_irqrestore(&n->list_lock, flags);
+	return total_free > 0;
+}
+
 /*
  * Try to allocate a partial slab from a specific node.
  */
@@ -4436,6 +4496,33 @@ static inline void *get_freelist(struct kmem_cache *s, struct slab *slab)
 	return old.freelist;
 }
 
+/*
+ * Get the slab's freelist and do not freeze it.
+ *
+ * Assumes the slab is isolated from node partial list and not frozen.
+ *
+ * Assumes this is performed only for caches without debugging so we
+ * don't need to worry about adding the slab to the full list
+ */
+static inline void *get_freelist_nofreeze(struct kmem_cache *s, struct slab *slab)
+{
+	struct freelist_counters old, new;
+
+	do {
+		old.freelist = slab->freelist;
+		old.counters = slab->counters;
+
+		new.freelist = NULL;
+		new.counters = old.counters;
+		VM_BUG_ON(new.frozen);
+
+		new.inuse = old.objects;
+
+	} while (!slab_update_freelist(s, slab, &old, &new, "get_freelist_nofreeze"));
+
+	return old.freelist;
+}
+
 /*
  * Freeze the partial slab and return the pointer to the freelist.
  */
@@ -4459,6 +4546,64 @@ static inline void *freeze_slab(struct kmem_cache *s, struct slab *slab)
 	return old.freelist;
 }
 
+/*
+ * If the object has been wiped upon free, make sure it's fully initialized by
+ * zeroing out freelist pointer.
+ *
+ * Note that we also wipe custom freelist pointers.
+ */
+static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
+						   void *obj)
+{
+	if (unlikely(slab_want_init_on_free(s)) && obj &&
+	    !freeptr_outside_object(s))
+		memset((void *)((char *)kasan_reset_tag(obj) + s->offset),
+			0, sizeof(void *));
+}
+
+static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
+		void **p, unsigned int count, bool allow_spin)
+{
+	unsigned int allocated = 0;
+	struct kmem_cache_node *n;
+	unsigned long flags;
+	void *object;
+
+	if (!allow_spin && (slab->objects - slab->inuse) > count) {
+
+		n = get_node(s, slab_nid(slab));
+
+		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
+			/* Unlucky, discard newly allocated slab */
+			defer_deactivate_slab(slab, NULL);
+			return 0;
+		}
+	}
+
+	object = slab->freelist;
+	while (object && allocated < count) {
+		p[allocated] = object;
+		object = get_freepointer(s, object);
+		maybe_wipe_obj_freeptr(s, p[allocated]);
+
+		slab->inuse++;
+		allocated++;
+	}
+	slab->freelist = object;
+
+	if (slab->freelist) {
+
+		if (allow_spin) {
+			n = get_node(s, slab_nid(slab));
+			spin_lock_irqsave(&n->list_lock, flags);
+		}
+		add_partial(n, slab, DEACTIVATE_TO_HEAD);
+		spin_unlock_irqrestore(&n->list_lock, flags);
+	}
+
+	return allocated;
+}
+
 /*
  * Slow path. The lockless freelist is empty or we need to perform
  * debugging duties.
@@ -4901,21 +5046,6 @@ static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
 	return object;
 }
 
-/*
- * If the object has been wiped upon free, make sure it's fully initialized by
- * zeroing out freelist pointer.
- *
- * Note that we also wipe custom freelist pointers.
- */
-static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
-						   void *obj)
-{
-	if (unlikely(slab_want_init_on_free(s)) && obj &&
-	    !freeptr_outside_object(s))
-		memset((void *)((char *)kasan_reset_tag(obj) + s->offset),
-			0, sizeof(void *));
-}
-
 static __fastpath_inline
 struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s, gfp_t flags)
 {
@@ -5376,6 +5506,9 @@ static int __prefill_sheaf_pfmemalloc(struct kmem_cache *s,
 	return ret;
 }
 
+static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
+				   size_t size, void **p);
+
 /*
  * returns a sheaf that has at least the requested size
  * when prefilling is needed, do so with given gfp flags
@@ -7461,6 +7594,117 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 }
 EXPORT_SYMBOL(kmem_cache_free_bulk);
 
+static unsigned int
+__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
+		 unsigned int max)
+{
+	struct slab *slab, *slab2;
+	struct partial_context pc;
+	unsigned int refilled = 0;
+	unsigned long flags;
+	void *object;
+	int node;
+
+	pc.flags = gfp;
+	pc.min_objects = min;
+	pc.max_objects = max;
+
+	node = numa_mem_id();
+
+	if (WARN_ON_ONCE(!gfpflags_allow_spinning(gfp)))
+		return 0;
+
+	/* TODO: consider also other nodes? */
+	if (!get_partial_node_bulk(s, get_node(s, node), &pc))
+		goto new_slab;
+
+	list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
+
+		list_del(&slab->slab_list);
+
+		object = get_freelist_nofreeze(s, slab);
+
+		while (object && refilled < max) {
+			p[refilled] = object;
+			object = get_freepointer(s, object);
+			maybe_wipe_obj_freeptr(s, p[refilled]);
+
+			refilled++;
+		}
+
+		/*
+		 * Freelist had more objects than we can accomodate, we need to
+		 * free them back. We can treat it like a detached freelist, just
+		 * need to find the tail object.
+		 */
+		if (unlikely(object)) {
+			void *head = object;
+			void *tail;
+			int cnt = 0;
+
+			do {
+				tail = object;
+				cnt++;
+				object = get_freepointer(s, object);
+			} while (object);
+			do_slab_free(s, slab, head, tail, cnt, _RET_IP_);
+		}
+
+		if (refilled >= max)
+			break;
+	}
+
+	if (unlikely(!list_empty(&pc.slabs))) {
+		struct kmem_cache_node *n = get_node(s, node);
+
+		spin_lock_irqsave(&n->list_lock, flags);
+
+		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
+
+			if (unlikely(!slab->inuse && n->nr_partial >= s->min_partial))
+				continue;
+
+			list_del(&slab->slab_list);
+			add_partial(n, slab, DEACTIVATE_TO_HEAD);
+		}
+
+		spin_unlock_irqrestore(&n->list_lock, flags);
+
+		/* any slabs left are completely free and for discard */
+		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
+
+			list_del(&slab->slab_list);
+			discard_slab(s, slab);
+		}
+	}
+
+
+	if (likely(refilled >= min))
+		goto out;
+
+new_slab:
+
+	slab = new_slab(s, pc.flags, node);
+	if (!slab)
+		goto out;
+
+	stat(s, ALLOC_SLAB);
+	inc_slabs_node(s, slab_nid(slab), slab->objects);
+
+	/*
+	 * TODO: possible optimization - if we know we will consume the whole
+	 * slab we might skip creating the freelist?
+	 */
+	refilled += alloc_from_new_slab(s, slab, p + refilled, max - refilled,
+					/* allow_spin = */ true);
+
+	if (refilled < min)
+		goto new_slab;
+out:
+
+	return refilled;
+}
+
 static inline
 int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 			    void **p)

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-8-98225cfb50cf%40suse.cz.

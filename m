Return-Path: <kasan-dev+bncBDXYDPH3S4OBB65ASTFQMGQELNHBCAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id E22C6D138ED
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:16 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-64c62f69defsf7243588a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231036; cv=pass;
        d=google.com; s=arc-20240605;
        b=lIBoQR5Bnv8rUFGDxyj5pfgx4UVjkYdqm0swMnvNYK1xFJ1YZSlf1FjApbIu2WpCoy
         9DrrGvEomzcQFIleTZbqms6nWZJe7Es47/JRXIFTr/QYkJekhG/ABo9AHleBXuZ0rd4Y
         ICqnSYt/did1Ur2UgTw7A9zA7VDXgnzfKkkXW203yMW7TGTwBdeSvYFVnYZqOYMLB8wN
         +I05VDflSW4MvConnPmNdlYp7vVKnJ7whN91z3SLWqico+pw0NDQC18idhwwShkBdq1J
         AYqxShs3YPY/lGX9/oWqHnp3FpdMfWowXAyGP87krgmrOynsjUQIIBZgwarh+UjQj3eL
         Ro8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=Z2Kknwsq1EwHtDJKkzBgXCHdS4kgT46QmpUlQdi2Kl4=;
        fh=DhASfIQmd03WOyfCgIi3/uoseDrpkl02vv6G3Wrsr1g=;
        b=MdsdOx4eqLiq869l4t8m4XVNzuvt0Bnyk0RU+mDpQi7Irz8psGkgXQWT81SKzo8xKq
         JpdD7DL4xIXBGhBaJy5zh3OGj0rP8SgGh8QdnujK6SbLXae0PeaBtG5cBWc7LVyaSuFU
         85zMw5tlJTFAQlAkgUlhxXOFJZ81GxuZNMwP5Zp/3nCEU9TPV81js7a1/iO8WQhwO2rR
         hvdya529GOZp97UqBk5k5ZaVNQNakD7VzOZO1jYOu4Rn4uoHNb+Edv+uFhdwpESlVX08
         xby0W9E2Uj46I8S1lkiAXnPKgIJJY8Rjikb6YO5TzVCqKh6A7HBWeIGuKZzC5O804vPF
         kTyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231036; x=1768835836; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Z2Kknwsq1EwHtDJKkzBgXCHdS4kgT46QmpUlQdi2Kl4=;
        b=N1hWHrs2urAxs9ghjGDXa0YATE4oQr8ekwa9skVrP55BTCHv9uPWOZPYhieRhODjzH
         ksINeECckHnBEmo4bTZdTeR2cV5dp2nLjZ6QamEfcIL5DuFZD6FMY5rwE3N4O8sniT+W
         GoaEVV/85V9qeX3AunchdXhgzqv6OBDIYNupUlJg2RKCrBvquwIjLIb9UiASYREq4/5Y
         roIxQv+YB/jhZ3D1X7MHWUmslud4sET25LSxvOi14hDvRQslWTeLRIi1kcrT+TO2z6M1
         BAHId8UNspdwBbKcxT/Mke5mTrqnH9sbz/rVxQWcCo3ivt6hb8EoOxFYocS7aNlcO2/0
         vyjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231036; x=1768835836;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Z2Kknwsq1EwHtDJKkzBgXCHdS4kgT46QmpUlQdi2Kl4=;
        b=nHJzTLTeaK1FvODcoKOuZFo3PiJpB/N0aAMp6LNU6v8I/a95QxUz9+JXF2zYB1WmRV
         f2zelaS0SgDVre1eMWhXb6AoVo8anV0p/IdUCKQkC8lMQAhd4LrBQUepZSBq42xVExzA
         PDVBLKZ5/PBdWPx9O1vJKPklpHyJXqcLvNIW1mKGmJX7XrzG1yqB7gAwGOndDlNNoHi9
         PuQWsDHlFN7P5n+Lih5tFuVvSqOxY6ajI6wjaFMgvRtSPJwxX3pxhTIfrOuFSjPDZRVc
         f7/jodpUc4kjMKAzs7UgrBOC73i9rOXQSGFVBzdYYDL3RRz0AbENejgrr/MFoKPOeMNN
         1VrQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW1Lx/anDmSZLty8Iuc8x9v6PTKXrg3KQTeggseQRkhGAhRKHpIYzBnQESA3fscEwQciJa0gA==@lfdr.de
X-Gm-Message-State: AOJu0YxF4V9mCkPbKgw3zAOo0t8+morda5G74lvKanZfdQQjnHPnQPBg
	kmHGOuo5+sEareTH+1kP8WhVgofRG/eXB4hiP62b8ZNuvgg/UYUPGDLS
X-Google-Smtp-Source: AGHT+IFLO7JGJhBRknE/z345uU74m6qpFS/RezE46c6OSuMvzQgZaicPTGh6Q/EqE9AvGI89XSJMmw==
X-Received: by 2002:a05:6402:40c2:b0:64d:317e:8ae3 with SMTP id 4fb4d7f45d1cf-65097e721eamr17017068a12.33.1768231036294;
        Mon, 12 Jan 2026 07:17:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FJy8BeNZFL0PQI4fLocldrIVdqtWM/3SvzsP1NyBIO7g=="
Received: by 2002:a05:6402:553:b0:64b:a8b0:ba67 with SMTP id
 4fb4d7f45d1cf-65074317c8els5306944a12.0.-pod-prod-07-eu; Mon, 12 Jan 2026
 07:17:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXU/hna7w4C/5v+asgjm17KSFGe+7cIzwR6EZfkwS7zL4ToF/5Tkv3BAS606c6knHf5V+nnxcnl9X8=@googlegroups.com
X-Received: by 2002:a05:6402:40c2:b0:64d:317e:8ae3 with SMTP id 4fb4d7f45d1cf-65097e721eamr17016881a12.33.1768231033728;
        Mon, 12 Jan 2026 07:17:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231033; cv=none;
        d=google.com; s=arc-20240605;
        b=BupZNRdt2mb+D/J8ttVq5exzb4Bo2fC6z/igS6i2aSA5ARGZPpxM7O7o5GH085iOXI
         /jGLFJLy28SMDAsYbmvFbLvmB+ANZggCR+lZRatbNrErs0MPblwRyoUUyn/TETZTLWS9
         2N74S2B0lUgkSsb4a2U5vYapg60xt2LFLBJ+PUtdrNW/AciyjSxtJ47TYBrGVIVGpR07
         Yc3yb3B9uGxT9FO6xZ37pBz+gjRH6N8q4+v/Fe/zNlobjgMkiCJYh49YeLvVhs0+HG1p
         mqlhYldl9hvjfBaq+sxLW4plEVz3amzvyWnH2w8s6OnPn5ZKbsU26hHPJJrH+grHBDZh
         FIhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=diP2IFc7AwGuuRdNganw2C+plBX5QxFb3pNFx4A6T6k=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=C7JDWLzRHf9BnVLOoeI6YRJxL4H7OJ1uEJAheL3LbPSr1Noqg0mvJKOWtCKLcyZjKE
         gOV5uxoM5oEVtr5acQUe8rUeVfXZmdfiyPl89Wzqo2ZIb1tUwRoCKDGoinpYFcoUm9Qr
         z/dtovywHYaTw/ExVOFQxxKMNra7W4dqTPa5keW6+X+idb2xxv16sr9BRcNB/Sn7YXoF
         F2C0wcD902z+uLBu+kDCZ1jcLMhjzT9wixUTA4ay9BX3uTFhEqkFCZC9vIUNBrS22H+U
         3WHfL8OL2StDsLNNsXR8nQCtxGU6u8j8wykCMz8c90ovAg5wvJRZy9Uog0zCZx+WczTk
         /FOw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d71679csi339128a12.6.2026.01.12.07.17.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:13 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id C4DF633695;
	Mon, 12 Jan 2026 15:16:58 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id A80C93EA65;
	Mon, 12 Jan 2026 15:16:58 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id oNG6KGoQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:58 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:17:06 +0100
Subject: [PATCH RFC v2 12/20] slab: remove defer_deactivate_slab()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-12-98225cfb50cf@suse.cz>
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
X-Rspamd-Queue-Id: C4DF633695
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

There are no more cpu slabs so we don't need their deferred
deactivation. The function is now only used from places where we
allocate a new slab but then can't spin on node list_lock to put it on
the partial list. Instead of the deferred action we can free it directly
via __free_slab(), we just need to tell it to use _nolock() freeing of
the underlying pages and take care of the accounting.

Since free_frozen_pages_nolock() variant does not yet exist for code
outside of the page allocator, create it as a trivial wrapper for
__free_frozen_pages(..., FPI_TRYLOCK).

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/internal.h   |  1 +
 mm/page_alloc.c |  5 +++++
 mm/slab.h       |  8 +-------
 mm/slub.c       | 51 ++++++++++++++++-----------------------------------
 4 files changed, 23 insertions(+), 42 deletions(-)

diff --git a/mm/internal.h b/mm/internal.h
index e430da900430..1f44ccb4badf 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -846,6 +846,7 @@ static inline struct page *alloc_frozen_pages_noprof(gfp_t gfp, unsigned int ord
 struct page *alloc_frozen_pages_nolock_noprof(gfp_t gfp_flags, int nid, unsigned int order);
 #define alloc_frozen_pages_nolock(...) \
 	alloc_hooks(alloc_frozen_pages_nolock_noprof(__VA_ARGS__))
+void free_frozen_pages_nolock(struct page *page, unsigned int order);
 
 extern void zone_pcp_reset(struct zone *zone);
 extern void zone_pcp_disable(struct zone *zone);
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 822e05f1a964..8a288ecfdd93 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2981,6 +2981,11 @@ void free_frozen_pages(struct page *page, unsigned int order)
 	__free_frozen_pages(page, order, FPI_NONE);
 }
 
+void free_frozen_pages_nolock(struct page *page, unsigned int order)
+{
+	__free_frozen_pages(page, order, FPI_TRYLOCK);
+}
+
 /*
  * Free a batch of folios
  */
diff --git a/mm/slab.h b/mm/slab.h
index e77260720994..4efec41b6445 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -71,13 +71,7 @@ struct slab {
 	struct kmem_cache *slab_cache;
 	union {
 		struct {
-			union {
-				struct list_head slab_list;
-				struct { /* For deferred deactivate_slab() */
-					struct llist_node llnode;
-					void *flush_freelist;
-				};
-			};
+			struct list_head slab_list;
 			/* Double-word boundary */
 			struct freelist_counters;
 		};
diff --git a/mm/slub.c b/mm/slub.c
index 522a7e671a26..0effeb3b9552 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3248,7 +3248,7 @@ static struct slab *new_slab(struct kmem_cache *s, gfp_t flags, int node)
 		flags & (GFP_RECLAIM_MASK | GFP_CONSTRAINT_MASK), node);
 }
 
-static void __free_slab(struct kmem_cache *s, struct slab *slab)
+static void __free_slab(struct kmem_cache *s, struct slab *slab, bool allow_spin)
 {
 	struct page *page = slab_page(slab);
 	int order = compound_order(page);
@@ -3262,11 +3262,20 @@ static void __free_slab(struct kmem_cache *s, struct slab *slab)
 	free_frozen_pages(page, order);
 }
 
+static void free_new_slab_nolock(struct kmem_cache *s, struct slab *slab)
+{
+	/*
+	 * Since it was just allocated, we can skip the actions in
+	 * discard_slab() and free_slab().
+	 */
+	__free_slab(s, slab, false);
+}
+
 static void rcu_free_slab(struct rcu_head *h)
 {
 	struct slab *slab = container_of(h, struct slab, rcu_head);
 
-	__free_slab(slab->slab_cache, slab);
+	__free_slab(slab->slab_cache, slab, true);
 }
 
 static void free_slab(struct kmem_cache *s, struct slab *slab)
@@ -3282,7 +3291,7 @@ static void free_slab(struct kmem_cache *s, struct slab *slab)
 	if (unlikely(s->flags & SLAB_TYPESAFE_BY_RCU))
 		call_rcu(&slab->rcu_head, rcu_free_slab);
 	else
-		__free_slab(s, slab);
+		__free_slab(s, slab, true);
 }
 
 static void discard_slab(struct kmem_cache *s, struct slab *slab)
@@ -3375,8 +3384,6 @@ static void *alloc_single_from_partial(struct kmem_cache *s,
 	return object;
 }
 
-static void defer_deactivate_slab(struct slab *slab, void *flush_freelist);
-
 /*
  * Called only for kmem_cache_debug() caches to allocate from a freshly
  * allocated slab. Allocate a single object instead of whole freelist
@@ -3392,8 +3399,8 @@ static void *alloc_single_from_new_slab(struct kmem_cache *s, struct slab *slab,
 	void *object;
 
 	if (!allow_spin && !spin_trylock_irqsave(&n->list_lock, flags)) {
-		/* Unlucky, discard newly allocated slab */
-		defer_deactivate_slab(slab, NULL);
+		/* Unlucky, discard newly allocated slab. */
+		free_new_slab_nolock(s, slab);
 		return NULL;
 	}
 
@@ -4262,7 +4269,7 @@ static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
 
 		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
 			/* Unlucky, discard newly allocated slab */
-			defer_deactivate_slab(slab, NULL);
+			free_new_slab_nolock(s, slab);
 			return 0;
 		}
 	}
@@ -6031,7 +6038,6 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 
 struct defer_free {
 	struct llist_head objects;
-	struct llist_head slabs;
 	struct irq_work work;
 };
 
@@ -6039,7 +6045,6 @@ static void free_deferred_objects(struct irq_work *work);
 
 static DEFINE_PER_CPU(struct defer_free, defer_free_objects) = {
 	.objects = LLIST_HEAD_INIT(objects),
-	.slabs = LLIST_HEAD_INIT(slabs),
 	.work = IRQ_WORK_INIT(free_deferred_objects),
 };
 
@@ -6052,10 +6057,9 @@ static void free_deferred_objects(struct irq_work *work)
 {
 	struct defer_free *df = container_of(work, struct defer_free, work);
 	struct llist_head *objs = &df->objects;
-	struct llist_head *slabs = &df->slabs;
 	struct llist_node *llnode, *pos, *t;
 
-	if (llist_empty(objs) && llist_empty(slabs))
+	if (llist_empty(objs))
 		return;
 
 	llnode = llist_del_all(objs);
@@ -6079,16 +6083,6 @@ static void free_deferred_objects(struct irq_work *work)
 
 		__slab_free(s, slab, x, x, 1, _THIS_IP_);
 	}
-
-	llnode = llist_del_all(slabs);
-	llist_for_each_safe(pos, t, llnode) {
-		struct slab *slab = container_of(pos, struct slab, llnode);
-
-		if (slab->frozen)
-			deactivate_slab(slab->slab_cache, slab, slab->flush_freelist);
-		else
-			free_slab(slab->slab_cache, slab);
-	}
 }
 
 static void defer_free(struct kmem_cache *s, void *head)
@@ -6102,19 +6096,6 @@ static void defer_free(struct kmem_cache *s, void *head)
 		irq_work_queue(&df->work);
 }
 
-static void defer_deactivate_slab(struct slab *slab, void *flush_freelist)
-{
-	struct defer_free *df;
-
-	slab->flush_freelist = flush_freelist;
-
-	guard(preempt)();
-
-	df = this_cpu_ptr(&defer_free_objects);
-	if (llist_add(&slab->llnode, &df->slabs))
-		irq_work_queue(&df->work);
-}
-
 void defer_free_barrier(void)
 {
 	int cpu;

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-12-98225cfb50cf%40suse.cz.

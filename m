Return-Path: <kasan-dev+bncBDXYDPH3S4OBBTXG5DDQMGQEHOR3WBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id D6D6BC018E8
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:19 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-362de25dbc4sf4494741fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227599; cv=pass;
        d=google.com; s=arc-20240605;
        b=V+pbuDRVHik7uarB65D1B37Sdt1Swdj1UmLMxjo0reK1lZ+moALdJnnXEfsuoMg9Dc
         8RbIad8DKlzpnLBi0DQjsS7GhDs88scVAmy2TMcS9byFqFZsGWSFDsBp8AZbVUMi65R2
         SnaUv6Ar0eafFWGZTFPj3sd8FprJCRl+mQP4y0T/hiHKzlhzStG/R59tJUiucazpphyd
         DYZhPPeHr0uCz5b168bS/cQlsKRSRFCWZHTX+rJIBzXrlRodUr7X/SGCeITwaDyS+vya
         XMGOgrkZgO9QaaQlUNxUBqmvENrHa8PzxPKWlcl6Y/27qvu1OhLFk/QiuYvDfvqIL6Dt
         nEew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=etDX8KahFhvACmLqdHm7HUF6Bv7mKDUnFNXJAd1MB7A=;
        fh=qqGEVX3gaocHnYdvDu86Jn9v02N7Y/HSwSKgs2ZU//c=;
        b=h4Nxo3429BVhTlH6zzchk7zuNvl+kgLTecRKmyvXshN4iTgImLlh9ohovgh3w7oh9K
         1eq6oqyRhD4XX+i690EClYLi3AgXmnypx8b0c/v3qvFinBBQt6duQpc99ASYNA9R6DIO
         RotPsPo7MrHeuA3CmneskfgRDuntkFmnXLd1YiXvYmku4zRC+XfawZSh7Jf0WalInGFa
         3c4s4p3EsmyzupNn9XGiRYmYuP+4HXcVIRm5uNxaL8vqSHTQaSuWzJz6j/SbQA+V+bR9
         D47GZtTOrFrYfHRIJhF7Df7tzbUu+926Z16nw3p4YHZlGwsZDfgaCpfcq7g5dUUS+NRx
         AOQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227599; x=1761832399; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=etDX8KahFhvACmLqdHm7HUF6Bv7mKDUnFNXJAd1MB7A=;
        b=kvbN3/ANxv7TwMMqoCj5FhD71u9mpoQ01w+Tmx8xStx3J9EeVnwPc0gyIL8mjimbSL
         wEhH57AOhpuNxD8ec14ouZ7VO1dIQWxTQIEB+cbWDQBuo3zYlMMHavBSQeEmC/ehvauQ
         lhp0KZV8J52jrAisayb9qKB/N9S/mUTWNAUu3cTTT4bhoFJKF4lp5SMjoMfQQZDb5uce
         MMd6TJfXTlmnNIAgNg8TiPHlodgKLXJ2zs4jNMaucEhF9K6GEbkY4Wyra45GX4XEyxhT
         3ZXr02ls8TAR84ivwT1hFO8S3pWLy913IGrfKzACEn5nv95bFKPU4tpN5wirGKwk7NiR
         7tig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227599; x=1761832399;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=etDX8KahFhvACmLqdHm7HUF6Bv7mKDUnFNXJAd1MB7A=;
        b=L7yArf6foVttiq8Xcy2f29Zkq8/A4seq3VVdJFKpTwYgGh5USnT0zx0KK/2T7jnmxq
         Mo1F5yJomOES3gXZH7jG4SdCc1jqUB0VntIt/mQbhQfNSiOtHNXKSFSiZHefsUPkjJvG
         Kah/a4H7Kc3nXIVPy5OdG468+j9hPx/aO9aBs7AkRK8WATysd/t3cNLNEvTtIU8vlkb7
         4bL2Ozkp7ZDZE220u5gAN4v2Bj/5F1oT3kU4V/XcB3KMOvtNh6bwtEI74SwcM2OoAt6s
         hxRj+J7ses9tTsF6gcuwl0BD1UIk/zebKYzkuSn6KVcRjoL2hK4xMkbyO9npurIVKAxY
         js9A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXduO5isZs03ESsqELeNIN3mfLPkXSq/BGSQCaelqLzj/t8QVTdNb8KsJPgRruK5TOywRZ38w==@lfdr.de
X-Gm-Message-State: AOJu0YzJwKnUtzxtSqGCy1EI9B5Qh7xoszU3lBWC9dP0VCAwnO4CiahN
	hdxY1qviW1n8zDKW60V2Ab/Z1wYdx899FEmZtT6KH4jw+N6E7XVVhb1V
X-Google-Smtp-Source: AGHT+IF4BVNbbsBtykIuiTPTvRl8gioEGDLoVdqTy7JrHODaNRsP52YBAAqDpHzAhQEAoel5M+1aCQ==
X-Received: by 2002:a05:651c:901:b0:36b:bfd3:13e3 with SMTP id 38308e7fff4ca-37797a08f5cmr69626891fa.29.1761227598674;
        Thu, 23 Oct 2025 06:53:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aRkMDwNAvdgGNUpf1vuQyroyQHCYuMtborZ4YowxAEhQ=="
Received: by 2002:a2e:9ec8:0:b0:376:3178:b73d with SMTP id 38308e7fff4ca-378d6499965ls1754501fa.1.-pod-prod-05-eu;
 Thu, 23 Oct 2025 06:53:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWwIBdZDNXaxUtzsv9LaTtvxR6myhxSymHAo1aB05rLt60+HmUXPhpVEa6LyeAZuZpg8/sGj8zgklI=@googlegroups.com
X-Received: by 2002:a05:651c:242:b0:372:932b:f5dd with SMTP id 38308e7fff4ca-377978d7220mr65641701fa.20.1761227595579;
        Thu, 23 Oct 2025 06:53:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227595; cv=none;
        d=google.com; s=arc-20240605;
        b=NjScLElgdb+7jiy1rCrOxRHuPTBLTkdPVlGNvwK9Ua1Q1HYGm9vWUGQHNEYIxiNpjK
         BTxx4YtvYiMzWvDSIgtCIzM4Bs8Ff203GNuQV2T5dr52BV9g/nmyOIi+RD9C/t3kNoS9
         BrVyXBriuzgclCPSLOpJCSteaRwSfE6VAZP84DJT7+V7zt1887zANoAdbSW9j++7NT11
         eeUXPt3rHtBgkkqMNM9e8yG6DfmVlhh/rzPt1e6D1pbtsV5sMS7szSCfKUDUTTxbHkU4
         7NndbEoTGRQATaYcD5Pem96h9GmDhurD6RR36iVLJXZejgRFYfCSpLe30pllzp9Wk350
         zH5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=T2ZEYr8/h5A7sedphkcRhXt+75mCYtLkQBBoLhCU1eo=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=MM0OAghsdxbTsLgEihLe2h9SXZDRZqrgwmpsvneHHfX4uDEGBJI2rD2idz7s2/d8oI
         X+JQr2cfeXhXkfaA/XlmETCx891hhNODS4xRYjYGmCikd3ecE8H9Q0HqYdswyvP5h7X6
         U41kWXlcM61q3whjBmToESj0zk0ZjjMahAQbS9UmR3p9OxYWTqFHSKmA+0au82IAbQzr
         ZHrqm2XAMRp/Mxyzi1Vhkl3WLmfJj+VpVzT3KQ91c7T1m49Jk1UUjgddcdPbDLHIad+M
         JKrs8BjZ51NbGEW6Qa3xB2EOyIgQcODKPfR/OJg8CdbNfalxjoFUrlU49XAdqJfbjPmM
         mf1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378d66942bbsi400111fa.1.2025.10.23.06.53.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A95971F7CA;
	Thu, 23 Oct 2025 13:53:01 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 4F60413B0B;
	Thu, 23 Oct 2025 13:52:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id QOT/EjYz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:54 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:35 +0200
Subject: [PATCH RFC 13/19] slab: remove defer_deactivate_slab()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-13-6ffa2c9941c0@suse.cz>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
In-Reply-To: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Cc: Uladzislau Rezki <urezki@gmail.com>, 
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
X-Spam-Level: 
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Rspamd-Queue-Id: A95971F7CA
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -4.00
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
deactivation. The function is now only used from a place where we
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
 mm/slub.c       | 50 +++++++++++++++-----------------------------------
 4 files changed, 22 insertions(+), 42 deletions(-)

diff --git a/mm/internal.h b/mm/internal.h
index 1561fc2ff5b8..64c5eda7c1ae 100644
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
index 600d9e981c23..f8ac3232db41 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2944,6 +2944,11 @@ void free_frozen_pages(struct page *page, unsigned int order)
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
index a103da44ab9d..b2663cc594f3 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -55,13 +55,7 @@ struct slab {
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
 			union {
 				struct {
diff --git a/mm/slub.c b/mm/slub.c
index a35eb397caa9..6f5ca26bbb00 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3246,7 +3246,7 @@ static struct slab *new_slab(struct kmem_cache *s, gfp_t flags, int node)
 		flags & (GFP_RECLAIM_MASK | GFP_CONSTRAINT_MASK), node);
 }
 
-static void __free_slab(struct kmem_cache *s, struct slab *slab)
+static void __free_slab(struct kmem_cache *s, struct slab *slab, bool allow_spin)
 {
 	struct folio *folio = slab_folio(slab);
 	int order = folio_order(folio);
@@ -3257,14 +3257,18 @@ static void __free_slab(struct kmem_cache *s, struct slab *slab)
 	__folio_clear_slab(folio);
 	mm_account_reclaimed_pages(pages);
 	unaccount_slab(slab, order, s);
-	free_frozen_pages(&folio->page, order);
+
+	if (allow_spin)
+		free_frozen_pages(&folio->page, order);
+	else
+		free_frozen_pages_nolock(&folio->page, order);
 }
 
 static void rcu_free_slab(struct rcu_head *h)
 {
 	struct slab *slab = container_of(h, struct slab, rcu_head);
 
-	__free_slab(slab->slab_cache, slab);
+	__free_slab(slab->slab_cache, slab, true);
 }
 
 static void free_slab(struct kmem_cache *s, struct slab *slab)
@@ -3280,7 +3284,7 @@ static void free_slab(struct kmem_cache *s, struct slab *slab)
 	if (unlikely(s->flags & SLAB_TYPESAFE_BY_RCU))
 		call_rcu(&slab->rcu_head, rcu_free_slab);
 	else
-		__free_slab(s, slab);
+		__free_slab(s, slab, true);
 }
 
 static void discard_slab(struct kmem_cache *s, struct slab *slab)
@@ -3373,8 +3377,6 @@ static void *alloc_single_from_partial(struct kmem_cache *s,
 	return object;
 }
 
-static void defer_deactivate_slab(struct slab *slab, void *flush_freelist);
-
 /*
  * Called only for kmem_cache_debug() caches to allocate from a freshly
  * allocated slab. Allocate a single object instead of whole freelist
@@ -3390,8 +3392,12 @@ static void *alloc_single_from_new_slab(struct kmem_cache *s, struct slab *slab,
 	void *object;
 
 	if (!allow_spin && !spin_trylock_irqsave(&n->list_lock, flags)) {
-		/* Unlucky, discard newly allocated slab */
-		defer_deactivate_slab(slab, NULL);
+		/*
+		 * Unlucky, discard newly allocated slab.
+		 * Since it was just allocated, we can skip the actions
+		 * in discard_slab() and free_slab().
+		 */
+		__free_slab(s, slab, false);
 		return NULL;
 	}
 
@@ -5949,7 +5955,6 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 
 struct defer_free {
 	struct llist_head objects;
-	struct llist_head slabs;
 	struct irq_work work;
 };
 
@@ -5957,7 +5962,6 @@ static void free_deferred_objects(struct irq_work *work);
 
 static DEFINE_PER_CPU(struct defer_free, defer_free_objects) = {
 	.objects = LLIST_HEAD_INIT(objects),
-	.slabs = LLIST_HEAD_INIT(slabs),
 	.work = IRQ_WORK_INIT(free_deferred_objects),
 };
 
@@ -5970,10 +5974,9 @@ static void free_deferred_objects(struct irq_work *work)
 {
 	struct defer_free *df = container_of(work, struct defer_free, work);
 	struct llist_head *objs = &df->objects;
-	struct llist_head *slabs = &df->slabs;
 	struct llist_node *llnode, *pos, *t;
 
-	if (llist_empty(objs) && llist_empty(slabs))
+	if (llist_empty(objs))
 		return;
 
 	llnode = llist_del_all(objs);
@@ -5997,16 +6000,6 @@ static void free_deferred_objects(struct irq_work *work)
 
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
@@ -6020,19 +6013,6 @@ static void defer_free(struct kmem_cache *s, void *head)
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
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-13-6ffa2c9941c0%40suse.cz.

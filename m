Return-Path: <kasan-dev+bncBDXYDPH3S4OBBO7G5DDQMGQENJWMWEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id CC285C018C1
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:01 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-63c55116bdfsf793107a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227581; cv=pass;
        d=google.com; s=arc-20240605;
        b=UdrAIZLK8ADDBjmW7HW1j8s89pU7LsL96tDaWRBd2sC36D/Fsqy+AP7tYjePp//g8S
         tC4wOvdbJ6VA5BkH7KTOvXwHeWXHCebbTc1dHH6pWRFwDemJ5ufdLdSh6HzE5Sjf0bZR
         jDMJdm9KsoQKNPdSQsHAKdHgHHVgs0nxQghtny94i+NJGuLLMn4khSjZUlK0rMwdX6KB
         lc3xJpmC5MliQvUG8aXN9OJ69xvD1kgeVbGto1IyWA0cBLZZXSk/laz41qrgbtn3m4oL
         Oino40UmNHQ5x8bzrh9cUrU1oZcKUo+eWci8PkYIqKBD/esXv1+PPvNZvINUzafIIy43
         0K9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=rqVBVjBFLtzvUJx81enjSHXiDqAUVXg2o+boI0WjQiA=;
        fh=A5v6pSFqz2R9DEoVlaCwwDF4DivdEhT89JrIanHF/Uk=;
        b=jCq1JNa/ySzKbBuuFa5L3VPCv5OoLBqoi2SiSqFRVt2hMkvjMtgx41ws9kojMRfk4u
         DNCQO9D1XyykhpXxVyxGTjbuMN6IONHVVvsdBqdwtJZitAOkeQoQl2zyySP6kX0I4uvE
         FMn13gPAbj/qb8NvjQnA3dRXTbAYy5z9E9RlcZ7rMjeOQevtRz3vmDFNH4pCpT9h/sH6
         RmB5T/KZQBbq2UQkUn2o+xZO4u7HWClOB5hJ9qmhdC+rMed+bzYkfin3xjrHVnEGLBYi
         LwYAA8eYz3YNDZ+dzAuV1M8VcgIWvmsVaPy9oXr84uMUHQKqoGI4Dkrk6S91ZO4wZFzi
         iTmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=JNhOt4Mr;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227581; x=1761832381; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rqVBVjBFLtzvUJx81enjSHXiDqAUVXg2o+boI0WjQiA=;
        b=uX+l2Ew57WFPKGB0ly/+cnq+OyeWALenUpaEPZDFvHgC4igrubP48fxehovq8xhpj9
         HzpbUpXIMKsnYmhiq9TbrOLn/0cEOLwpEG3ORYOiEN9SFyPzfVvUaYSdm0Bg1dn18rca
         jGdL/azX7DGKExzDt3OM94mZ/eQbdsdVTt6zgFXfrd6m3GkSDfFl+TRuLEcKexOYYBaD
         PD52B342BJ5af8vVPdgkauVQQj1UIKk6970jxLYw0wJuVpTo/28XbB8HPjz0NpB1tS9T
         XMQo1X825wyFGYTERwayGmKFp0eXVs5bsSwMWf5lhgvowUWjBz4xbpcEY1dbbZPir47V
         ChVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227581; x=1761832381;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rqVBVjBFLtzvUJx81enjSHXiDqAUVXg2o+boI0WjQiA=;
        b=U8dYr250IbjyGAOBzqu0YDFUPgU3+8JEiHk0N7ttq6ml3JFQeHkAxiRj8VWoirIr3M
         SqwMkG5G7S4bCd2h9x4o4U1eYaIrmrIAfMhjwjkuhKTdY2dH0QKdPIPnysJKaHtPIuEy
         CBQEln69tWP1+ZvBtETtj2Mz/kH008KMM8Xq7M5YEeR4lWQV9ePjb7u/zrJIDiuAuPIU
         qaoRDAGTvsbcHqVkuYubGwH+MWviFgFq+K1a2Q20GsAF8EZ73IoJXk4XXBcN+bxt8wsC
         FJ93aqY1lt9FsqSt3exJsbcu5tdkFudTDoqbZ3Yv2IZ+gyZW8MhMwYMsF8jxs+Fe4++5
         NXmQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWAojzPEli+YvM8t3MKUitYfsM0LmlaWIVh83M2qcjPtA3qaTJE6PEUZQ0ae4qciD/rXDQalA==@lfdr.de
X-Gm-Message-State: AOJu0YwrQ8jRi6bOXmrpBtdNhKL17MGL6zz4Vxy/H/Rbsu1gOD+sq2im
	LXBLs3xlG7EN6adKjm+FUPBsli64yax6DjTNEPYsDeu4lI8tQkzr5i0Y
X-Google-Smtp-Source: AGHT+IEEErCnu2JoR9Uzth5AbON3B3b42hk5C8bBdvg93jS5jM0MZBmBjNzMQLeLWnDpow3JdnsIaA==
X-Received: by 2002:a05:6402:40c5:b0:637:e4d1:af00 with SMTP id 4fb4d7f45d1cf-63c1f677665mr23923984a12.10.1761227580837;
        Thu, 23 Oct 2025 06:53:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5YABz3UswtKYHt7X1vEpEXl/ptxASMn6Lj6kRkLbdGTg=="
Received: by 2002:a05:6402:20cc:20b0:63c:4828:e88b with SMTP id
 4fb4d7f45d1cf-63e3eb8f346ls732544a12.2.-pod-prod-07-eu; Thu, 23 Oct 2025
 06:52:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU/2ety9YFt2AnRneKdFMzZN+qL8oHKXaLgqv/L0xXjc4AW8cmKFBvQeiHWdYu6TL0fJ9S+bzUFh70=@googlegroups.com
X-Received: by 2002:a17:907:a43:b0:b41:c892:2c70 with SMTP id a640c23a62f3a-b647512871emr2963713666b.49.1761227577973;
        Thu, 23 Oct 2025 06:52:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227577; cv=none;
        d=google.com; s=arc-20240605;
        b=NavQsgJ+eJTej2dCCQPRv9P38awV/Cczv9qtFIMDdXuRaY2uo47vjvHJnlXv7y/A/L
         5ewS/s7XfJ1z8bBMKpq/6qoyYCfgYUGEl3AVpYnYhbccvBP4xT6l0QbCgaAvpmLNVvK7
         m6RvqaWYYDESU3SWzsXsDT7ze4zRV3pTVINr9Ns9+E8+QcYvHbrMpjKJjlr+n78+9In7
         14ohcv0RGT2tlT46xtNSrHDftY+nA6gBAp5Zif8u83vmxbexkpspMcoG0pAzBx4/UWEa
         xWUL0Z4RmUfl5iMQIB3zXEJBTek3MJ0AFtnPv6wP0SdpFdBzMO8PVsLiqhqf6OSk70wD
         dhaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=QwO+ywC/2qNyrdzTEnXXbwTudyXSN4BHY9D8LplJsaM=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=XGHIbdrj6jYt+rH7uedRoK127pUI6DhcnCx9bnJhrWkWTruQvkViTfiLhjiaHY+ENt
         ljNpH0QEg/FqkJP2O3DOq+2Su5tEc9nvTZ+WO9ImsKlsXhXIfM410wCj8VsnPBCtaH4o
         dQ3NDVUdvPGuUQhNd36VOVABdMxhVZl5BNDTkid/71pZytPF7XEOaGcwPNLXWQdcIezC
         QK92btxXFE59ZBT8mt8tql7iOQsrll4XHEOuyDqeFZrYCFniXqQU/OUhVtVxGRk9PWfb
         3hdEqRVdJG6AWUbvq9i21yXPav6sw+ZOgYA6QubviWu8Pwp59/Du/EdPhyHAqqgv2KR5
         kzMg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=JNhOt4Mr;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b6d513c689fsi4860066b.3.2025.10.23.06.52.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:52:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 67B0B1F7E5;
	Thu, 23 Oct 2025 13:52:53 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 4A26513AAC;
	Thu, 23 Oct 2025 13:52:53 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id gMrQETUz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:53 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:25 +0200
Subject: [PATCH RFC 03/19] slub: remove CONFIG_SLUB_TINY specific code
 paths
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-3-6ffa2c9941c0@suse.cz>
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
X-Rspamd-Queue-Id: 67B0B1F7E5
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -4.00
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=JNhOt4Mr;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

CONFIG_SLUB_TINY minimizes the SLUB's memory overhead in multiple ways,
mainly by avoiding percpu caching of slabs and objects. It also reduces
code size by replacing some code paths with simplified ones through
ifdefs, but the benefits of that are smaller and would complicate the
upcoming changes.

Thus remove these code paths and associated ifdefs and simplify the code
base.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h |   2 --
 mm/slub.c | 107 +++-----------------------------------------------------------
 2 files changed, 4 insertions(+), 105 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 078daecc7cf5..f7b8df56727d 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -236,10 +236,8 @@ struct kmem_cache_order_objects {
  * Slab cache management.
  */
 struct kmem_cache {
-#ifndef CONFIG_SLUB_TINY
 	struct kmem_cache_cpu __percpu *cpu_slab;
 	struct lock_class_key lock_key;
-#endif
 	struct slub_percpu_sheaves __percpu *cpu_sheaves;
 	/* Used for retrieving partial slabs, etc. */
 	slab_flags_t flags;
diff --git a/mm/slub.c b/mm/slub.c
index ab03f29dc3bf..68867cd52c4f 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -410,7 +410,6 @@ enum stat_item {
 	NR_SLUB_STAT_ITEMS
 };
 
-#ifndef CONFIG_SLUB_TINY
 /*
  * When changing the layout, make sure freelist and tid are still compatible
  * with this_cpu_cmpxchg_double() alignment requirements.
@@ -432,7 +431,6 @@ struct kmem_cache_cpu {
 	unsigned int stat[NR_SLUB_STAT_ITEMS];
 #endif
 };
-#endif /* CONFIG_SLUB_TINY */
 
 static inline void stat(const struct kmem_cache *s, enum stat_item si)
 {
@@ -597,12 +595,10 @@ static inline void *get_freepointer(struct kmem_cache *s, void *object)
 	return freelist_ptr_decode(s, p, ptr_addr);
 }
 
-#ifndef CONFIG_SLUB_TINY
 static void prefetch_freepointer(const struct kmem_cache *s, void *object)
 {
 	prefetchw(object + s->offset);
 }
-#endif
 
 /*
  * When running under KMSAN, get_freepointer_safe() may return an uninitialized
@@ -714,10 +710,12 @@ static inline unsigned int slub_get_cpu_partial(struct kmem_cache *s)
 	return s->cpu_partial_slabs;
 }
 #else
+#ifdef SLAB_SUPPORTS_SYSFS
 static inline void
 slub_set_cpu_partial(struct kmem_cache *s, unsigned int nr_objects)
 {
 }
+#endif
 
 static inline unsigned int slub_get_cpu_partial(struct kmem_cache *s)
 {
@@ -2026,13 +2024,11 @@ static inline void inc_slabs_node(struct kmem_cache *s, int node,
 							int objects) {}
 static inline void dec_slabs_node(struct kmem_cache *s, int node,
 							int objects) {}
-#ifndef CONFIG_SLUB_TINY
 static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
 			       void **freelist, void *nextfree)
 {
 	return false;
 }
-#endif
 #endif /* CONFIG_SLUB_DEBUG */
 
 #ifdef CONFIG_SLAB_OBJ_EXT
@@ -3617,8 +3613,6 @@ static struct slab *get_partial(struct kmem_cache *s, int node,
 	return get_any_partial(s, pc);
 }
 
-#ifndef CONFIG_SLUB_TINY
-
 #ifdef CONFIG_PREEMPTION
 /*
  * Calculate the next globally unique transaction for disambiguation
@@ -4018,12 +4012,6 @@ static bool has_cpu_slab(int cpu, struct kmem_cache *s)
 	return c->slab || slub_percpu_partial(c);
 }
 
-#else /* CONFIG_SLUB_TINY */
-static inline void __flush_cpu_slab(struct kmem_cache *s, int cpu) { }
-static inline bool has_cpu_slab(int cpu, struct kmem_cache *s) { return false; }
-static inline void flush_this_cpu_slab(struct kmem_cache *s) { }
-#endif /* CONFIG_SLUB_TINY */
-
 static bool has_pcs_used(int cpu, struct kmem_cache *s)
 {
 	struct slub_percpu_sheaves *pcs;
@@ -4364,7 +4352,6 @@ static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags)
 	return true;
 }
 
-#ifndef CONFIG_SLUB_TINY
 static inline bool
 __update_cpu_freelist_fast(struct kmem_cache *s,
 			   void *freelist_old, void *freelist_new,
@@ -4628,7 +4615,7 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
 	pc.orig_size = orig_size;
 	slab = get_partial(s, node, &pc);
 	if (slab) {
-		if (kmem_cache_debug(s)) {
+		if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
 			freelist = pc.object;
 			/*
 			 * For debug caches here we had to go through
@@ -4666,7 +4653,7 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
 
 	stat(s, ALLOC_SLAB);
 
-	if (kmem_cache_debug(s)) {
+	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
 		freelist = alloc_single_from_new_slab(s, slab, orig_size, gfpflags);
 
 		if (unlikely(!freelist))
@@ -4874,32 +4861,6 @@ static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
 
 	return object;
 }
-#else /* CONFIG_SLUB_TINY */
-static void *__slab_alloc_node(struct kmem_cache *s,
-		gfp_t gfpflags, int node, unsigned long addr, size_t orig_size)
-{
-	struct partial_context pc;
-	struct slab *slab;
-	void *object;
-
-	pc.flags = gfpflags;
-	pc.orig_size = orig_size;
-	slab = get_partial(s, node, &pc);
-
-	if (slab)
-		return pc.object;
-
-	slab = new_slab(s, gfpflags, node);
-	if (unlikely(!slab)) {
-		slab_out_of_memory(s, gfpflags, node);
-		return NULL;
-	}
-
-	object = alloc_single_from_new_slab(s, slab, orig_size, gfpflags);
-
-	return object;
-}
-#endif /* CONFIG_SLUB_TINY */
 
 /*
  * If the object has been wiped upon free, make sure it's fully initialized by
@@ -5746,9 +5707,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 	 * it did local_lock_irqsave(&s->cpu_slab->lock, flags).
 	 * In this case fast path with __update_cpu_freelist_fast() is not safe.
 	 */
-#ifndef CONFIG_SLUB_TINY
 	if (!in_nmi() || !local_lock_is_locked(&s->cpu_slab->lock))
-#endif
 		ret = __slab_alloc_node(s, alloc_gfp, node, _RET_IP_, size);
 
 	if (PTR_ERR(ret) == -EBUSY) {
@@ -6511,14 +6470,10 @@ static void free_deferred_objects(struct irq_work *work)
 	llist_for_each_safe(pos, t, llnode) {
 		struct slab *slab = container_of(pos, struct slab, llnode);
 
-#ifdef CONFIG_SLUB_TINY
-		free_slab(slab->slab_cache, slab);
-#else
 		if (slab->frozen)
 			deactivate_slab(slab->slab_cache, slab, slab->flush_freelist);
 		else
 			free_slab(slab->slab_cache, slab);
-#endif
 	}
 }
 
@@ -6554,7 +6509,6 @@ void defer_free_barrier(void)
 		irq_work_sync(&per_cpu_ptr(&defer_free_objects, cpu)->work);
 }
 
-#ifndef CONFIG_SLUB_TINY
 /*
  * Fastpath with forced inlining to produce a kfree and kmem_cache_free that
  * can perform fastpath freeing without additional function calls.
@@ -6647,14 +6601,6 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
 	}
 	stat_add(s, FREE_FASTPATH, cnt);
 }
-#else /* CONFIG_SLUB_TINY */
-static void do_slab_free(struct kmem_cache *s,
-				struct slab *slab, void *head, void *tail,
-				int cnt, unsigned long addr)
-{
-	__slab_free(s, slab, head, tail, cnt, addr);
-}
-#endif /* CONFIG_SLUB_TINY */
 
 static __fastpath_inline
 void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
@@ -6932,11 +6878,7 @@ void kfree_nolock(const void *object)
 	 * since kasan quarantine takes locks and not supported from NMI.
 	 */
 	kasan_slab_free(s, x, false, false, /* skip quarantine */true);
-#ifndef CONFIG_SLUB_TINY
 	do_slab_free(s, slab, x, x, 0, _RET_IP_);
-#else
-	defer_free(s, x);
-#endif
 }
 EXPORT_SYMBOL_GPL(kfree_nolock);
 
@@ -7386,7 +7328,6 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 }
 EXPORT_SYMBOL(kmem_cache_free_bulk);
 
-#ifndef CONFIG_SLUB_TINY
 static inline
 int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 			    void **p)
@@ -7451,35 +7392,6 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	return 0;
 
 }
-#else /* CONFIG_SLUB_TINY */
-static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
-				   size_t size, void **p)
-{
-	int i;
-
-	for (i = 0; i < size; i++) {
-		void *object = kfence_alloc(s, s->object_size, flags);
-
-		if (unlikely(object)) {
-			p[i] = object;
-			continue;
-		}
-
-		p[i] = __slab_alloc_node(s, flags, NUMA_NO_NODE,
-					 _RET_IP_, s->object_size);
-		if (unlikely(!p[i]))
-			goto error;
-
-		maybe_wipe_obj_freeptr(s, p[i]);
-	}
-
-	return i;
-
-error:
-	__kmem_cache_free_bulk(s, i, p);
-	return 0;
-}
-#endif /* CONFIG_SLUB_TINY */
 
 /* Note that interrupts must be enabled when calling this function. */
 int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
@@ -7698,7 +7610,6 @@ init_kmem_cache_node(struct kmem_cache_node *n, struct node_barn *barn)
 		barn_init(barn);
 }
 
-#ifndef CONFIG_SLUB_TINY
 static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
 {
 	BUILD_BUG_ON(PERCPU_DYNAMIC_EARLY_SIZE <
@@ -7719,12 +7630,6 @@ static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
 
 	return 1;
 }
-#else
-static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
-{
-	return 1;
-}
-#endif /* CONFIG_SLUB_TINY */
 
 static int init_percpu_sheaves(struct kmem_cache *s)
 {
@@ -7814,13 +7719,11 @@ void __kmem_cache_release(struct kmem_cache *s)
 	cache_random_seq_destroy(s);
 	if (s->cpu_sheaves)
 		pcs_destroy(s);
-#ifndef CONFIG_SLUB_TINY
 #ifdef CONFIG_PREEMPT_RT
 	if (s->cpu_slab)
 		lockdep_unregister_key(&s->lock_key);
 #endif
 	free_percpu(s->cpu_slab);
-#endif
 	free_kmem_cache_nodes(s);
 }
 
@@ -8563,10 +8466,8 @@ void __init kmem_cache_init(void)
 
 void __init kmem_cache_init_late(void)
 {
-#ifndef CONFIG_SLUB_TINY
 	flushwq = alloc_workqueue("slub_flushwq", WQ_MEM_RECLAIM, 0);
 	WARN_ON(!flushwq);
-#endif
 }
 
 struct kmem_cache *

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-3-6ffa2c9941c0%40suse.cz.

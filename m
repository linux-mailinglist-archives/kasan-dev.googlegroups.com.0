Return-Path: <kasan-dev+bncBDXYDPH3S4OBBR7G5DDQMGQET3QGPWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 978FFC018D9
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:14 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-378deda303esf2461081fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227592; cv=pass;
        d=google.com; s=arc-20240605;
        b=XwRxluLa5FQ9mpjnxJGj7DhXJVhhpZl438jP9E64L4Yrzv/IkK4N9WxHqvejNwAogS
         Cyf7E7B3+64DLZlDRVT7SNY58L7T7UohgtGf/990liUY3zqoJU27IqBGDwr2IL0wFhU9
         I/woXJeo8pU0DQjsF+G5vq7wuUQLZseQy0ToMGjXfbyddo+TYxwlbf2yvlACYUviYhae
         YvS+7NPtA5FzAJpt3DuW9OM6su4SBH7S3iHzaJqb5/ksLbYHmE743ALR70jbBpyR42Pf
         3pS48R03yGwgNPDw1XNXS0z/pC0md9MxXz/nUzuBZOUE4NZfH7rXl6ptU1rW6DQeqYPj
         REeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=AQTVplxk5p9Ul4nIAmHnLaAMWzOFICidKicW6NLPlrw=;
        fh=fBF1Ol8fjLzlzXG3KrwpFBdVjZ4iXE16bfXsxhl0mtw=;
        b=Jeqf2S5zG5l7qb5PPfWIiQNVX5ButDM+dXSjmmZu5GVnhK8pjgcW8Eb8UJgvxTCav8
         Pl298iwu8Ot6KsfitLgFYRKErnmKregi1I5t9WODRdoLbPnNSvRtCQNV18colKHY7NIf
         nwNNCjDchnBFAiwjlBxLL5bX7IkFEXqEGs7kDTFwU3X0UMeMebzRXzl41efWIz6LAe8L
         9VIPV0sbTK76IFxhhe4t3TkQFKPEBO8msbR5XXXSpgf2+co9EuQ3QkkiSiTxxSVwRpxb
         U60knKnZ52plYcgQmzlSt+J26ZV06t2V9tkfklAU0DOmKWu7Bt5+znB58MZwu08m68od
         fLPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227592; x=1761832392; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AQTVplxk5p9Ul4nIAmHnLaAMWzOFICidKicW6NLPlrw=;
        b=CMRJAt4cAWlJ8/wkpXzYwM1jvUCfuDJ6xfORAfX46QEYHf2pBwEuZdKO+CbiCF9K/D
         pKQTCXusit7GikXhLkKea/acNgyZrA+B25dCdXuCNbSoIEqV0T6fe6WTfddrHHLqAFIu
         BlClaua7T34Gy6EwmclgYln18AwB0hgF7mZqyS0ukFodCa+MayAgPhJksLnb5wVQjUtT
         ekS1zwYMYAgG2Lkixn3SWJ0aZ5L44XaoMufPRQb84DPtx5/KAR2ROtUmaRAIanCMW9MD
         3CjKWg+uPXFpTPMEzBJ8XStr5OX12q7EWCVLdYq6MhBIXtOsRZtu7KZAnZ7gXg7GHpi2
         XzrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227592; x=1761832392;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AQTVplxk5p9Ul4nIAmHnLaAMWzOFICidKicW6NLPlrw=;
        b=mhFJFJAtm6Zc78AlDXNuI26a/XL5mfA4b9QRlBBfyZmRva6vrdRO3WlRrUvxVTn8bZ
         ybgawUg4achEhhrCprl1IHncDwtksCySaBH5PUMd3oXjf9G64+6pmhw+moYIdRo2jGQZ
         AKkFcCOelKYL2V6vsZb24owcCRsIaplru/dUNfzxPr3cFOVpgW9iWczBxpDo/xV8GPfD
         n2dDJCjmOVY06bcw+okdVsRbVfgTCGzHHhNAON6idWjGUkf+pxgdiNc+b6TxyGaIG26l
         yP1Shk7z7Kg07R9H9R75JPZY9zqdWB29/RWXkQzzg6fuOe/wxda9F/eRFK8bgPRJFc0U
         iJKA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWwQtDQEW1tO5IvHKTtThPXRfXti2gc2gf/taZ7sApuModw1j5OG+5j6hq3gQEg0NJkiY9EeQ==@lfdr.de
X-Gm-Message-State: AOJu0YwejwFONGXOA9ByvjWn3BnlnWqOMeoF8eSd2B0+XpVz+gmgtz57
	W9/3foBPwscwiRvRme6ky5d9T4aGK7mBdYmjw1o8R2nGmKEiVVl6Ek4e
X-Google-Smtp-Source: AGHT+IHzJYI4WwcmUQ+tznbKAb1Ho+Va4DU1sA6aDvkBW/ULwoyL6EokCLI7Cf/SifFlfrvypcUQHQ==
X-Received: by 2002:a05:651c:25c9:10b0:378:dda3:2b52 with SMTP id 38308e7fff4ca-378dda32c39mr5229421fa.19.1761227592200;
        Thu, 23 Oct 2025 06:53:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4kBr0wt2ICHpPCo8lyFTqV5IOkZ9XWlxJmcsnJAwbqzA=="
Received: by 2002:a2e:2e18:0:b0:378:d26c:53ba with SMTP id 38308e7fff4ca-378d64cbfecls1722781fa.1.-pod-prod-01-eu;
 Thu, 23 Oct 2025 06:53:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW6F5L0pbh24fY50sBVkF9A3A5kJYaGw2JhoUA+Oslu6JULWLRB98iQVgly1lSGbuAUoVwOQVrxKMM=@googlegroups.com
X-Received: by 2002:a05:651c:198d:b0:332:1720:2ec7 with SMTP id 38308e7fff4ca-378d699694cmr8311401fa.0.1761227588022;
        Thu, 23 Oct 2025 06:53:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227588; cv=none;
        d=google.com; s=arc-20240605;
        b=Pr9Ui14vR7hl4yFJnczRYmGaOxBxn7XhIybJoUvAp+x+1whZ2ePGpxVAtFlUQxuoPx
         H7shWg1NxFYOFb4NW5CWreXVHkpINgvJUk2cfSLFWGfibY+/uerddhQfKxrQHj9NlNdh
         nTi0bebpbgGRUwnk2fn0SX18Y3S95k83P2GcNZvmOETkc3UhB3+qO1FdjlYIwuPhrjn0
         wRmu0Gcceqc9ksn8PbDiirWV+Nf94lEaqcX8MGKmdnswJ1xPHCmlllgC6igaRLI1zXev
         wJyHIePtBddPaPPE+jJ3JlY9iYszWhbTb8FJqWci7wdl5zkb6S6MsHGGMRNeZVFezosQ
         H67g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=4kYMyiO0i+h38Qow7/pAU93NuFwedjIDESI4JfwTgTo=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=bU0FtX5s1K1nTlos8+JA50tFxr2iKTuxP1w4llxFdzSRF6Su9JiUS2GTudAvWViaUh
         LJo69mnnTVj5XUqMzd0MtAMBCbYS/SLLg4vWQaap44q3fZEo0UYoUEQZnwbz3Ge1wnkx
         2SQRHwj1rLVjRfnD8EfxmEdQEiT77kEK+/dpDO50dPzVR+863fEvLDtguwZ44Y0f0/qK
         URvx0+pv6cIuijEx04Sgep7IUNuqctcxuNLA3YTjO+T37cZT4LC9YO2h7sBejkcd/Tx5
         H3IJCuflNsgTK+sITpLG0IgOVfuaoYzRdDRG351Fr98c0ql1cqHUgSRgpjvN1rXC17LD
         TutA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378d6694547si417861fa.2.2025.10.23.06.53.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id AD1382124D;
	Thu, 23 Oct 2025 13:53:01 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 8CD2913B0D;
	Thu, 23 Oct 2025 13:52:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 8PcTIjYz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:54 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:37 +0200
Subject: [PATCH RFC 15/19] slab: remove struct kmem_cache_cpu
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-15-6ffa2c9941c0@suse.cz>
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
X-Rspamd-Queue-Id: AD1382124D
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -4.00
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
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

The cpu slab is not used anymore for allocation or freeing, the
remaining code is for flushing, but it's effectively dead.  Remove the
whole struct kmem_cache_cpu, the flushing code and other orphaned
functions.

The remaining used field of kmem_cache_cpu is the stat array with
CONFIG_SLUB_STATS. Put it instead in a new struct kmem_cache_stats.
In struct kmem_cache, the field is cpu_stats and placed near the
end of the struct.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h |   7 +-
 mm/slub.c | 298 +++++---------------------------------------------------------
 2 files changed, 24 insertions(+), 281 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 7dde0b56a7b0..62db8a347edf 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -21,14 +21,12 @@
 # define system_has_freelist_aba()	system_has_cmpxchg128()
 # define try_cmpxchg_freelist		try_cmpxchg128
 # endif
-#define this_cpu_try_cmpxchg_freelist	this_cpu_try_cmpxchg128
 typedef u128 freelist_full_t;
 #else /* CONFIG_64BIT */
 # ifdef system_has_cmpxchg64
 # define system_has_freelist_aba()	system_has_cmpxchg64()
 # define try_cmpxchg_freelist		try_cmpxchg64
 # endif
-#define this_cpu_try_cmpxchg_freelist	this_cpu_try_cmpxchg64
 typedef u64 freelist_full_t;
 #endif /* CONFIG_64BIT */
 
@@ -207,7 +205,6 @@ struct kmem_cache_order_objects {
  * Slab cache management.
  */
 struct kmem_cache {
-	struct kmem_cache_cpu __percpu *cpu_slab;
 	struct slub_percpu_sheaves __percpu *cpu_sheaves;
 	/* Used for retrieving partial slabs, etc. */
 	slab_flags_t flags;
@@ -256,6 +253,10 @@ struct kmem_cache {
 	unsigned int usersize;		/* Usercopy region size */
 #endif
 
+#ifdef CONFIG_SLUB_STATS
+	struct kmem_cache_stats __percpu *cpu_stats;
+#endif
+
 	struct kmem_cache_node *node[MAX_NUMNODES];
 };
 
diff --git a/mm/slub.c b/mm/slub.c
index 6dd7fd153391..dcf28fc3a112 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -403,24 +403,11 @@ enum stat_item {
 	NR_SLUB_STAT_ITEMS
 };
 
-/*
- * When changing the layout, make sure freelist and tid are still compatible
- * with this_cpu_cmpxchg_double() alignment requirements.
- */
-struct kmem_cache_cpu {
-	union {
-		struct {
-			void **freelist;	/* Pointer to next available object */
-			unsigned long tid;	/* Globally unique transaction id */
-		};
-		freelist_aba_t freelist_tid;
-	};
-	struct slab *slab;	/* The slab from which we are allocating */
-	local_trylock_t lock;	/* Protects the fields above */
 #ifdef CONFIG_SLUB_STATS
+struct kmem_cache_stats {
 	unsigned int stat[NR_SLUB_STAT_ITEMS];
-#endif
 };
+#endif
 
 static inline void stat(const struct kmem_cache *s, enum stat_item si)
 {
@@ -429,7 +416,7 @@ static inline void stat(const struct kmem_cache *s, enum stat_item si)
 	 * The rmw is racy on a preemptible kernel but this is acceptable, so
 	 * avoid this_cpu_add()'s irq-disable overhead.
 	 */
-	raw_cpu_inc(s->cpu_slab->stat[si]);
+	raw_cpu_inc(s->cpu_stats->stat[si]);
 #endif
 }
 
@@ -437,7 +424,7 @@ static inline
 void stat_add(const struct kmem_cache *s, enum stat_item si, int v)
 {
 #ifdef CONFIG_SLUB_STATS
-	raw_cpu_add(s->cpu_slab->stat[si], v);
+	raw_cpu_add(s->cpu_stats->stat[si], v);
 #endif
 }
 
@@ -1158,20 +1145,6 @@ static void object_err(struct kmem_cache *s, struct slab *slab,
 	WARN_ON(1);
 }
 
-static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
-			       void **freelist, void *nextfree)
-{
-	if ((s->flags & SLAB_CONSISTENCY_CHECKS) &&
-	    !check_valid_pointer(s, slab, nextfree) && freelist) {
-		object_err(s, slab, *freelist, "Freechain corrupt");
-		*freelist = NULL;
-		slab_fix(s, "Isolate corrupted freechain");
-		return true;
-	}
-
-	return false;
-}
-
 static void __slab_err(struct slab *slab)
 {
 	if (slab_in_kunit_test())
@@ -1949,11 +1922,6 @@ static inline void inc_slabs_node(struct kmem_cache *s, int node,
 							int objects) {}
 static inline void dec_slabs_node(struct kmem_cache *s, int node,
 							int objects) {}
-static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
-			       void **freelist, void *nextfree)
-{
-	return false;
-}
 #endif /* CONFIG_SLUB_DEBUG */
 
 /*
@@ -3640,195 +3608,6 @@ static void *get_partial(struct kmem_cache *s, int node,
 	return get_any_partial(s, pc);
 }
 
-#ifdef CONFIG_PREEMPTION
-/*
- * Calculate the next globally unique transaction for disambiguation
- * during cmpxchg. The transactions start with the cpu number and are then
- * incremented by CONFIG_NR_CPUS.
- */
-#define TID_STEP  roundup_pow_of_two(CONFIG_NR_CPUS)
-#else
-/*
- * No preemption supported therefore also no need to check for
- * different cpus.
- */
-#define TID_STEP 1
-#endif /* CONFIG_PREEMPTION */
-
-static inline unsigned long next_tid(unsigned long tid)
-{
-	return tid + TID_STEP;
-}
-
-#ifdef SLUB_DEBUG_CMPXCHG
-static inline unsigned int tid_to_cpu(unsigned long tid)
-{
-	return tid % TID_STEP;
-}
-
-static inline unsigned long tid_to_event(unsigned long tid)
-{
-	return tid / TID_STEP;
-}
-#endif
-
-static inline unsigned int init_tid(int cpu)
-{
-	return cpu;
-}
-
-static void init_kmem_cache_cpus(struct kmem_cache *s)
-{
-	int cpu;
-	struct kmem_cache_cpu *c;
-
-	for_each_possible_cpu(cpu) {
-		c = per_cpu_ptr(s->cpu_slab, cpu);
-		local_trylock_init(&c->lock);
-		c->tid = init_tid(cpu);
-	}
-}
-
-/*
- * Finishes removing the cpu slab. Merges cpu's freelist with slab's freelist,
- * unfreezes the slabs and puts it on the proper list.
- * Assumes the slab has been already safely taken away from kmem_cache_cpu
- * by the caller.
- */
-static void deactivate_slab(struct kmem_cache *s, struct slab *slab,
-			    void *freelist)
-{
-	struct kmem_cache_node *n = get_node(s, slab_nid(slab));
-	int free_delta = 0;
-	void *nextfree, *freelist_iter, *freelist_tail;
-	int tail = DEACTIVATE_TO_HEAD;
-	unsigned long flags = 0;
-	struct slab new;
-	struct slab old;
-
-	if (READ_ONCE(slab->freelist)) {
-		stat(s, DEACTIVATE_REMOTE_FREES);
-		tail = DEACTIVATE_TO_TAIL;
-	}
-
-	/*
-	 * Stage one: Count the objects on cpu's freelist as free_delta and
-	 * remember the last object in freelist_tail for later splicing.
-	 */
-	freelist_tail = NULL;
-	freelist_iter = freelist;
-	while (freelist_iter) {
-		nextfree = get_freepointer(s, freelist_iter);
-
-		/*
-		 * If 'nextfree' is invalid, it is possible that the object at
-		 * 'freelist_iter' is already corrupted.  So isolate all objects
-		 * starting at 'freelist_iter' by skipping them.
-		 */
-		if (freelist_corrupted(s, slab, &freelist_iter, nextfree))
-			break;
-
-		freelist_tail = freelist_iter;
-		free_delta++;
-
-		freelist_iter = nextfree;
-	}
-
-	/*
-	 * Stage two: Unfreeze the slab while splicing the per-cpu
-	 * freelist to the head of slab's freelist.
-	 */
-	do {
-		old.freelist = READ_ONCE(slab->freelist);
-		old.counters = READ_ONCE(slab->counters);
-		VM_BUG_ON(!old.frozen);
-
-		/* Determine target state of the slab */
-		new.counters = old.counters;
-		new.frozen = 0;
-		if (freelist_tail) {
-			new.inuse -= free_delta;
-			set_freepointer(s, freelist_tail, old.freelist);
-			new.freelist = freelist;
-		} else {
-			new.freelist = old.freelist;
-		}
-	} while (!slab_update_freelist(s, slab,
-		old.freelist, old.counters,
-		new.freelist, new.counters,
-		"unfreezing slab"));
-
-	/*
-	 * Stage three: Manipulate the slab list based on the updated state.
-	 */
-	if (!new.inuse && n->nr_partial >= s->min_partial) {
-		stat(s, DEACTIVATE_EMPTY);
-		discard_slab(s, slab);
-		stat(s, FREE_SLAB);
-	} else if (new.freelist) {
-		spin_lock_irqsave(&n->list_lock, flags);
-		add_partial(n, slab, tail);
-		spin_unlock_irqrestore(&n->list_lock, flags);
-		stat(s, tail);
-	} else {
-		stat(s, DEACTIVATE_FULL);
-	}
-}
-
-static inline void flush_slab(struct kmem_cache *s, struct kmem_cache_cpu *c)
-{
-	unsigned long flags;
-	struct slab *slab;
-	void *freelist;
-
-	local_lock_irqsave(&s->cpu_slab->lock, flags);
-
-	slab = c->slab;
-	freelist = c->freelist;
-
-	c->slab = NULL;
-	c->freelist = NULL;
-	c->tid = next_tid(c->tid);
-
-	local_unlock_irqrestore(&s->cpu_slab->lock, flags);
-
-	if (slab) {
-		deactivate_slab(s, slab, freelist);
-		stat(s, CPUSLAB_FLUSH);
-	}
-}
-
-static inline void __flush_cpu_slab(struct kmem_cache *s, int cpu)
-{
-	struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab, cpu);
-	void *freelist = c->freelist;
-	struct slab *slab = c->slab;
-
-	c->slab = NULL;
-	c->freelist = NULL;
-	c->tid = next_tid(c->tid);
-
-	if (slab) {
-		deactivate_slab(s, slab, freelist);
-		stat(s, CPUSLAB_FLUSH);
-	}
-}
-
-static inline void flush_this_cpu_slab(struct kmem_cache *s)
-{
-	struct kmem_cache_cpu *c = this_cpu_ptr(s->cpu_slab);
-
-	if (c->slab)
-		flush_slab(s, c);
-}
-
-static bool has_cpu_slab(int cpu, struct kmem_cache *s)
-{
-	struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab, cpu);
-
-	return c->slab;
-}
-
 static bool has_pcs_used(int cpu, struct kmem_cache *s)
 {
 	struct slub_percpu_sheaves *pcs;
@@ -3842,7 +3621,7 @@ static bool has_pcs_used(int cpu, struct kmem_cache *s)
 }
 
 /*
- * Flush cpu slab.
+ * Flush percpu sheaves
  *
  * Called from CPU work handler with migration disabled.
  */
@@ -3857,8 +3636,6 @@ static void flush_cpu_slab(struct work_struct *w)
 
 	if (s->sheaf_capacity)
 		pcs_flush_all(s);
-
-	flush_this_cpu_slab(s);
 }
 
 static void flush_all_cpus_locked(struct kmem_cache *s)
@@ -3871,7 +3648,7 @@ static void flush_all_cpus_locked(struct kmem_cache *s)
 
 	for_each_online_cpu(cpu) {
 		sfw = &per_cpu(slub_flush, cpu);
-		if (!has_cpu_slab(cpu, s) && !has_pcs_used(cpu, s)) {
+		if (!has_pcs_used(cpu, s)) {
 			sfw->skip = true;
 			continue;
 		}
@@ -3976,7 +3753,6 @@ static int slub_cpu_dead(unsigned int cpu)
 
 	mutex_lock(&slab_mutex);
 	list_for_each_entry(s, &slab_caches, list) {
-		__flush_cpu_slab(s, cpu);
 		if (s->sheaf_capacity)
 			__pcs_flush_all_cpu(s, cpu);
 	}
@@ -7036,26 +6812,21 @@ init_kmem_cache_node(struct kmem_cache_node *n, struct node_barn *barn)
 		barn_init(barn);
 }
 
-static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
+#ifdef CONFIG_SLUB_STATS
+static inline int alloc_kmem_cache_stats(struct kmem_cache *s)
 {
 	BUILD_BUG_ON(PERCPU_DYNAMIC_EARLY_SIZE <
 			NR_KMALLOC_TYPES * KMALLOC_SHIFT_HIGH *
-			sizeof(struct kmem_cache_cpu));
+			sizeof(struct kmem_cache_stats));
 
-	/*
-	 * Must align to double word boundary for the double cmpxchg
-	 * instructions to work; see __pcpu_double_call_return_bool().
-	 */
-	s->cpu_slab = __alloc_percpu(sizeof(struct kmem_cache_cpu),
-				     2 * sizeof(void *));
+	s->cpu_stats = alloc_percpu(struct kmem_cache_stats);
 
-	if (!s->cpu_slab)
+	if (!s->cpu_stats)
 		return 0;
 
-	init_kmem_cache_cpus(s);
-
 	return 1;
 }
+#endif
 
 static int init_percpu_sheaves(struct kmem_cache *s)
 {
@@ -7166,7 +6937,9 @@ void __kmem_cache_release(struct kmem_cache *s)
 {
 	cache_random_seq_destroy(s);
 	pcs_destroy(s);
-	free_percpu(s->cpu_slab);
+#ifdef CONFIG_SLUB_STATS
+	free_percpu(s->cpu_stats);
+#endif
 	free_kmem_cache_nodes(s);
 }
 
@@ -7847,12 +7620,6 @@ static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
 
 	memcpy(s, static_cache, kmem_cache->object_size);
 
-	/*
-	 * This runs very early, and only the boot processor is supposed to be
-	 * up.  Even if it weren't true, IRQs are not up so we couldn't fire
-	 * IPIs around.
-	 */
-	__flush_cpu_slab(s, smp_processor_id());
 	for_each_kmem_cache_node(s, node, n) {
 		struct slab *p;
 
@@ -8092,8 +7859,10 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 	if (!init_kmem_cache_nodes(s))
 		goto out;
 
-	if (!alloc_kmem_cache_cpus(s))
+#ifdef CONFIG_SLUB_STATS
+	if (!alloc_kmem_cache_stats(s))
 		goto out;
+#endif
 
 	err = init_percpu_sheaves(s);
 	if (err)
@@ -8412,33 +8181,6 @@ static ssize_t show_slab_objects(struct kmem_cache *s,
 	if (!nodes)
 		return -ENOMEM;
 
-	if (flags & SO_CPU) {
-		int cpu;
-
-		for_each_possible_cpu(cpu) {
-			struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab,
-							       cpu);
-			int node;
-			struct slab *slab;
-
-			slab = READ_ONCE(c->slab);
-			if (!slab)
-				continue;
-
-			node = slab_nid(slab);
-			if (flags & SO_TOTAL)
-				x = slab->objects;
-			else if (flags & SO_OBJECTS)
-				x = slab->inuse;
-			else
-				x = 1;
-
-			total += x;
-			nodes[node] += x;
-
-		}
-	}
-
 	/*
 	 * It is impossible to take "mem_hotplug_lock" here with "kernfs_mutex"
 	 * already held which will conflict with an existing lock order:
@@ -8809,7 +8551,7 @@ static int show_stat(struct kmem_cache *s, char *buf, enum stat_item si)
 		return -ENOMEM;
 
 	for_each_online_cpu(cpu) {
-		unsigned x = per_cpu_ptr(s->cpu_slab, cpu)->stat[si];
+		unsigned x = per_cpu_ptr(s->cpu_stats, cpu)->stat[si];
 
 		data[cpu] = x;
 		sum += x;
@@ -8835,7 +8577,7 @@ static void clear_stat(struct kmem_cache *s, enum stat_item si)
 	int cpu;
 
 	for_each_online_cpu(cpu)
-		per_cpu_ptr(s->cpu_slab, cpu)->stat[si] = 0;
+		per_cpu_ptr(s->cpu_stats, cpu)->stat[si] = 0;
 }
 
 #define STAT_ATTR(si, text) 					\

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-15-6ffa2c9941c0%40suse.cz.

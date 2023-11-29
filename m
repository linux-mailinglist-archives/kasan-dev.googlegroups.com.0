Return-Path: <kasan-dev+bncBAABBVUVTSVQMGQESOO3BAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id A76A57FD356
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 10:56:39 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-41e3e4aa311sf87279911cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 01:56:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701251798; cv=pass;
        d=google.com; s=arc-20160816;
        b=dpo27MWEAXIugNlulPdodkJh/PayvVy2+63EXsjq+rcfDuNoaphdfihdIS6Cp7aw/W
         u+1HhV3soF6fg+WQwFifCxynCobT3lsMkVG0hgR+LcKHEvVzanDUw2lsjOfbUJw0DhZW
         4GcPuYKr4IWXu96keLieJbjSdGHbVR+Bzy6WNTruSJHUmvXfx12R/btDgj0p04KaKBP/
         pjkLscqOd+fYboOPmS4ypEacVM5htn3rFSrtYBcJw/61R1WZrZkyopIy7s0t5s2lsL2m
         RqKgoEHisbGhKORnlkcK3D7zzKiDSsnlsE9ef24uVbXRrIHYMjqGrTdxOk5/KPhtXj0U
         MytQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=M7C7u29j2NRt563Zgn+KDRLU4KOWre/cVW3TdHxjwAo=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=VCqqN1l723AfYecOeK5BZC4qTUSSQt20BBJaUzlwUWDdHlKe5Oake7ZCXV9JIbQfNO
         0b1R0cbHdgqGc2MtN12WzhQuYSXy837xJQa+gUU73W0AGTSnAzeyihyr/PhrbFCylu5f
         PmA1G0G6x/DgQ+CnmMADe3pDuVwfELGdBO1YQDQ3rgw9Jp273+F4Ot/M0ekjvP/GLine
         dU+ArWPGXcHZx1EDw7lMHR/grxULu/1M2tkXOiDHeicCnSk+B6X1ipKjcU3mgXpXCOSQ
         6FLcneDwpMd7IkgZmtDXTMrLMZO6iEjA/B6/QqUDvEo7zhK+ztwHVlunxVv/v1Jj1Ld8
         IagA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701251798; x=1701856598; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=M7C7u29j2NRt563Zgn+KDRLU4KOWre/cVW3TdHxjwAo=;
        b=DuzcWzdSPKg47Gd7AP3y4NrM3RSYoqbDXomMYwOghbhkJ/wCcxzaV27nEpZQ09/tkw
         cvMAo9Ih9qwM5MdY0ETYNsRXOD33c1DG1NOf3KwdBx+B4xo71wONvMCpV68URMuwwyDz
         VTIc+5wDaACjeCye6V8zxfO6HeiWOpd6S4fTTY0kxV0wgXNOF2sSosOLxMVPjizWWprF
         HCACy74r+zaRBb+HT7qUvv63aLS6G1Y+qE7C+ibJWLkrKXiharGH7ZRLLOg8b8sx69NN
         9WTXjJL/Go56Xo5xDlZWA+FFlAHf3GwnFRijiXyLw/ZIAqBMYfi+GhzE0ruSJlxFXz2r
         aC3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701251798; x=1701856598;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=M7C7u29j2NRt563Zgn+KDRLU4KOWre/cVW3TdHxjwAo=;
        b=JLGucKP/nPEQGHZEAqCzP85ibKe330NxrtOG3x/s+0KYtENvQzYU4yD3Cs5HNGWWmK
         YqJuBswX5CdqgEx0Rd2iR0Ua1slMXYq/vl3J63CtDHAQrP/VyOo+BJ+NGPtbRg7qMsBk
         ZnwX/h/TD7crQPrGKXUGS1m2wibZg0hPTnU5j1y7gCAfve5TrxcSF0XfL1bCiJm1g3Ee
         jygpqB7VNqTBb/wJvVises0vayzvL8HZjNEyQMM7siJ3ZavDy7UWX6EBJIe1xUQYx+3q
         19eZHxNi5Al0GzhaPk6TUwMxFPHIhlUg8LJzVGKe1UjabasxIDs8bMP2l4Z84T8JBXhs
         adDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyehmTyPaUl/GX5QrY3sGkHZ9ZfzqjQRzvI5KVw2+W/xuY3wbdb
	/x0iyTcIbkG5m8bhnPPACg0=
X-Google-Smtp-Source: AGHT+IGtUUPhY6RjeLVtSIyUTRLMAYHou5+G+A87DKhMP8HM2XDSroLAYezJF46zfAhjKCiwDrhBhA==
X-Received: by 2002:a05:622a:5505:b0:423:a7b2:415 with SMTP id fj5-20020a05622a550500b00423a7b20415mr15068578qtb.38.1701251798531;
        Wed, 29 Nov 2023 01:56:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1009:b0:421:c71a:9295 with SMTP id
 d9-20020a05622a100900b00421c71a9295ls1335502qte.0.-pod-prod-01-us; Wed, 29
 Nov 2023 01:56:38 -0800 (PST)
X-Received: by 2002:ac8:1402:0:b0:423:70a0:6137 with SMTP id k2-20020ac81402000000b0042370a06137mr488485qtj.3.1701251798140;
        Wed, 29 Nov 2023 01:56:38 -0800 (PST)
Received: by 2002:a05:620a:8ec3:b0:77d:cfff:33fb with SMTP id af79cd13be357-77dcfff3957ms85a;
        Wed, 29 Nov 2023 01:53:40 -0800 (PST)
X-Received: by 2002:a05:600c:4f13:b0:40b:3d6e:16b7 with SMTP id l19-20020a05600c4f1300b0040b3d6e16b7mr9062989wmq.33.1701251618666;
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701251618; cv=none;
        d=google.com; s=arc-20160816;
        b=lji0efsZ1/gjf7TUWSPdBRq4LrG0qSUypLOjlADjSF0EoX6MXeNBmORdyBlkw3cyWf
         t42xjJ65puvziUs1S4xiGFoY+PgLNQ5oFSmAAYiw0vh3jw5q+GzfnonGwve9E+XYifOq
         NQZJC/dNqgLHti78jTfu7qUNK3NuMpspSYObpqdIJaHzpPohT1cUkjNbDvn6bZNUSosX
         4oPDsc3RCcVsfDp0vfFXnKSms/Mn0kpxhgHWPKGO+HqtTSWpYSX4+kRNVjcPqK8X1RW8
         K77C+1ZXwzHUn1DXmGIjiWLSsSksJaGymgL9Y5IOO2OR0SSFdrf2gN8+71wKxaTaYSMN
         eUYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=mCZNnnAgtZ9BCKVsGZOHUXKdRtd+yAwyaxi7IiapAks=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=ZHXc5PXdd++WsXzyolSzFohxXMt99uVJTgTbwwx218MXRfF4rcHP3HKERnVY3kGYhu
         LJO3BwTRw59rbYMQ4SSbYczCNfQeweGza5QITcs55knE/50w3o49GdxmDfBNGMao5ASW
         uiHm8MaLn2+ycCTeb+v8nRSu0zqraca1MSVTLK2KlcnR3F9k7NLnUKWBUL20TUAS5bU7
         r3xPMGE8he7aQHCyUp7lWbss06nBHFO+mS0DZNEkQHaZYhyYQuI0fJ7jeh8/OgIGrIwm
         Fxc3cDsu+nYKrZ773J7C1GsVIMPciCOG6v9ap1cTmfJtzEMBbWaJKQzyTUJO4FmxNc5p
         vb5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id p7-20020a05600c1d8700b0040a25ec1cfesi70761wms.0.2023.11.29.01.53.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E262721992;
	Wed, 29 Nov 2023 09:53:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 3E5FA13A9B;
	Wed, 29 Nov 2023 09:53:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id yPPuDiEKZ2UrfQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Nov 2023 09:53:37 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 29 Nov 2023 10:53:30 +0100
Subject: [PATCH RFC v3 5/9] mm/slub: add opt-in percpu array cache of
 objects
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231129-slub-percpu-caches-v3-5-6bcf536772bc@suse.cz>
References: <20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz>
In-Reply-To: <20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz>
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
 Matthew Wilcox <willy@infradead.org>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, maple-tree@lists.infradead.org, 
 kasan-dev@googlegroups.com, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Level: 
X-Rspamd-Server: rspamd1
X-Rspamd-Queue-Id: E262721992
X-Spam-Score: -4.00
X-Spam-Flag: NO
X-Spamd-Result: default: False [-4.00 / 50.00];
	 TAGGED_RCPT(0.00)[];
	 REPLY(-4.00)[]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

kmem_cache_setup_percpu_array() will allocate a per-cpu array for
caching alloc/free objects of given size for the cache. The cache
has to be created with SLAB_NO_MERGE flag.

When empty, half of the array is filled by an internal bulk alloc
operation. When full, half of the array is flushed by an internal bulk
free operation.

The array does not distinguish NUMA locality of the cached objects. If
an allocation is requested with kmem_cache_alloc_node() with numa node
not equal to NUMA_NO_NODE, the array is bypassed.

The bulk operations exposed to slab users also try to utilize the array
when possible, but leave the array empty or full and use the bulk
alloc/free only to finish the operation itself. If kmemcg is enabled and
active, bulk freeing skips the array completely as it would be less
efficient to use it.

The locking scheme is copied from the page allocator's pcplists, based
on embedded spin locks. Interrupts are not disabled, only preemption
(cpu migration on RT). Trylock is attempted to avoid deadlock due to an
interrupt; trylock failure means the array is bypassed.

Sysfs stat counters alloc_cpu_cache and free_cpu_cache count objects
allocated or freed using the percpu array; counters cpu_cache_refill and
cpu_cache_flush count objects refilled or flushed form the array.

kmem_cache_prefill_percpu_array() can be called to ensure the array on
the current cpu to at least the given number of objects. However this is
only opportunistic as there's no cpu pinning between the prefill and
usage, and trylocks may fail when the usage is in an irq handler.
Therefore allocations cannot rely on the array for success even after
the prefill. But misses should be rare enough that e.g. GFP_ATOMIC
allocations should be acceptable after the refill.

When slub_debug is enabled for a cache with percpu array, the objects in
the array are considered as allocated from the slub_debug perspective,
and the alloc/free debugging hooks occur when moving the objects between
the array and slab pages. This means that e.g. an use-after-free that
occurs for an object cached in the array is undetected. Collected
alloc/free stacktraces might also be less useful. This limitation could
be changed in the future.

On the other hand, KASAN, kmemcg and other hooks are executed on actual
allocations and frees by kmem_cache users even if those use the array,
so their debugging or accounting accuracy should be unaffected.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slab.h     |   4 +
 include/linux/slub_def.h |  12 ++
 mm/Kconfig               |   1 +
 mm/slub.c                | 457 ++++++++++++++++++++++++++++++++++++++++++++++-
 4 files changed, 468 insertions(+), 6 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index d6d6ffeeb9a2..fe0c0981be59 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -197,6 +197,8 @@ struct kmem_cache *kmem_cache_create_usercopy(const char *name,
 void kmem_cache_destroy(struct kmem_cache *s);
 int kmem_cache_shrink(struct kmem_cache *s);
 
+int kmem_cache_setup_percpu_array(struct kmem_cache *s, unsigned int count);
+
 /*
  * Please use this macro to create slab caches. Simply specify the
  * name of the structure and maybe some flags that are listed above.
@@ -512,6 +514,8 @@ void kmem_cache_free(struct kmem_cache *s, void *objp);
 void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p);
 int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size, void **p);
 
+int kmem_cache_prefill_percpu_array(struct kmem_cache *s, unsigned int count, gfp_t gfp);
+
 static __always_inline void kfree_bulk(size_t size, void **p)
 {
 	kmem_cache_free_bulk(NULL, size, p);
diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
index deb90cf4bffb..2083aa849766 100644
--- a/include/linux/slub_def.h
+++ b/include/linux/slub_def.h
@@ -13,8 +13,10 @@
 #include <linux/local_lock.h>
 
 enum stat_item {
+	ALLOC_PCA,		/* Allocation from percpu array cache */
 	ALLOC_FASTPATH,		/* Allocation from cpu slab */
 	ALLOC_SLOWPATH,		/* Allocation by getting a new cpu slab */
+	FREE_PCA,		/* Free to percpu array cache */
 	FREE_FASTPATH,		/* Free to cpu slab */
 	FREE_SLOWPATH,		/* Freeing not to cpu slab */
 	FREE_FROZEN,		/* Freeing to frozen slab */
@@ -39,6 +41,8 @@ enum stat_item {
 	CPU_PARTIAL_FREE,	/* Refill cpu partial on free */
 	CPU_PARTIAL_NODE,	/* Refill cpu partial from node partial */
 	CPU_PARTIAL_DRAIN,	/* Drain cpu partial to node partial */
+	PCA_REFILL,		/* Refilling empty percpu array cache */
+	PCA_FLUSH,		/* Flushing full percpu array cache */
 	NR_SLUB_STAT_ITEMS
 };
 
@@ -66,6 +70,13 @@ struct kmem_cache_cpu {
 };
 #endif /* CONFIG_SLUB_TINY */
 
+struct slub_percpu_array {
+	spinlock_t lock;
+	unsigned int count;
+	unsigned int used;
+	void * objects[];
+};
+
 #ifdef CONFIG_SLUB_CPU_PARTIAL
 #define slub_percpu_partial(c)		((c)->partial)
 
@@ -99,6 +110,7 @@ struct kmem_cache {
 #ifndef CONFIG_SLUB_TINY
 	struct kmem_cache_cpu __percpu *cpu_slab;
 #endif
+	struct slub_percpu_array __percpu *cpu_array;
 	/* Used for retrieving partial slabs, etc. */
 	slab_flags_t flags;
 	unsigned long min_partial;
diff --git a/mm/Kconfig b/mm/Kconfig
index 89971a894b60..aa53c51bb4a6 100644
--- a/mm/Kconfig
+++ b/mm/Kconfig
@@ -237,6 +237,7 @@ choice
 config SLAB_DEPRECATED
 	bool "SLAB (DEPRECATED)"
 	depends on !PREEMPT_RT
+	depends on BROKEN
 	help
 	  Deprecated and scheduled for removal in a few cycles. Replaced by
 	  SLUB.
diff --git a/mm/slub.c b/mm/slub.c
index 59912a376c6d..f08bd71c244f 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -188,6 +188,79 @@ do {					\
 #define USE_LOCKLESS_FAST_PATH()	(false)
 #endif
 
+/* copy/pasted  from mm/page_alloc.c */
+
+#if defined(CONFIG_SMP) || defined(CONFIG_PREEMPT_RT)
+/*
+ * On SMP, spin_trylock is sufficient protection.
+ * On PREEMPT_RT, spin_trylock is equivalent on both SMP and UP.
+ */
+#define pcp_trylock_prepare(flags)	do { } while (0)
+#define pcp_trylock_finish(flag)	do { } while (0)
+#else
+
+/* UP spin_trylock always succeeds so disable IRQs to prevent re-entrancy. */
+#define pcp_trylock_prepare(flags)	local_irq_save(flags)
+#define pcp_trylock_finish(flags)	local_irq_restore(flags)
+#endif
+
+/*
+ * Locking a pcp requires a PCP lookup followed by a spinlock. To avoid
+ * a migration causing the wrong PCP to be locked and remote memory being
+ * potentially allocated, pin the task to the CPU for the lookup+lock.
+ * preempt_disable is used on !RT because it is faster than migrate_disable.
+ * migrate_disable is used on RT because otherwise RT spinlock usage is
+ * interfered with and a high priority task cannot preempt the allocator.
+ */
+#ifndef CONFIG_PREEMPT_RT
+#define pcpu_task_pin()		preempt_disable()
+#define pcpu_task_unpin()	preempt_enable()
+#else
+#define pcpu_task_pin()		migrate_disable()
+#define pcpu_task_unpin()	migrate_enable()
+#endif
+
+/*
+ * Generic helper to lookup and a per-cpu variable with an embedded spinlock.
+ * Return value should be used with equivalent unlock helper.
+ */
+#define pcpu_spin_lock(type, member, ptr)				\
+({									\
+	type *_ret;							\
+	pcpu_task_pin();						\
+	_ret = this_cpu_ptr(ptr);					\
+	spin_lock(&_ret->member);					\
+	_ret;								\
+})
+
+#define pcpu_spin_trylock(type, member, ptr)				\
+({									\
+	type *_ret;							\
+	pcpu_task_pin();						\
+	_ret = this_cpu_ptr(ptr);					\
+	if (!spin_trylock(&_ret->member)) {				\
+		pcpu_task_unpin();					\
+		_ret = NULL;						\
+	}								\
+	_ret;								\
+})
+
+#define pcpu_spin_unlock(member, ptr)					\
+({									\
+	spin_unlock(&ptr->member);					\
+	pcpu_task_unpin();						\
+})
+
+/* struct slub_percpu_array specific helpers. */
+#define pca_spin_lock(ptr)						\
+	pcpu_spin_lock(struct slub_percpu_array, lock, ptr)
+
+#define pca_spin_trylock(ptr)						\
+	pcpu_spin_trylock(struct slub_percpu_array, lock, ptr)
+
+#define pca_spin_unlock(ptr)						\
+	pcpu_spin_unlock(lock, ptr)
+
 #ifndef CONFIG_SLUB_TINY
 #define __fastpath_inline __always_inline
 #else
@@ -3454,6 +3527,78 @@ static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
 			0, sizeof(void *));
 }
 
+static bool refill_pca(struct kmem_cache *s, unsigned int count, gfp_t gfp);
+
+static __fastpath_inline
+void *alloc_from_pca(struct kmem_cache *s, gfp_t gfp)
+{
+	unsigned long __maybe_unused UP_flags;
+	struct slub_percpu_array *pca;
+	void *object;
+
+retry:
+	pcp_trylock_prepare(UP_flags);
+	pca = pca_spin_trylock(s->cpu_array);
+
+	if (unlikely(!pca)) {
+		pcp_trylock_finish(UP_flags);
+		return NULL;
+	}
+
+	if (unlikely(pca->used == 0)) {
+		unsigned int batch = pca->count / 2;
+
+		pca_spin_unlock(pca);
+		pcp_trylock_finish(UP_flags);
+
+		if (!gfpflags_allow_blocking(gfp) || in_irq())
+			return NULL;
+
+		if (refill_pca(s, batch, gfp))
+			goto retry;
+
+		return NULL;
+	}
+
+	object = pca->objects[--pca->used];
+
+	pca_spin_unlock(pca);
+	pcp_trylock_finish(UP_flags);
+
+	stat(s, ALLOC_PCA);
+
+	return object;
+}
+
+static __fastpath_inline
+int alloc_from_pca_bulk(struct kmem_cache *s, size_t size, void **p)
+{
+	unsigned long __maybe_unused UP_flags;
+	struct slub_percpu_array *pca;
+
+	pcp_trylock_prepare(UP_flags);
+	pca = pca_spin_trylock(s->cpu_array);
+
+	if (unlikely(!pca)) {
+		size = 0;
+		goto failed;
+	}
+
+	if (pca->used < size)
+		size = pca->used;
+
+	for (int i = size; i > 0;) {
+		p[--i] = pca->objects[--pca->used];
+	}
+
+	pca_spin_unlock(pca);
+	stat_add(s, ALLOC_PCA, size);
+
+failed:
+	pcp_trylock_finish(UP_flags);
+	return size;
+}
+
 /*
  * Inlined fastpath so that allocation functions (kmalloc, kmem_cache_alloc)
  * have the fastpath folded into their functions. So no function call
@@ -3479,7 +3624,11 @@ static __fastpath_inline void *slab_alloc_node(struct kmem_cache *s, struct list
 	if (unlikely(object))
 		goto out;
 
-	object = __slab_alloc_node(s, gfpflags, node, addr, orig_size);
+	if (s->cpu_array && (node == NUMA_NO_NODE))
+		object = alloc_from_pca(s, gfpflags);
+
+	if (!object)
+		object = __slab_alloc_node(s, gfpflags, node, addr, orig_size);
 
 	maybe_wipe_obj_freeptr(s, object);
 	init = slab_want_init_on_alloc(gfpflags, s);
@@ -3726,6 +3875,81 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 	discard_slab(s, slab);
 }
 
+static bool flush_pca(struct kmem_cache *s, unsigned int count);
+
+static __fastpath_inline
+bool free_to_pca(struct kmem_cache *s, void *object)
+{
+	unsigned long __maybe_unused UP_flags;
+	struct slub_percpu_array *pca;
+
+retry:
+	pcp_trylock_prepare(UP_flags);
+	pca = pca_spin_trylock(s->cpu_array);
+
+	if (!pca) {
+		pcp_trylock_finish(UP_flags);
+		return false;
+	}
+
+	if (pca->used == pca->count) {
+		unsigned int batch = pca->count / 2;
+
+		pca_spin_unlock(pca);
+		pcp_trylock_finish(UP_flags);
+
+		if (in_irq())
+			return false;
+
+		if (!flush_pca(s, batch))
+			return false;
+
+		goto retry;
+	}
+
+	pca->objects[pca->used++] = object;
+
+	pca_spin_unlock(pca);
+	pcp_trylock_finish(UP_flags);
+
+	stat(s, FREE_PCA);
+
+	return true;
+}
+
+static __fastpath_inline
+size_t free_to_pca_bulk(struct kmem_cache *s, size_t size, void **p)
+{
+	unsigned long __maybe_unused UP_flags;
+	struct slub_percpu_array *pca;
+	bool init;
+
+	pcp_trylock_prepare(UP_flags);
+	pca = pca_spin_trylock(s->cpu_array);
+
+	if (unlikely(!pca)) {
+		size = 0;
+		goto failed;
+	}
+
+	if (pca->count - pca->used < size)
+		size = pca->count - pca->used;
+
+	init = slab_want_init_on_free(s);
+
+	for (size_t i = 0; i < size; i++) {
+		if (likely(slab_free_hook(s, p[i], init)))
+			pca->objects[pca->used++] = p[i];
+	}
+
+	pca_spin_unlock(pca);
+	stat_add(s, FREE_PCA, size);
+
+failed:
+	pcp_trylock_finish(UP_flags);
+	return size;
+}
+
 #ifndef CONFIG_SLUB_TINY
 /*
  * Fastpath with forced inlining to produce a kfree and kmem_cache_free that
@@ -3811,7 +4035,12 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 {
 	memcg_slab_free_hook(s, slab, &object, 1);
 
-	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
+	if (unlikely(!slab_free_hook(s, object, slab_want_init_on_free(s))))
+		return;
+
+	if (s->cpu_array)
+		free_to_pca(s, object);
+	else
 		do_slab_free(s, slab, object, object, 1, addr);
 }
 
@@ -3956,6 +4185,26 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 	if (!size)
 		return;
 
+	/*
+	 * In case the objects might need memcg_slab_free_hook(), skip the array
+	 * because the hook is not effective with single objects and benefits
+	 * from groups of objects from a single slab that the detached freelist
+	 * builds. But once we build the detached freelist, it's wasteful to
+	 * throw it away and put the objects into the array.
+	 *
+	 * XXX: This test could be cache-specific if it was not possible to use
+	 * __GFP_ACCOUNT with caches that are not SLAB_ACCOUNT
+	 */
+	if (s && s->cpu_array && !memcg_kmem_online()) {
+		size_t pca_freed = free_to_pca_bulk(s, size, p);
+
+		if (pca_freed == size)
+			return;
+
+		p += pca_freed;
+		size -= pca_freed;
+	}
+
 	do {
 		struct detached_freelist df;
 
@@ -4073,7 +4322,8 @@ static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
 int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 			  void **p)
 {
-	int i;
+	int from_pca = 0;
+	int allocated = 0;
 	struct obj_cgroup *objcg = NULL;
 
 	if (!size)
@@ -4084,19 +4334,147 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	if (unlikely(!s))
 		return 0;
 
-	i = __kmem_cache_alloc_bulk(s, flags, size, p);
+	if (s->cpu_array)
+		from_pca = alloc_from_pca_bulk(s, size, p);
+
+	if (from_pca < size) {
+		allocated = __kmem_cache_alloc_bulk(s, flags, size-from_pca,
+						    p+from_pca);
+		if (allocated == 0 && from_pca > 0) {
+			__kmem_cache_free_bulk(s, from_pca, p);
+		}
+	}
+
+	allocated += from_pca;
 
 	/*
 	 * memcg and kmem_cache debug support and memory initialization.
 	 * Done outside of the IRQ disabled fastpath loop.
 	 */
-	if (i != 0)
+	if (allocated != 0)
 		slab_post_alloc_hook(s, objcg, flags, size, p,
 			slab_want_init_on_alloc(flags, s), s->object_size);
-	return i;
+	return allocated;
 }
 EXPORT_SYMBOL(kmem_cache_alloc_bulk);
 
+static bool refill_pca(struct kmem_cache *s, unsigned int count, gfp_t gfp)
+{
+	void *objects[32];
+	unsigned int batch, allocated;
+	unsigned long __maybe_unused UP_flags;
+	struct slub_percpu_array *pca;
+
+bulk_alloc:
+	batch = min(count, 32U);
+
+	allocated = __kmem_cache_alloc_bulk(s, gfp, batch, &objects[0]);
+	if (!allocated)
+		return false;
+
+	pcp_trylock_prepare(UP_flags);
+	pca = pca_spin_trylock(s->cpu_array);
+	if (!pca) {
+		pcp_trylock_finish(UP_flags);
+		return false;
+	}
+
+	batch = min(allocated, pca->count - pca->used);
+
+	for (unsigned int i = 0; i < batch; i++) {
+		pca->objects[pca->used++] = objects[i];
+	}
+
+	pca_spin_unlock(pca);
+	pcp_trylock_finish(UP_flags);
+
+	stat_add(s, PCA_REFILL, batch);
+
+	/*
+	 * We could have migrated to a different cpu or somebody else freed to the
+	 * pca while we were bulk allocating, and now we have too many objects
+	 */
+	if (batch < allocated) {
+		__kmem_cache_free_bulk(s, allocated - batch, &objects[batch]);
+	} else {
+		count -= batch;
+		if (count > 0)
+			goto bulk_alloc;
+	}
+
+	return true;
+}
+
+static bool flush_pca(struct kmem_cache *s, unsigned int count)
+{
+	void *objects[32];
+	unsigned int batch, remaining;
+	unsigned long __maybe_unused UP_flags;
+	struct slub_percpu_array *pca;
+
+next_batch:
+	batch = min(count, 32);
+
+	pcp_trylock_prepare(UP_flags);
+	pca = pca_spin_trylock(s->cpu_array);
+	if (!pca) {
+		pcp_trylock_finish(UP_flags);
+		return false;
+	}
+
+	batch = min(batch, pca->used);
+
+	for (unsigned int i = 0; i < batch; i++) {
+		objects[i] = pca->objects[--pca->used];
+	}
+
+	remaining = pca->used;
+
+	pca_spin_unlock(pca);
+	pcp_trylock_finish(UP_flags);
+
+	__kmem_cache_free_bulk(s, batch, &objects[0]);
+
+	stat_add(s, PCA_FLUSH, batch);
+
+	if (batch < count && remaining > 0) {
+		count -= batch;
+		goto next_batch;
+	}
+
+	return true;
+}
+
+/* Do not call from irq handler nor with irqs disabled */
+int kmem_cache_prefill_percpu_array(struct kmem_cache *s, unsigned int count,
+				    gfp_t gfp)
+{
+	struct slub_percpu_array *pca;
+	unsigned int used;
+
+	lockdep_assert_no_hardirq();
+
+	if (!s->cpu_array)
+		return -EINVAL;
+
+	/* racy but we don't care */
+	pca = raw_cpu_ptr(s->cpu_array);
+
+	used = READ_ONCE(pca->used);
+
+	if (used >= count)
+		return 0;
+
+	if (pca->count < count)
+		return -EINVAL;
+
+	count -= used;
+
+	if (!refill_pca(s, count, gfp))
+		return -ENOMEM;
+
+	return 0;
+}
 
 /*
  * Object placement in a slab is made very easy because we always start at
@@ -5167,6 +5545,65 @@ int __kmem_cache_create(struct kmem_cache *s, slab_flags_t flags)
 	return 0;
 }
 
+/**
+ * kmem_cache_setup_percpu_array - Create a per-cpu array cache for the cache
+ * @s: The cache to add per-cpu array. Must be created with SLAB_NO_MERGE flag.
+ * @count: Size of the per-cpu array.
+ *
+ * After this call, allocations from the cache go through a percpu array. When
+ * it becomes empty, half is refilled with a bulk allocation. When it becomes
+ * full, half is flushed with a bulk free operation.
+ *
+ * Using the array cache is not guaranteed, i.e. it can be bypassed if its lock
+ * cannot be obtained. The array cache also does not distinguish NUMA nodes, so
+ * allocations via kmem_cache_alloc_node() with a node specified other than
+ * NUMA_NO_NODE will bypass the cache.
+ *
+ * Bulk allocation and free operations also try to use the array.
+ *
+ * kmem_cache_prefill_percpu_array() can be used to pre-fill the array cache
+ * before e.g. entering a restricted context. It is however not guaranteed that
+ * the caller will be able to subsequently consume the prefilled cache. Such
+ * failures should be however sufficiently rare so after the prefill,
+ * allocations using GFP_ATOMIC | __GFP_NOFAIL are acceptable for objects up to
+ * the prefilled amount.
+ *
+ * Limitations: when slub_debug is enabled for the cache, all relevant actions
+ * (i.e. poisoning, obtaining stacktraces) and checks happen when objects move
+ * between the array cache and slab pages, which may result in e.g. not
+ * detecting a use-after-free while the object is in the array cache, and the
+ * stacktraces may be less useful.
+ *
+ * Return: 0 if OK, -EINVAL on caches without SLAB_NO_MERGE or with the array
+ * already created, -ENOMEM when the per-cpu array creation fails.
+ */
+int kmem_cache_setup_percpu_array(struct kmem_cache *s, unsigned int count)
+{
+	int cpu;
+
+	if (WARN_ON_ONCE(!(s->flags & SLAB_NO_MERGE)))
+		return -EINVAL;
+
+	if (s->cpu_array)
+		return -EINVAL;
+
+	s->cpu_array = __alloc_percpu(struct_size(s->cpu_array, objects, count),
+					sizeof(void *));
+
+	if (!s->cpu_array)
+		return -ENOMEM;
+
+	for_each_possible_cpu(cpu) {
+		struct slub_percpu_array *pca = per_cpu_ptr(s->cpu_array, cpu);
+
+		spin_lock_init(&pca->lock);
+		pca->count = count;
+		pca->used = 0;
+	}
+
+	return 0;
+}
+
 #ifdef SLAB_SUPPORTS_SYSFS
 static int count_inuse(struct slab *slab)
 {
@@ -5944,8 +6381,10 @@ static ssize_t text##_store(struct kmem_cache *s,		\
 }								\
 SLAB_ATTR(text);						\
 
+STAT_ATTR(ALLOC_PCA, alloc_cpu_cache);
 STAT_ATTR(ALLOC_FASTPATH, alloc_fastpath);
 STAT_ATTR(ALLOC_SLOWPATH, alloc_slowpath);
+STAT_ATTR(FREE_PCA, free_cpu_cache);
 STAT_ATTR(FREE_FASTPATH, free_fastpath);
 STAT_ATTR(FREE_SLOWPATH, free_slowpath);
 STAT_ATTR(FREE_FROZEN, free_frozen);
@@ -5970,6 +6409,8 @@ STAT_ATTR(CPU_PARTIAL_ALLOC, cpu_partial_alloc);
 STAT_ATTR(CPU_PARTIAL_FREE, cpu_partial_free);
 STAT_ATTR(CPU_PARTIAL_NODE, cpu_partial_node);
 STAT_ATTR(CPU_PARTIAL_DRAIN, cpu_partial_drain);
+STAT_ATTR(PCA_REFILL, cpu_cache_refill);
+STAT_ATTR(PCA_FLUSH, cpu_cache_flush);
 #endif	/* CONFIG_SLUB_STATS */
 
 #ifdef CONFIG_KFENCE
@@ -6031,8 +6472,10 @@ static struct attribute *slab_attrs[] = {
 	&remote_node_defrag_ratio_attr.attr,
 #endif
 #ifdef CONFIG_SLUB_STATS
+	&alloc_cpu_cache_attr.attr,
 	&alloc_fastpath_attr.attr,
 	&alloc_slowpath_attr.attr,
+	&free_cpu_cache_attr.attr,
 	&free_fastpath_attr.attr,
 	&free_slowpath_attr.attr,
 	&free_frozen_attr.attr,
@@ -6057,6 +6500,8 @@ static struct attribute *slab_attrs[] = {
 	&cpu_partial_free_attr.attr,
 	&cpu_partial_node_attr.attr,
 	&cpu_partial_drain_attr.attr,
+	&cpu_cache_refill_attr.attr,
+	&cpu_cache_flush_attr.attr,
 #endif
 #ifdef CONFIG_FAILSLAB
 	&failslab_attr.attr,

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231129-slub-percpu-caches-v3-5-6bcf536772bc%40suse.cz.

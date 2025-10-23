Return-Path: <kasan-dev+bncBDXYDPH3S4OBBUPG5DDQMGQEKJZS3SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 07710C018EE
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:23 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-369b2d355d0sf8396981fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227602; cv=pass;
        d=google.com; s=arc-20240605;
        b=HCxjHh5YTXUaeUi78FiTV6JXSmtJfNChAbthMth8b7ZEVCmm7ZtcjiurNZZnuotCrM
         49M9fFYbZfzz6i1a1BGUd2qxFJV7LQ5+C5u1k75CTWeXO4LJ+OQXBB2QN4LlHQV+zjws
         kmHei+s61txZhJEfeVtY30RsrfXP3y8zr791F3VE5bNEpEFuXFAf7cm/I6xFsukuhafJ
         XG5xqFOxQt7JW7sDYXXgYT+pX+XpxrOeM7r6QnNMUABTQjSNj+32qpqP7Wj+VODA4P9G
         nGZtVhjYhuTnF9v8/k/iRmfSHQjCH8THzC0gCySKRccoPFBcNdTslVgtFZEIGVd8bpNL
         MpDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=53kfLsB+oi4h2NabLmlj5G1L592FnlPp3M8peoqRwss=;
        fh=xAhn9LlXVHJRkXxwlHON/Vj+RgH65BS4weY60az3WSo=;
        b=ARlgpo+1pDfbkT3CG8vZpVy3Soiuv6pQEocopC27q6RbXqowseVGvfOdaanPLTrPRu
         06xJQ51rKHjUJqgqwQ+YbMXjtX6WbA3O9otKsHPnHTU0b9gWax3n2BzTSXx2LhMcHYiw
         /e37XiZN96HZdNLUtNN4wfR7MNxomoJ/xvOUIe6niH+bS2aUH8w7QRFGRO0cuNd/3m0U
         Vcb6JvIYe1mV9R0IKE6K3RMhQF0U65JhPU2vESIoWhYmP1353ySqIes7+/d/8M0nUaLX
         JFVEft26JFeX1Z9T/RrqlHmCTfDdwyrev3GZBPWeXRZpsJ/5Gh4jNzkaWyjQPMZyvDeP
         6e6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227602; x=1761832402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=53kfLsB+oi4h2NabLmlj5G1L592FnlPp3M8peoqRwss=;
        b=YdInqXQCXVl2tOLsl0F8YNgl4VbTeO1sUWomWsByO/2cKlhYt02yjJTOJTCyClxJxf
         RZpGy506WxuRmI4LsgFeGEDaPXG4o7Vz19D0asdjXtpWjPHvQVELdP8IKq+CmieVGp53
         Ccy3G0RuBQZEica/28OGR9cHStNTbLeE6ObcWWyIGVkDOjZhhUpJAI4oSa8wp6suyKPu
         KFAAvr7iQtKGohnUA0t3u32DNk+FHI0VOsa8tkRrEFlyZf7oWMgZ6C3uB1jrhUdbNk9w
         5aStrWfH+NBTrbBBbnjRbicCk/jVBw48gbikSSCFxhiiwkbGsws5LfOYWO3Gf2tp1c5X
         vF2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227602; x=1761832402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=53kfLsB+oi4h2NabLmlj5G1L592FnlPp3M8peoqRwss=;
        b=qy0IIWUYFYpc6i3va4TTj8mzFkIgT+0sCssooocwXHfyeXmMCars+HRQso9PabWbsZ
         NQvu22OChmS3kRQkC/5KaJc0Tgl+Rs/i06yl0nNivwb2Ti4x/fr1SKU3FWR9YoXVWIup
         Qt2OStklFybP1TkYF2FbczhVlmv4l6aOHjvGT8qyTOjlBiHaudNSadeX72uc9MZIexk2
         eSoK4pOv1q8wMfcey4SSl7cfGUEtoGQwmLP17/PmI3G7E1AgEtRCL2/jvWvT9s0gaQ86
         qcjmLkgEXjLRqJ0Ns4h5XbEM+Sc8OtcHYmeaDh5pH/+Fi9jQ78ts7lsgDKErWr2VkD/y
         72VQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX8EBfyj6ffbkQ1G3xL5VG5Rs+dUyRy1h/wB5fye9c/waS9ShwVpeKIrQkYC1LkJWR3VBWSCg==@lfdr.de
X-Gm-Message-State: AOJu0Yz+93/00RhSyM4cjPoo3Bi1v99Q7lesXy88wuS/78/2UkEpMX3a
	X5tAhw+LHtrEc74OOY6hsgqQAvJ1n9GZ01dcAYRYAigiQ/JdU7+Jx0bS
X-Google-Smtp-Source: AGHT+IEK88o2ijQCX+5T3teCkecK660MUHknxpFOGgA1Gul1WbC/nDbMQyBrVLwBS3UMDp7/Qt5JQA==
X-Received: by 2002:a2e:bd04:0:b0:376:5027:7f37 with SMTP id 38308e7fff4ca-37797a8a0b8mr65865091fa.41.1761227602282;
        Thu, 23 Oct 2025 06:53:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4xs21sk3Suo6uWJL84QvsCnN2ch0WyhUtAlu/AnVn2tg=="
Received: by 2002:a2e:330f:0:b0:363:22ce:bcfc with SMTP id 38308e7fff4ca-378d64eb06als2036151fa.2.-pod-prod-03-eu;
 Thu, 23 Oct 2025 06:53:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/HYBbjgfDoYHCtK6y25f7XgpRQDTwzb1jMGgCL/wKf2FwI0no/2iZm5Gr506UyU9xfzaRpr0hK6I=@googlegroups.com
X-Received: by 2002:a05:651c:25d3:20b0:378:d499:d375 with SMTP id 38308e7fff4ca-378d499f1bbmr7841551fa.45.1761227599389;
        Thu, 23 Oct 2025 06:53:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227599; cv=none;
        d=google.com; s=arc-20240605;
        b=dL7WzwGZHvkMhLhy97hfVirn8mNDbsGro3+Gmo5bh4OyOtiFhYW3HYMt6ZcUUaQd2s
         lTGtH2IIKqwFE0t8T8r3KPG9kUNSF8NePSNbBTsKqQjiHt30wvj2We5Ut9fSXXdZ9XD/
         +c60gyrCLPMevjd5xdyOSw65Qk7sr9O/dvT3YIwBlq0JAbu9EDNgZ4TuVi+l8s8PmJxQ
         +9NAGSfPytGIIAQ9+HItlgriMzE+BCVSMZQIoNQltBWSESgVRcLbLfEcn5WSAaoO0MN0
         ZKy9rIkKrCdSdNn9zFkfJvW3cFRW/nHHoeF+Ayzs0e6CzyFR/QNhMuU6VSh7HpPke9+q
         Ib4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=/fUS68CfQH5iByD6xTuI0kS83+VvA4JrdyQgDxukJhY=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=Lt7AoQeoEb8fLngosCYfZpmeKEwlI4vycY6m5kOfPZsEd2bv1mFHajPrly12eWdydB
         5fof7pRb/npS88OEwDsmDaX7VWIBUfHegXTU0b12DNKstWbPQMJ9YFqTSoUrbTevI5IL
         AzjieiDSauaVlchs6jrLLdxCJyTojlYAsyw0Cdo51dwYIGZQYjlwURQn4Ad7fJNSLFXG
         b3G9ldsUS2hJ83lyPtF2dciMOansLApki7GjljpZk1l7NK8Se6a84i7uRfNwoe+TQAXe
         3Gj/C1KRtvxozMvESR0JmPoHj/kBASDfWRb0yMfto+kGC2D3CZtrZqg7170vPcAZ1XH3
         FSuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378d65a40fbsi345871fa.0.2025.10.23.06.53.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id AB7B41F7CD;
	Thu, 23 Oct 2025 13:53:01 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 73D6613B0C;
	Thu, 23 Oct 2025 13:52:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id AKv3GzYz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:54 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:36 +0200
Subject: [PATCH RFC 14/19] slab: simplify kmalloc_nolock()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-14-6ffa2c9941c0@suse.cz>
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
X-Rspamd-Queue-Id: AB7B41F7CD
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
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted
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

The kmalloc_nolock() implementation has several complications and
restrictions due to SLUB's cpu slab locking, lockless fastpath and
PREEMPT_RT differences. With cpu slab usage removed, we can simplify
things:

- the local_lock_cpu_slab() macros became unused, remove them

- we no longer need to set up lockdep classes on PREEMPT_RT

- we no longer need to annotate ___slab_alloc as NOKPROBE_SYMBOL
  since there's no lockless cpu freelist manipulation anymore

- __slab_alloc_node() can be called from kmalloc_nolock_noprof()
  unconditionally

Note that we still need __CMPXCHG_DOUBLE, because while it was removed
we don't use cmpxchg16b on cpu freelist anymore, we still use it on
slab freelist, and the alternative is slab_lock() which can be
interrupted by a nmi. Clarify the comment to mention it specifically.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h |   1 -
 mm/slub.c | 100 ++++----------------------------------------------------------
 2 files changed, 6 insertions(+), 95 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index b2663cc594f3..7dde0b56a7b0 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -208,7 +208,6 @@ struct kmem_cache_order_objects {
  */
 struct kmem_cache {
 	struct kmem_cache_cpu __percpu *cpu_slab;
-	struct lock_class_key lock_key;
 	struct slub_percpu_sheaves __percpu *cpu_sheaves;
 	/* Used for retrieving partial slabs, etc. */
 	slab_flags_t flags;
diff --git a/mm/slub.c b/mm/slub.c
index 6f5ca26bbb00..6dd7fd153391 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3679,29 +3679,12 @@ static inline unsigned int init_tid(int cpu)
 
 static void init_kmem_cache_cpus(struct kmem_cache *s)
 {
-#ifdef CONFIG_PREEMPT_RT
-	/*
-	 * Register lockdep key for non-boot kmem caches to avoid
-	 * WARN_ON_ONCE(static_obj(key))) in lockdep_register_key()
-	 */
-	bool finegrain_lockdep = !init_section_contains(s, 1);
-#else
-	/*
-	 * Don't bother with different lockdep classes for each
-	 * kmem_cache, since we only use local_trylock_irqsave().
-	 */
-	bool finegrain_lockdep = false;
-#endif
 	int cpu;
 	struct kmem_cache_cpu *c;
 
-	if (finegrain_lockdep)
-		lockdep_register_key(&s->lock_key);
 	for_each_possible_cpu(cpu) {
 		c = per_cpu_ptr(s->cpu_slab, cpu);
 		local_trylock_init(&c->lock);
-		if (finegrain_lockdep)
-			lockdep_set_class(&c->lock, &s->lock_key);
 		c->tid = init_tid(cpu);
 	}
 }
@@ -3792,47 +3775,6 @@ static void deactivate_slab(struct kmem_cache *s, struct slab *slab,
 	}
 }
 
-/*
- * ___slab_alloc()'s caller is supposed to check if kmem_cache::kmem_cache_cpu::lock
- * can be acquired without a deadlock before invoking the function.
- *
- * Without LOCKDEP we trust the code to be correct. kmalloc_nolock() is
- * using local_lock_is_locked() properly before calling local_lock_cpu_slab(),
- * and kmalloc() is not used in an unsupported context.
- *
- * With LOCKDEP, on PREEMPT_RT lockdep does its checking in local_lock_irqsave().
- * On !PREEMPT_RT we use trylock to avoid false positives in NMI, but
- * lockdep_assert() will catch a bug in case:
- * #1
- * kmalloc() -> ___slab_alloc() -> irqsave -> NMI -> bpf -> kmalloc_nolock()
- * or
- * #2
- * kmalloc() -> ___slab_alloc() -> irqsave -> tracepoint/kprobe -> bpf -> kmalloc_nolock()
- *
- * On PREEMPT_RT an invocation is not possible from IRQ-off or preempt
- * disabled context. The lock will always be acquired and if needed it
- * block and sleep until the lock is available.
- * #1 is possible in !PREEMPT_RT only.
- * #2 is possible in both with a twist that irqsave is replaced with rt_spinlock:
- * kmalloc() -> ___slab_alloc() -> rt_spin_lock(kmem_cache_A) ->
- *    tracepoint/kprobe -> bpf -> kmalloc_nolock() -> rt_spin_lock(kmem_cache_B)
- *
- * local_lock_is_locked() prevents the case kmem_cache_A == kmem_cache_B
- */
-#if defined(CONFIG_PREEMPT_RT) || !defined(CONFIG_LOCKDEP)
-#define local_lock_cpu_slab(s, flags)	\
-	local_lock_irqsave(&(s)->cpu_slab->lock, flags)
-#else
-#define local_lock_cpu_slab(s, flags)					       \
-	do {								       \
-		bool __l = local_trylock_irqsave(&(s)->cpu_slab->lock, flags); \
-		lockdep_assert(__l);					       \
-	} while (0)
-#endif
-
-#define local_unlock_cpu_slab(s, flags)	\
-	local_unlock_irqrestore(&(s)->cpu_slab->lock, flags)
-
 static inline void flush_slab(struct kmem_cache *s, struct kmem_cache_cpu *c)
 {
 	unsigned long flags;
@@ -4320,19 +4262,6 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
 
 	return freelist;
 }
-/*
- * We disallow kprobes in ___slab_alloc() to prevent reentrance
- *
- * kmalloc() -> ___slab_alloc() -> local_lock_cpu_slab() protected part of
- * ___slab_alloc() manipulating c->freelist -> kprobe -> bpf ->
- * kmalloc_nolock() or kfree_nolock() -> __update_cpu_freelist_fast()
- * manipulating c->freelist without lock.
- *
- * This does not prevent kprobe in functions called from ___slab_alloc() such as
- * local_lock_irqsave() itself, and that is fine, we only need to protect the
- * c->freelist manipulation in ___slab_alloc() itself.
- */
-NOKPROBE_SYMBOL(___slab_alloc);
 
 static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
 		gfp_t gfpflags, int node, unsigned long addr, size_t orig_size)
@@ -5201,10 +5130,11 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 	if (!(s->flags & __CMPXCHG_DOUBLE) && !kmem_cache_debug(s))
 		/*
 		 * kmalloc_nolock() is not supported on architectures that
-		 * don't implement cmpxchg16b, but debug caches don't use
-		 * per-cpu slab and per-cpu partial slabs. They rely on
-		 * kmem_cache_node->list_lock, so kmalloc_nolock() can
-		 * attempt to allocate from debug caches by
+		 * don't implement cmpxchg16b and thus need slab_lock()
+		 * which could be preempted by a nmi.
+		 * But debug caches don't use that and only rely on
+		 * kmem_cache_node->list_lock, so kmalloc_nolock() can attempt
+		 * to allocate from debug caches by
 		 * spin_trylock_irqsave(&n->list_lock, ...)
 		 */
 		return NULL;
@@ -5214,27 +5144,13 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 	if (ret)
 		goto success;
 
-	ret = ERR_PTR(-EBUSY);
-
 	/*
 	 * Do not call slab_alloc_node(), since trylock mode isn't
 	 * compatible with slab_pre_alloc_hook/should_failslab and
 	 * kfence_alloc. Hence call __slab_alloc_node() (at most twice)
 	 * and slab_post_alloc_hook() directly.
-	 *
-	 * In !PREEMPT_RT ___slab_alloc() manipulates (freelist,tid) pair
-	 * in irq saved region. It assumes that the same cpu will not
-	 * __update_cpu_freelist_fast() into the same (freelist,tid) pair.
-	 * Therefore use in_nmi() to check whether particular bucket is in
-	 * irq protected section.
-	 *
-	 * If in_nmi() && local_lock_is_locked(s->cpu_slab) then it means that
-	 * this cpu was interrupted somewhere inside ___slab_alloc() after
-	 * it did local_lock_irqsave(&s->cpu_slab->lock, flags).
-	 * In this case fast path with __update_cpu_freelist_fast() is not safe.
 	 */
-	if (!in_nmi() || !local_lock_is_locked(&s->cpu_slab->lock))
-		ret = __slab_alloc_node(s, alloc_gfp, node, _RET_IP_, size);
+	ret = __slab_alloc_node(s, alloc_gfp, node, _RET_IP_, size);
 
 	if (PTR_ERR(ret) == -EBUSY) {
 		if (can_retry) {
@@ -7250,10 +7166,6 @@ void __kmem_cache_release(struct kmem_cache *s)
 {
 	cache_random_seq_destroy(s);
 	pcs_destroy(s);
-#ifdef CONFIG_PREEMPT_RT
-	if (s->cpu_slab)
-		lockdep_unregister_key(&s->lock_key);
-#endif
 	free_percpu(s->cpu_slab);
 	free_kmem_cache_nodes(s);
 }

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-14-6ffa2c9941c0%40suse.cz.

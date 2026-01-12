Return-Path: <kasan-dev+bncBDXYDPH3S4OBB7VASTFQMGQEM4BVHUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id B8A11D138F8
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:19 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-64d5bec0e59sf9601950a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231039; cv=pass;
        d=google.com; s=arc-20240605;
        b=RD7ee60VVcyIYx+oE8DvipYZUybM4/7Zr8AEqyYta/MNjxEC+pm9tTLcMtOQCE8VU2
         QyCliEePWyVvGe0sMWqwBfgdEbBy7NPuBuvAS0TjliyWw13AWL7cuJ2gUZFMYEcxEN7L
         tDRfrIfWSeyc+qTpDzf63TGMyjTv/8ckvu5n1YKg2cI3MM95tGFK1n9E0BXAr+E5ptyb
         XWn8aRF5lWs/Vfteu2FgoVhdvurwpMjWuXNQyUHpLq+cInjE7R617GCFJtTF5F96GYtl
         ojre01KOg3Bygw1uVrr2kcbYTRg7AoFPXPvdBH3kreZsZ31QY+oawJK53Uht+A2Y5kNa
         FEQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=3xs7OeGAmh+lyTxlRMocv1FNW1j7yKc4omiIbMqqmAE=;
        fh=UEeThFIXqsbaIDafoFosj/7E+jilCTvCzI+JUdpjguU=;
        b=Go2bYC2InQK6pfOQ9B54iO9IlnZHBqrLmgAT1MGrCWkxqlDNfoDZH1HTLGmztlv0mf
         rP81sISaQ+xJh9CiTk8D8xkxaEt1DL5vAMUJXia0dk8+wJM8dEu3j2WkJ44cpnq17458
         zrMbkXPCzdo2nWDXHunONBNxBq0MOfwkrSsBhV3ViDlsuuJqeDs1KgbMGk8hbdAtGbOd
         RLUDOGeQbQGuTuziRfDtT+SIY0y/GqKb8GLquuL4Lp5SiLQZVZXeD98qP54mfYV603fG
         USucjGSqh2Ai4xeuKASwS+1GzQB7VVBBwFYZen5OsHNNLi4pOIsr0IJwUc4OdowMA3Ad
         9Bhg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231039; x=1768835839; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3xs7OeGAmh+lyTxlRMocv1FNW1j7yKc4omiIbMqqmAE=;
        b=tL/bc/L1mItwGuyinK9tc9iOCDokG1c4GPlLktpaGSbyNhjJz2FfTE2URp3GWZUbEd
         fuscykU/KinJoW6VjJ4KVuvPBeb+gqVdfX6jmhfEPMlSBRtfNyDEGckcN4Wm3afJcg4F
         7P3sn+7J6HeiW9VRb5HclRXHae1NL7Lk+7NPGbl2nSbrivYAHSIdv4uvSKO9D8DwaKzl
         1Tv2APKCKwhrrgpptuXXB4MNq17sgjiKRG3Z9V4lJUR4Wcj49kpzbq3omu/eydvYCw6w
         4jTcQOvjoNaZ5dxq3IdmXTp7jvTPnZ0/BcJbfSQYeAYXT3LB7ffvVffi6YuHQOvHYMAe
         LTgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231039; x=1768835839;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3xs7OeGAmh+lyTxlRMocv1FNW1j7yKc4omiIbMqqmAE=;
        b=fTq91+HM8vDhbSJb+ABKd08lXsnKVi7q0m5EAsrjojzYWbblmP3DSQJlK9cSMnCtV8
         unjcvoD/UgfixhKGxS2KU52PLUewcaff40+H6dSrAs7d33IIzxEP+pUWBExElLKID9+j
         HhZkiSwyYiHiWg33J0wVn9FoYa2GMmQ9hPlOtZozNFT+oqPkbZc2AkPa9hsMPWiv3/v1
         YqbRuh2fs1Oo3yc99gbbH2CpXIShBXa9w8qlzy85Y9v726YHGgwBNG96pJWR7DM4+piM
         rBEv3NcPs1Dy8DWhkhMrOi1cI4VTygnyy6ooW7CJQz2cXGXbTteCzoiPul/Gxey0yz7T
         g6JA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUFO5SCckdxbEg25RtgDY6XcTQQ4p4CeosKKgj4BqScUrZqQShUWh+AFKeHZ/Oamqhtu0TdVw==@lfdr.de
X-Gm-Message-State: AOJu0Yx5ACRLM1xwHgYMDQJvLfJUUegOf2AoNvQyqAWGrwdIKex5Sj/V
	l239VlJmm0DCryVppue67FdPSwbm5BIv4jRmijJtAwKfilupDsUWWUPc
X-Google-Smtp-Source: AGHT+IF/a4rSwnG+7soBbUWopI88hyjChR6NFkiLnPs4XLahNfEQEqxlLsq9KzXP3XqBCmBZUpxbBg==
X-Received: by 2002:aa7:c4e6:0:b0:64d:4a01:fc23 with SMTP id 4fb4d7f45d1cf-65097dea37emr13448453a12.10.1768231038998;
        Mon, 12 Jan 2026 07:17:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EFdF//+vzXmXrCcEIH56DZkcpVv/KHwiIWNEcdDmQBAQ=="
Received: by 2002:a05:6402:5356:20b0:644:f95b:b16f with SMTP id
 4fb4d7f45d1cf-6507443534cls4925474a12.0.-pod-prod-08-eu; Mon, 12 Jan 2026
 07:17:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWnsLHmWac8zYH4UZLIW28gE80WEdaFweIzY5dIz8iftZFbDXslGlzqVxPnH+zxrvP4j1BbysN/KTw=@googlegroups.com
X-Received: by 2002:a05:6402:5110:b0:64d:1762:9ba2 with SMTP id 4fb4d7f45d1cf-65097df8435mr17429662a12.13.1768231036419;
        Mon, 12 Jan 2026 07:17:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231036; cv=none;
        d=google.com; s=arc-20240605;
        b=bSsK02i13r1T95kukuikvaCQjHNbABBjakdbCfBtVat7uFP+6UZeS+WILmr+FFxGoY
         7NW4BtMr//uLTkOJqhiIUxbGQN9oY3mFSgwEsYrERWV7dln5X/PU4yUcNIgWVlHXzTev
         Dn5S+aODWdrQeXbzWu+LaXE8WcCeRjS3sxax0gzj8KK7BqxQu3vbhv7drQz9/oD51XGu
         xMfZM1U5AlivcrF2/5AdJDYzcbe/4nxfBSk/pd7zDVsZKGIJls3Wzgk4Qn+SA+qKi0Nn
         f56NefTzauLBDp2uSN2dgcSfRoyXmK1PQ8OcS89qupTM4QsTiMHodfb+knSbIGQYe+dY
         rrGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=KkKoCCU6P6m0eSC8xsu40OzvhBb6myNeyGA3eaUel9o=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=YVQ1AkcfAVBXWA5aLKXneT/bZ9lOQfKglnsfIDt8r6WHH5QXb4LZybM82Fv+0OFsE9
         s160TWzrrCzMASn4uFzOroHCIjEkvQxGnqPvUSeHQJvFed+QLW7XeEgMnibqxM7sX+rP
         9bhPndPj3Jrn5O5KTFJKpW9Puq/8n4h70EPPD4irJP2V8jGgA3mE4BXzEKa6sKGJHvHe
         Ph2ZfC93sPOFCJeOJmaVt8JBx0DlBYDCpCoCgWI1y/f3/6b5m1vza5tkc03GlnyL0yL1
         pV/5+crvlJlk83HKkFJ7hbHzgfJZzRpE3gaKAjzrQ0qnY6niGwBa7mfYoNoJt6Nf0zMs
         rbgg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d705352si355827a12.4.2026.01.12.07.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:16 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E175933696;
	Mon, 12 Jan 2026 15:16:58 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id C2FD53EA63;
	Mon, 12 Jan 2026 15:16:58 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id yPdRL2oQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:58 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:17:07 +0100
Subject: [PATCH RFC v2 13/20] slab: simplify kmalloc_nolock()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-13-98225cfb50cf@suse.cz>
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
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Spam-Flag: NO
X-Spam-Score: -4.00
X-Rspamd-Queue-Id: E175933696
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
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

The kmalloc_nolock() implementation has several complications and
restrictions due to SLUB's cpu slab locking, lockless fastpath and
PREEMPT_RT differences. With cpu slab usage removed, we can simplify
things:

- the local_lock_cpu_slab() macros became unused, remove them

- we no longer need to set up lockdep classes on PREEMPT_RT

- we no longer need to annotate ___slab_alloc as NOKPROBE_SYMBOL
  since there's no lockless cpu freelist manipulation anymore

- __slab_alloc_node() can be called from kmalloc_nolock_noprof()
  unconditionally. It can also no longer return EBUSY. But trylock
  failures can still happen so retry with the larger bucket if the
  allocation fails for any reason.

Note that we still need __CMPXCHG_DOUBLE, because while it was removed
we don't use cmpxchg16b on cpu freelist anymore, we still use it on
slab freelist, and the alternative is slab_lock() which can be
interrupted by a nmi. Clarify the comment to mention it specifically.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h |   1 -
 mm/slub.c | 132 +++++++++++---------------------------------------------------
 2 files changed, 23 insertions(+), 110 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 4efec41b6445..e9a0738133ed 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -190,7 +190,6 @@ struct kmem_cache_order_objects {
  */
 struct kmem_cache {
 	struct kmem_cache_cpu __percpu *cpu_slab;
-	struct lock_class_key lock_key;
 	struct slub_percpu_sheaves __percpu *cpu_sheaves;
 	/* Used for retrieving partial slabs, etc. */
 	slab_flags_t flags;
diff --git a/mm/slub.c b/mm/slub.c
index 0effeb3b9552..07d977e12478 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3677,29 +3677,12 @@ static inline unsigned int init_tid(int cpu)
 
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
@@ -3786,47 +3769,6 @@ static void deactivate_slab(struct kmem_cache *s, struct slab *slab,
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
@@ -4385,20 +4327,6 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
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
-
 static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
 		gfp_t gfpflags, int node, unsigned long addr, size_t orig_size)
 {
@@ -5258,10 +5186,11 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
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
@@ -5270,42 +5199,31 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
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
 
-	if (PTR_ERR(ret) == -EBUSY) {
-		if (can_retry) {
-			/* pick the next kmalloc bucket */
-			size = s->object_size + 1;
-			/*
-			 * Another alternative is to
-			 * if (memcg) alloc_gfp &= ~__GFP_ACCOUNT;
-			 * else if (!memcg) alloc_gfp |= __GFP_ACCOUNT;
-			 * to retry from bucket of the same size.
-			 */
-			can_retry = false;
-			goto retry;
-		}
-		ret = NULL;
+	/*
+	 * It's possible we failed due to trylock as we preempted someone with
+	 * the sheaves locked, and the list_lock is also held by another cpu.
+	 * But it should be rare that multiple kmalloc buckets would have
+	 * sheaves locked, so try a larger one.
+	 */
+	if (!ret && can_retry) {
+		/* pick the next kmalloc bucket */
+		size = s->object_size + 1;
+		/*
+		 * Another alternative is to
+		 * if (memcg) alloc_gfp &= ~__GFP_ACCOUNT;
+		 * else if (!memcg) alloc_gfp |= __GFP_ACCOUNT;
+		 * to retry from bucket of the same size.
+		 */
+		can_retry = false;
+		goto retry;
 	}
 
 success:
@@ -7328,10 +7246,6 @@ void __kmem_cache_release(struct kmem_cache *s)
 	cache_random_seq_destroy(s);
 	if (s->cpu_sheaves)
 		pcs_destroy(s);
-#ifdef CONFIG_PREEMPT_RT
-	if (s->cpu_slab)
-		lockdep_unregister_key(&s->lock_key);
-#endif
 	free_percpu(s->cpu_slab);
 	free_kmem_cache_nodes(s);
 }

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-13-98225cfb50cf%40suse.cz.

Return-Path: <kasan-dev+bncBDXYDPH3S4OBBSHG5DDQMGQECJGLXMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id EAA22C018DF
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:14 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-592f4153f08sf387451e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227593; cv=pass;
        d=google.com; s=arc-20240605;
        b=g0LChkD5u9e3FaA4RVcN293myUhwnVRpDJSA+6LzuDIkw2cnoILZp8/2dy01uizmsw
         O8c6lWeMVJrd3Oq+xQwPKAwiH4ccowjJSPpp1zYd3KTVBE+LVcD+DF7egvbIMGpr1wO8
         nHZoxLQz9AJR3COxHoDn9MquIB+R8Wloz6z8+gqPo9fp95e6h7NOCLzP7I5RQ94HAK1P
         hZMALeMzxczt9kxavSd0RjS561Z0j4srL2+fB9K1dX2wIMmZ7cbX+CZ3jnYEmIkHrNmw
         s6bKbTr4J4+50m6xDgsMP5DYDwrIaXfCRvZKcBjolGC+/ijJobXUoIlWFG+Wbodfbs74
         7unQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=4gf5O0UNE69CAqtxYbRKuQy18LnxpvS3imxQBOVJD6A=;
        fh=4O7DZ3FArZqdQyLVMzLu2N1R9hmebTdYeufEnybt+SM=;
        b=dbUhRs3LKUz3RfOMZJeUmTzGH9qGxfZwS1MviiQZUC56xclXEAoU2hX2DHg8EIUNXc
         pCa+w2kjG8kImDwhOsX1OuUSwoOYxYApI2zRsUIERYesL3KqEFQoZqbYSNXGfOKECEwN
         vb3n5zE6LIrofT0GWpDMHeg+XaWCF+yl52zs1j1gld+ep4U3Di3/mXotWpshncYEo+mG
         gGgiqKLGm5+5gQWWW+T590TnhnMHvvxJF9HMkneEW8sSHJ0nEefPiIVtxlnh2wK0fivY
         Rw4zwiq2IPXRacc1JW7BCJJwaZdNPjXlXADUb8iQrWjupt/QPfezLK67D7tOBOWfQWWy
         ddvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227593; x=1761832393; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4gf5O0UNE69CAqtxYbRKuQy18LnxpvS3imxQBOVJD6A=;
        b=V6OhlKgt86kDWLa2OWH5wHxlSb+nL/4HgV5Gj6Hl1l8aC64IFXwOOFhzHXBOrnH0w7
         xmg8743/n3bz+tKOXuczTLfaYJPuUaQCllrm1DGaU3Gt7TRqzA4nI39Ax37nw3OtDFe6
         8w1H7iO/Rg9n67+O6nMA9QL0vbYCa8Vqds01DEnb5NSYiNj24soTBvXboqXM4nCsnTPR
         kA/dOfISu7svgw1lEN1VA41gEBErd2xGB3EXBwwV6uxCdfHV6LnVn9MToBn+3lR5d9qI
         hko15GAPzzyD6zJE77g2gu2cZmETgh78M3WN8k0dpWz8Zt0IJFzjDny24oOwQ0fv1jAe
         +QQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227593; x=1761832393;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4gf5O0UNE69CAqtxYbRKuQy18LnxpvS3imxQBOVJD6A=;
        b=EfjbMfvW4HMq+XhaWSqbb/Vnshvjb1SVQ8elfmgn+DnykpYAcTHTC7LKvjtcsliscQ
         WMdp6AE32CPmWYbUWCx3+wSCqDZUc2lq/WlHrmKx9uhd0d4XxytH3bUgEkl4bY5e7yT1
         wTvlJOGLH2Yz8ii9nDpq90LdrcVT+mx1kGVqT/N95d2DG3C8+t4EEs7riNMLJju/2vdy
         /Bf+M7hx2FIdFuBcUeT5+FET96m10L3Byiff3H5b4x/7GuSFFVIB7uebxLHqz4QHzXRC
         zV1S4cYx88W7tyyITcRtxAB/8ltQicF+Qjlbdr118KABlZe0YKJQRKG04Eh+HrIEa0YY
         KyYw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXup+hnmQfFvYqdgRrSW7ETqcZVb+z2X0rl2YrcKYn1qny9Hz5vXo8005oEwRP3Jk8d5MVsPQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx5Qll8VkuPE2M4tpIwv7f0xk2XAurdc+LXDwFa1WgD3GjG2FeO
	wMiPgLYPbi+imAd78l7n+oROzJnOZsPg39RfAONYRUh+C37qiIBdp8dz
X-Google-Smtp-Source: AGHT+IG+i/SZXpsRXhbQlfgPfNFU2zFfWKs4pVF0p6K8dcVfvBhjWmYa80AeGaHREhyp6EuOorDd9w==
X-Received: by 2002:a05:6512:689:b0:581:bdb8:6df9 with SMTP id 2adb3069b0e04-592f17400d3mr1657027e87.10.1761227592872;
        Thu, 23 Oct 2025 06:53:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bP05gj8LVFexenS9UKkcOf/fS4xe3UmulbQY19D0FROQ=="
Received: by 2002:ac2:5626:0:b0:55f:4af2:a581 with SMTP id 2adb3069b0e04-592f53382fbls66358e87.0.-pod-prod-00-eu;
 Thu, 23 Oct 2025 06:53:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUcDRCduPpXuttqSekXpY9bnybG28iYVgJc/AygRglTm5PiLXxZ8JfA2yzMqm4gvEOs8j4gPQwgBJ8=@googlegroups.com
X-Received: by 2002:a05:6512:2c04:b0:580:d110:f413 with SMTP id 2adb3069b0e04-592f186305amr1585811e87.16.1761227589655;
        Thu, 23 Oct 2025 06:53:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227589; cv=none;
        d=google.com; s=arc-20240605;
        b=FBufva2AHGRbMjxb58C1R8yWc983MK3XYXxunl4kEs23Xz9Yyzb2lgn/OIcboicBy9
         YuSQKAawCKIzOPFUSz5L78zbADFk5ExoGZkJ5K8lsJQ8UYdWTeOD1n6KpgY/jazAyuhK
         5YiJgJPm7gYPRbU87tMSqarWY0wV1IMrJr9pxebrHPOCwn9YmXQ4J0ZDCf9vdFTh+AvF
         K1anuTKSc2mR7soX5vrd/pnzW2KeNY7uJl2QUyMkzKox+pJUGVdCjcU4JWRAt5zxFoYX
         KcfLPEnwMsRlydbhrdU6Rf9+JLPOk2D7eRLCJmRdUaJIHB9YWv8A6v/PljfKysVf544o
         h+nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=yxhT4UB0xWxTyj1ZZ9eXWMgewHmvLpOhYokSg154voQ=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=RwAyfos+Tr9KpV5ta/l6mEPvPyveRQU6C4E0AJty/Ipx1zV8ufoWn/hyh5br5QmsKG
         7CnmCy5Zu4ORJMQGvQXQLiOkGWGWjghxShxHxI8ms68VySg2KHidpUSfsGLY/oQkWWrr
         UTx9Gtj5coOAGJOVfdEaSRkhWtQz35szLbh+1d24t0BdIa2UYRjrv15NPpIXE3mlucmd
         byJjTevYk/9iAWOiD1HM1WudnSKZamvTQcfBAJIwKYodAYwaKkD+wzrPs//DQT6ngZNx
         kgChgF4u+zpxhjc6DdObMtlEjVCrRJkql0wZlKT/DNP0Bx0FHakUljX8EKY77hroHGiM
         augA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-592f4cd5588si48561e87.2.2025.10.23.06.53.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 9E44C1F7C7;
	Thu, 23 Oct 2025 13:53:01 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 31AD813B0A;
	Thu, 23 Oct 2025 13:52:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id UAPYCzYz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:54 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:34 +0200
Subject: [PATCH RFC 12/19] slab: remove the do_slab_free() fastpath
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-12-6ffa2c9941c0@suse.cz>
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
X-Rspamd-Queue-Id: 9E44C1F7C7
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

We have removed cpu slab usage from allocation paths. Now remove
do_slab_free() which was freeing objects to the cpu slab when
the object belonged to it. Instead call __slab_free() directly,
which was previously the fallback.

This simplifies kfree_nolock() - when freeing to percpu sheaf
fails, we can call defer_free() directly.

Also remove functions that became unused.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 149 ++++++--------------------------------------------------------
 1 file changed, 13 insertions(+), 136 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index d8891d852a8f..a35eb397caa9 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3671,29 +3671,6 @@ static inline unsigned int init_tid(int cpu)
 	return cpu;
 }
 
-static inline void note_cmpxchg_failure(const char *n,
-		const struct kmem_cache *s, unsigned long tid)
-{
-#ifdef SLUB_DEBUG_CMPXCHG
-	unsigned long actual_tid = __this_cpu_read(s->cpu_slab->tid);
-
-	pr_info("%s %s: cmpxchg redo ", n, s->name);
-
-	if (IS_ENABLED(CONFIG_PREEMPTION) &&
-	    tid_to_cpu(tid) != tid_to_cpu(actual_tid)) {
-		pr_warn("due to cpu change %d -> %d\n",
-			tid_to_cpu(tid), tid_to_cpu(actual_tid));
-	} else if (tid_to_event(tid) != tid_to_event(actual_tid)) {
-		pr_warn("due to cpu running other code. Event %ld->%ld\n",
-			tid_to_event(tid), tid_to_event(actual_tid));
-	} else {
-		pr_warn("for unknown reason: actual=%lx was=%lx target=%lx\n",
-			actual_tid, tid, next_tid(tid));
-	}
-#endif
-	stat(s, CMPXCHG_DOUBLE_CPU_FAIL);
-}
-
 static void init_kmem_cache_cpus(struct kmem_cache *s)
 {
 #ifdef CONFIG_PREEMPT_RT
@@ -4231,18 +4208,6 @@ static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags)
 	return true;
 }
 
-static inline bool
-__update_cpu_freelist_fast(struct kmem_cache *s,
-			   void *freelist_old, void *freelist_new,
-			   unsigned long tid)
-{
-	freelist_aba_t old = { .freelist = freelist_old, .counter = tid };
-	freelist_aba_t new = { .freelist = freelist_new, .counter = next_tid(tid) };
-
-	return this_cpu_try_cmpxchg_freelist(s->cpu_slab->freelist_tid.full,
-					     &old.full, new.full);
-}
-
 /*
  * Get the slab's freelist and do not freeze it.
  *
@@ -6076,99 +6041,6 @@ void defer_free_barrier(void)
 		irq_work_sync(&per_cpu_ptr(&defer_free_objects, cpu)->work);
 }
 
-/*
- * Fastpath with forced inlining to produce a kfree and kmem_cache_free that
- * can perform fastpath freeing without additional function calls.
- *
- * The fastpath is only possible if we are freeing to the current cpu slab
- * of this processor. This typically the case if we have just allocated
- * the item before.
- *
- * If fastpath is not possible then fall back to __slab_free where we deal
- * with all sorts of special processing.
- *
- * Bulk free of a freelist with several objects (all pointing to the
- * same slab) possible by specifying head and tail ptr, plus objects
- * count (cnt). Bulk free indicated by tail pointer being set.
- */
-static __always_inline void do_slab_free(struct kmem_cache *s,
-				struct slab *slab, void *head, void *tail,
-				int cnt, unsigned long addr)
-{
-	/* cnt == 0 signals that it's called from kfree_nolock() */
-	bool allow_spin = cnt;
-	struct kmem_cache_cpu *c;
-	unsigned long tid;
-	void **freelist;
-
-redo:
-	/*
-	 * Determine the currently cpus per cpu slab.
-	 * The cpu may change afterward. However that does not matter since
-	 * data is retrieved via this pointer. If we are on the same cpu
-	 * during the cmpxchg then the free will succeed.
-	 */
-	c = raw_cpu_ptr(s->cpu_slab);
-	tid = READ_ONCE(c->tid);
-
-	/* Same with comment on barrier() in __slab_alloc_node() */
-	barrier();
-
-	if (unlikely(slab != c->slab)) {
-		if (unlikely(!allow_spin)) {
-			/*
-			 * __slab_free() can locklessly cmpxchg16 into a slab,
-			 * but then it might need to take spin_lock
-			 * for further processing.
-			 * Avoid the complexity and simply add to a deferred list.
-			 */
-			defer_free(s, head);
-		} else {
-			__slab_free(s, slab, head, tail, cnt, addr);
-		}
-		return;
-	}
-
-	if (unlikely(!allow_spin)) {
-		if ((in_nmi() || !USE_LOCKLESS_FAST_PATH()) &&
-		    local_lock_is_locked(&s->cpu_slab->lock)) {
-			defer_free(s, head);
-			return;
-		}
-		cnt = 1; /* restore cnt. kfree_nolock() frees one object at a time */
-	}
-
-	if (USE_LOCKLESS_FAST_PATH()) {
-		freelist = READ_ONCE(c->freelist);
-
-		set_freepointer(s, tail, freelist);
-
-		if (unlikely(!__update_cpu_freelist_fast(s, freelist, head, tid))) {
-			note_cmpxchg_failure("slab_free", s, tid);
-			goto redo;
-		}
-	} else {
-		__maybe_unused unsigned long flags = 0;
-
-		/* Update the free list under the local lock */
-		local_lock_cpu_slab(s, flags);
-		c = this_cpu_ptr(s->cpu_slab);
-		if (unlikely(slab != c->slab)) {
-			local_unlock_cpu_slab(s, flags);
-			goto redo;
-		}
-		tid = c->tid;
-		freelist = c->freelist;
-
-		set_freepointer(s, tail, freelist);
-		c->freelist = head;
-		c->tid = next_tid(tid);
-
-		local_unlock_cpu_slab(s, flags);
-	}
-	stat_add(s, FREE_FASTPATH, cnt);
-}
-
 static __fastpath_inline
 void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	       unsigned long addr)
@@ -6185,7 +6057,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 			return;
 	}
 
-	do_slab_free(s, slab, object, object, 1, addr);
+	__slab_free(s, slab, object, object, 1, addr);
 }
 
 #ifdef CONFIG_MEMCG
@@ -6194,7 +6066,7 @@ static noinline
 void memcg_alloc_abort_single(struct kmem_cache *s, void *object)
 {
 	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
-		do_slab_free(s, virt_to_slab(object), object, object, 1, _RET_IP_);
+		__slab_free(s, virt_to_slab(object), object, object, 1, _RET_IP_);
 }
 #endif
 
@@ -6209,7 +6081,7 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
 	 * to remove objects, whose reuse must be delayed.
 	 */
 	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
-		do_slab_free(s, slab, head, tail, cnt, addr);
+		__slab_free(s, slab, head, tail, cnt, addr);
 }
 
 #ifdef CONFIG_SLUB_RCU_DEBUG
@@ -6235,14 +6107,14 @@ static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
 
 	/* resume freeing */
 	if (slab_free_hook(s, object, slab_want_init_on_free(s), true))
-		do_slab_free(s, slab, object, object, 1, _THIS_IP_);
+		__slab_free(s, slab, object, object, 1, _THIS_IP_);
 }
 #endif /* CONFIG_SLUB_RCU_DEBUG */
 
 #ifdef CONFIG_KASAN_GENERIC
 void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
 {
-	do_slab_free(cache, virt_to_slab(x), x, x, 1, addr);
+	__slab_free(cache, virt_to_slab(x), x, x, 1, addr);
 }
 #endif
 
@@ -6444,8 +6316,13 @@ void kfree_nolock(const void *object)
 	 * since kasan quarantine takes locks and not supported from NMI.
 	 */
 	kasan_slab_free(s, x, false, false, /* skip quarantine */true);
+	/*
+	 * __slab_free() can locklessly cmpxchg16 into a slab, but then it might
+	 * need to take spin_lock for further processing.
+	 * Avoid the complexity and simply add to a deferred list.
+	 */
 	if (!free_to_pcs(s, x, false))
-		do_slab_free(s, slab, x, x, 0, _RET_IP_);
+		defer_free(s, x);
 }
 EXPORT_SYMBOL_GPL(kfree_nolock);
 
@@ -6862,7 +6739,7 @@ static void __kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 		if (kfence_free(df.freelist))
 			continue;
 
-		do_slab_free(df.s, df.slab, df.freelist, df.tail, df.cnt,
+		__slab_free(df.s, df.slab, df.freelist, df.tail, df.cnt,
 			     _RET_IP_);
 	} while (likely(size));
 }
@@ -6945,7 +6822,7 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
 				cnt++;
 				object = get_freepointer(s, object);
 			} while (object);
-			do_slab_free(s, slab, head, tail, cnt, _RET_IP_);
+			__slab_free(s, slab, head, tail, cnt, _RET_IP_);
 		}
 
 		if (refilled >= max)

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-12-6ffa2c9941c0%40suse.cz.

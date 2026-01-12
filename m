Return-Path: <kasan-dev+bncBDXYDPH3S4OBBANBSTFQMGQETS5OHZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 17F75D138FB
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:22 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-47d28e7960fsf67716965e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231041; cv=pass;
        d=google.com; s=arc-20240605;
        b=YhEAWnGD/cLxNuURdhk/kIuhC06EzQs3TGWn/+8gAdy5XJSF/L8N1daA5z+3L9SS5B
         jmyScJzDSYFt8OK2zttfhKFEcELmGcE8cobpbWBsMYDX6Vx1e4vww8JVXaoJcxUgk65y
         rujhmyd+I37R2H8GCOrioR+cKT0xPk+4hp+5qiSkfqretymRtt1e0XR1jKz6DRwP/2lU
         aJtaMlewCNMv+1ffF+DKBzGyDiIXE9uM3BNuLzSVP+HA+4JE3B2qXwd8lJrvdT7CyIga
         PV9vpbj6ntiqFBGxJoITIN0svJm0aB6YNQpvhcGohS/Ko3Nhq0xZbEzZkRjK/oAxgJrT
         F8lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=jHWS70HBGruImM1M7DJ45SAIiksZmHAqZYnLXTrFdvU=;
        fh=T91SCMcGOXdELLbnBhV2LwzwWV3Gt5qo8NIUomzoQ7o=;
        b=MagZHF6Bnj+TFrpfNZNmqAkCfxOwyQtn+V0+OAp56DnZwkJebEKkRb2TwnPVqSKon7
         ncZcSrsNrv/L0Mc/udRSkirDRRLVooTNCc/kJDyK9qvg/cz44+Vtz0Suwxyd0deHEJ4N
         gLUCAnkC/CYxhUHMGztBJgR0AeM+PY1bJRU0DMFLBQT0qrZTvvo2qNKb7GJye0M1ix5F
         hS+A6fF1s85xcVBzKzYBvTIrh2vUeBGzth94QjQnTr0AhYXyLhmS1AXtP3Bv4Gd5HMOs
         bcXjeTsJfG3gVb2+okpkBSMaboX96uLVWPybKTwnOicERquyWtRPJybKPusqOQkLPXk/
         AbpQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231041; x=1768835841; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jHWS70HBGruImM1M7DJ45SAIiksZmHAqZYnLXTrFdvU=;
        b=H/d+bN1qBX8D6HFaCEjOxSwq8hg5gayUa6D6RuYQr+AGcKxrAYwDFk5WnxcRTMINfQ
         onUWvinqoPGYAq8wtpJUI7rbGGHiqE/X++G09YnF4xoYZmFKfi1P8a1UXlr/eNXnQ9Rq
         G5HhfUG1F77TxsO9ObX4iMNX2oRDmja18wZ8xRCK/xrnY3ZqAwM2VycXOjrop5sHFd29
         w5PlAVlrNRB/GcpazTuaBtQ8fT1VyuQPrQacT9YnvUk8V9jezXotoDudxF0y0FG14e7O
         DG6S/vOqNgyvSllKXYitTkn6ALQWLoGPU+6A9vNAinlW4YPZZxKKp2Z40FcTGBlVEHk+
         q4Pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231041; x=1768835841;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jHWS70HBGruImM1M7DJ45SAIiksZmHAqZYnLXTrFdvU=;
        b=eozyxUm4oKj5nWlPiBTIJ77z1DsFanSSQ2xgugjz4f5V0ZQ4eUsGFJuE95bCNALo4W
         qdGoqAXcaHD+q9Z+Dzw4kFIQmforYUEbG/GvepyeEfIKn+kxqXjwQH5LqWZ+WSaWvDvQ
         gDG/2t7bgDXr5Pdcpzf0NYpcagNOi1Bc4gz3qI8QbbIflvdOOzf4c4WPfb5yo8zwtL9J
         KhdWxXBjjthc13t4NKSSOAUJTg83x/qizNCHoSKu81M8BT/swb3k2bktb523sYBSSaUV
         T97o+VYPebfjdYgA4FjjRSd3Jg6znRrSiApkHfWwVZFKL3ph1sWaV+ha4t0gYIdMpt8N
         cwZQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUE5i4B1hY2Mk7vGlM6qmRfvj42N+WeoBmtJE87d1BcCyYVfH2WtDVtOBAjC/q3Qz3YGpEUog==@lfdr.de
X-Gm-Message-State: AOJu0YzBNK5TH4AKqQRyt9CwHYq8xrZF6fHiXgqwYqHUlcN7aa/HRYWk
	Lt5vAqrjasoQkfLZpVCG3LFLuTtOxK1oVkOmv1mYVG27m2KTXSmW6RHu
X-Google-Smtp-Source: AGHT+IHfistLNMlN0CKJ4xLOk9Z0OU3dveTQdMpcOMmW3UlHhjqFIs5pQoJAa4KktsPEGpspYJsXZw==
X-Received: by 2002:a05:600c:3b19:b0:45d:d97c:236c with SMTP id 5b1f17b1804b1-47d84b3b645mr224014535e9.21.1768231041525;
        Mon, 12 Jan 2026 07:17:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FiLyvaPulrEqTOyFasGYccU6f6sC8OA+kcBA9uMUaYOg=="
Received: by 2002:a05:600c:4443:b0:477:a036:8e82 with SMTP id
 5b1f17b1804b1-47d7eaa4893ls44299085e9.0.-pod-prod-08-eu; Mon, 12 Jan 2026
 07:17:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWwPEZMG64C3i5je+IVsTbeJTjv4QWTjwhqLOw+gpolE0cUMegP2J5/NF8+d9pGFXy19H7d5ebqmis=@googlegroups.com
X-Received: by 2002:a5d:5f53:0:b0:42f:b649:6dc9 with SMTP id ffacd0b85a97d-432c37c3338mr21862594f8f.58.1768231039204;
        Mon, 12 Jan 2026 07:17:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231039; cv=none;
        d=google.com; s=arc-20240605;
        b=RHRLoU3cuiDbSBAfETyoqwYjWQusDkftTBQgvpC1BpVFlWo7tCijSxrigjDV6Q8VB9
         7/9VuWf8H9BK/o3ibqq93ZIJOL/CJe5uQ4tAg544uUqNAnHsOBjTmwrtEco4DLXVjX8F
         RCH2GxsPEyrSv8CfIcovg1gj66JzfBihri/MbT4moJ9/m2Tr/fC5n9c1G5Y6Dj5AwdPi
         n382PmMWNswsXKt5Q5q8s2bwkvonNX57f/X6mD0TUV9WV+8v2pMuy5QEA1iVmor0avLv
         Pnw2PPPBIX+HAemIf7gQ6z6BeUO8v9PF26/LPXFCtG+MgYx4/cg2y/J4biOABaflq65w
         6n3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=HO3yb5/DTvOVu4gGCODslTusNQMw4vd0+MOyeq3eM4Y=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=gdqnteDMdPCMcaVsny4n0yrPusOPnMs/y3WR7jdX9HcPl1nsJLEj43mK2+Y09qz6em
         QhC53ft/VIx9LU5aHRG/IU1GduKbh3btLnNZm2BvV+7NRNikM1yyPHTKyQU3tiX24uin
         CVU2Xt9VsmeFog73ZP6PsIqc6ZwlYgRHQRiJNyUj5Dma3wSHBZjUCF/bovlitd0JxjG5
         6J7cD5Xivhxi6nceJC9GO/V87CtvIxkkHBKGZ/AHu6Nz9+GT15LpSLArhZEPhHRuME9P
         Dt7WIp3QnEE+P1GnCFPVyBeUTi5qm4jkOx73sRmakUp7lCD3hz3lKJx1DWHkBtb93YPu
         OaRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432be509c68si278274f8f.8.2026.01.12.07.17.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:19 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id AA0905BCD5;
	Mon, 12 Jan 2026 15:16:58 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 8C2473EA63;
	Mon, 12 Jan 2026 15:16:58 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id WDzqIWoQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:58 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:17:05 +0100
Subject: [PATCH RFC v2 11/20] slab: remove the do_slab_free() fastpath
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-11-98225cfb50cf@suse.cz>
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
X-Rspamd-Queue-Id: AA0905BCD5
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
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
index 006f3be1a163..522a7e671a26 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3668,29 +3668,6 @@ static inline unsigned int init_tid(int cpu)
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
@@ -4229,18 +4206,6 @@ static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags)
 	return true;
 }
 
-static inline bool
-__update_cpu_freelist_fast(struct kmem_cache *s,
-			   void *freelist_old, void *freelist_new,
-			   unsigned long tid)
-{
-	struct freelist_tid old = { .freelist = freelist_old, .tid = tid };
-	struct freelist_tid new = { .freelist = freelist_new, .tid = next_tid(tid) };
-
-	return this_cpu_try_cmpxchg_freelist(s->cpu_slab->freelist_tid,
-					     &old.freelist_tid, new.freelist_tid);
-}
-
 /*
  * Get the slab's freelist and do not freeze it.
  *
@@ -6158,99 +6123,6 @@ void defer_free_barrier(void)
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
@@ -6267,7 +6139,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 			return;
 	}
 
-	do_slab_free(s, slab, object, object, 1, addr);
+	__slab_free(s, slab, object, object, 1, addr);
 }
 
 #ifdef CONFIG_MEMCG
@@ -6276,7 +6148,7 @@ static noinline
 void memcg_alloc_abort_single(struct kmem_cache *s, void *object)
 {
 	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
-		do_slab_free(s, virt_to_slab(object), object, object, 1, _RET_IP_);
+		__slab_free(s, virt_to_slab(object), object, object, 1, _RET_IP_);
 }
 #endif
 
@@ -6291,7 +6163,7 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
 	 * to remove objects, whose reuse must be delayed.
 	 */
 	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
-		do_slab_free(s, slab, head, tail, cnt, addr);
+		__slab_free(s, slab, head, tail, cnt, addr);
 }
 
 #ifdef CONFIG_SLUB_RCU_DEBUG
@@ -6317,14 +6189,14 @@ static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
 
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
 
@@ -6524,8 +6396,13 @@ void kfree_nolock(const void *object)
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
 
@@ -6951,7 +6828,7 @@ static void __kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 		if (kfence_free(df.freelist))
 			continue;
 
-		do_slab_free(df.s, df.slab, df.freelist, df.tail, df.cnt,
+		__slab_free(df.s, df.slab, df.freelist, df.tail, df.cnt,
 			     _RET_IP_);
 	} while (likely(size));
 }
@@ -7037,7 +6914,7 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
 				cnt++;
 				object = get_freepointer(s, object);
 			} while (object);
-			do_slab_free(s, slab, head, tail, cnt, _RET_IP_);
+			__slab_free(s, slab, head, tail, cnt, _RET_IP_);
 		}
 
 		if (refilled >= max)

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-11-98225cfb50cf%40suse.cz.

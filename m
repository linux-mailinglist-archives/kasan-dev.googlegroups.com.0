Return-Path: <kasan-dev+bncBDXYDPH3S4OBB543VHFQMGQEPBTYFPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 32E85D32C64
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:40:58 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-59b796a0e40sf1756742e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:40:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574456; cv=pass;
        d=google.com; s=arc-20240605;
        b=A/JL7I7z5b1ml3aCFtlqD/AXqUSHwHODAQ7o34RxqfWViIyT0QOc0RK0ulFt677tsv
         fGXCXbQIhMvd+uYcqZU2xgKFoiNQnr/hkItebJUgqcGqcbiI9lwLGNMO6rm8glVSsFFG
         doej5A9UHyzcr80okvOcs9Z7hZo1B9V1VRHcvqKk6l9re7yqbZu8lk/b2HZH0s6r7gI+
         E4Rz85TxEoUovGmTMzE3okKzc9JUGc1VMiSvtebuU9xCjfrsdJt9+m5IHRfd4ohyxRm7
         8jnqadq74AneyVoTrEdBbiUeoZWPwFjgRhnZkhXjJQowpeWva+1lIn3JQIFXwad8YCs/
         TZFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=dgG0ejLIEZRbaviQlhPMXQP7Prq3JkTYGJCQMAAN/Kw=;
        fh=erKNLj0RPpmR08nqAk9x+GMJ708XHA/bAsfxkE0vEEc=;
        b=RoCe9fRb0BpdDvh3r1Wxz6tWHhNrH/cYLxAMpWorqGJj4btnhaQswGpAWCSxpsgoG0
         2R6q9YvEdUtkJlGbaodLamMx05u/utOXsJo8yaz5P3GV4/VnB39YkTfWgN+wmmdkV9NB
         Xsj1Y3ULvtWeaDWpMRY1mPUo8PAfzXzBj7SJQ31huWNtxa8VsMIBn0Qpf5MryN5qvju3
         VTIMnwZpAePw8r1rEPU1ajXTDZsussZtBRRZ5HB6dxdTNwZ9/bU8WNQxhwrPQ+HZlsll
         IGNBb8GHGtii9h+NK3dG/2OGPTrBMR99nkNvg7ySzqk+oZEdaKSkjmso5mv3co54ghtz
         gXtA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TGAuPHLM;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TGAuPHLM;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574456; x=1769179256; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dgG0ejLIEZRbaviQlhPMXQP7Prq3JkTYGJCQMAAN/Kw=;
        b=ml2QxtFnOcABPyw0sYel97nfmhJ8CGHkRj2PDxNAjDsaVrGjosRoDGFsG67DOLWXzY
         c6czd6MVaIsvYC6xenL6eNvZaQK5IMC3G5gY4Uggb6TDMSliizBTcO3frlEBRem8bkX1
         7hTG29A6l2wgUgvXO+q9tcZi6qzJiZ+JLj9Q/QFpIHt0eQrA0RydQ0nq3kz0vb6z0XKC
         /kql8SA4ZRVbUMMakE34CDrMBaNPvXI6KGe2TrQdfP2Wm3/vEYwnxRpmT9sdVUeqVAkx
         k4MaUX3D9IEt+Wr/5Zc7v26qGQ1hLoZgJ+jZlKeT999RiFmoNU+Z0Zfqk5WyZ1ZBodPY
         Lfzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574456; x=1769179256;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dgG0ejLIEZRbaviQlhPMXQP7Prq3JkTYGJCQMAAN/Kw=;
        b=ullsiaZqLpMJlIDsPuCmhc9ckcWKy9teujqagF+06MclnJoP2ZW3c/h9d1c1iwn7Kc
         Ow3kkazlm7pKp3dxHn7eUYatpT/aIEylUvHUWQ908s9jODoI7yLAXF4ecCIihL1kHmUF
         N7/nIyEXW6oSiZ9snR0PJEdkqRP1Ic8eu/dR1odZyqNkIKV0kURlPtjmEJmRBRNfFy07
         DDG8R2vFl5oBC3tth++KjHaztho0jA1tNDtXrmD8qiNikh9W5qccJOYjLGLVxpbb5GAV
         xyxuHdGQjI7y5iqIfQ3H/EmXvjJOeNjbC+Mow/uNTg9Vnchh6/xutLVySsV9Syc6xpke
         UHGA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXpDMDfSuvGoo/JHc9YUAZfJwXY/XRz+yt/ZE5vQl9rXb95yykGizoAFEWYWcoZsi0Zvjndew==@lfdr.de
X-Gm-Message-State: AOJu0YziH3C9H/HOVHOSjnxP2CdT4vw2ay0pf/7SLeS9UIWVUDwGsDUv
	frOU9szOWMf8sqZO0Vn87CjnXzgxrjGAkr37A7QP8RlwzrLD+Lj5xmFb
X-Received: by 2002:a05:6512:2310:b0:598:8f90:eff2 with SMTP id 2adb3069b0e04-59baffe8eeemr993300e87.50.1768574456335;
        Fri, 16 Jan 2026 06:40:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H6odPgK9AaKf0UioJxkvUphrbPfxqxwDO6+Crrs2AAzg=="
Received: by 2002:a05:6512:31d2:b0:59b:7bbc:799e with SMTP id
 2adb3069b0e04-59ba6b4b064ls822092e87.1.-pod-prod-04-eu; Fri, 16 Jan 2026
 06:40:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXqG6yDM6e936vKkvOU2h1WN1JPzbgvmOknmlWxfofoUV1gPLqAE6RSiz2cBvZZqXo4W6WyzgJQO/E=@googlegroups.com
X-Received: by 2002:a05:6512:3e14:b0:594:39bf:6d4b with SMTP id 2adb3069b0e04-59baffdd15fmr855660e87.46.1768574453569;
        Fri, 16 Jan 2026 06:40:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574453; cv=none;
        d=google.com; s=arc-20240605;
        b=V8hXS4ZYiuF8BU4AvQcBzzTDEVnAHu4E2vtxCoJXzXsaaz88pE0DwRYYodyIsRxUSe
         bkZz58478Z37+xfEO49PICyDRb7RmqKOhFEyzKBzXv9BbTNgcXpDVwN6LcTpbHZMvg5S
         xH6mIuinFb1lacld34ABLCa0oqjK33/M4C37iwIA33cT5gpcmp0vMVcSGq2Xug2wbbo4
         QUaCLUb0udhJmEWZ8VoMiFBbHkkdkl4Uwa3pSF7EHSc3drIq2P1Hw1oe/wRtsuTS4/xt
         094vmay8GIIyZmAWuS5YufTH62ZxIBLqagadaBDjrK+Kja/sVBQh2opy++IkOF0AU1AN
         i8Gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=1zCFUxTR6Bz27ufJId/W/RTWyhVuq6m8QvGcv4tOF6U=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=QG56Lq25VQLBauxCC4URzhWMOQCbR0/nPSQEpBJp2SS3mttG0SJUnBGzn3jumJP0KA
         QKaY3zxGwJKcz+PoH27LAbfb23fXRqMUwLfRCZwnQ+pIWpT59rg8XyvAomvjGH7H4ioA
         XDAZ5AhSC8WjNM1m0b9PlzpW7EvHdje9iUoDdK0gjDTB/15z2URheS3gn2+PiQoDuxfX
         Q0/RQiwonkVvSTM7dHsPpivE8Kfu+Sxnq+r2pnUUCPg9R8sgJnHteQiMJVyAnyhYjQOk
         smWL/dLjOzxjXQg4Ueez4YHYv8aS0/AyooXtqdxHe8bQmxcdVxUhM4kWIA+GQb/GtRE+
         noOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TGAuPHLM;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TGAuPHLM;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59baf3a1d4asi47873e87.8.2026.01.16.06.40.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:40:53 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id F29EB5BE45;
	Fri, 16 Jan 2026 14:40:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D05D23EA66;
	Fri, 16 Jan 2026 14:40:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 0LyVMuVNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:37 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:32 +0100
Subject: [PATCH v3 12/21] slab: remove the do_slab_free() fastpath
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-12-5595cb000772@suse.cz>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
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
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.999];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[18];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	R_RATELIMIT(0.00)[to_ip_from(RLwn5r54y1cp81no5tmbbew5oc)]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=TGAuPHLM;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=TGAuPHLM;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 149 ++++++--------------------------------------------------------
 1 file changed, 13 insertions(+), 136 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 6b1280f7900a..b08e775dc4cb 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3682,29 +3682,6 @@ static inline unsigned int init_tid(int cpu)
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
@@ -4243,18 +4220,6 @@ static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags)
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
@@ -6162,99 +6127,6 @@ void defer_free_barrier(void)
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
@@ -6271,7 +6143,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 			return;
 	}
 
-	do_slab_free(s, slab, object, object, 1, addr);
+	__slab_free(s, slab, object, object, 1, addr);
 }
 
 #ifdef CONFIG_MEMCG
@@ -6280,7 +6152,7 @@ static noinline
 void memcg_alloc_abort_single(struct kmem_cache *s, void *object)
 {
 	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
-		do_slab_free(s, virt_to_slab(object), object, object, 1, _RET_IP_);
+		__slab_free(s, virt_to_slab(object), object, object, 1, _RET_IP_);
 }
 #endif
 
@@ -6295,7 +6167,7 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
 	 * to remove objects, whose reuse must be delayed.
 	 */
 	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
-		do_slab_free(s, slab, head, tail, cnt, addr);
+		__slab_free(s, slab, head, tail, cnt, addr);
 }
 
 #ifdef CONFIG_SLUB_RCU_DEBUG
@@ -6321,14 +6193,14 @@ static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
 
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
 
@@ -6528,8 +6400,13 @@ void kfree_nolock(const void *object)
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
 
@@ -6955,7 +6832,7 @@ static void __kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 		if (kfence_free(df.freelist))
 			continue;
 
-		do_slab_free(df.s, df.slab, df.freelist, df.tail, df.cnt,
+		__slab_free(df.s, df.slab, df.freelist, df.tail, df.cnt,
 			     _RET_IP_);
 	} while (likely(size));
 }
@@ -7041,7 +6918,7 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-12-5595cb000772%40suse.cz.

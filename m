Return-Path: <kasan-dev+bncBDXYDPH3S4OBBC5BSTFQMGQEX72GNKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 433F5D13910
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:33 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-64d1982d980sf8592869a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231052; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jv4X9Zd+WrK6hYzEWJiZvvnJQV06xMNWi7j1SCeg6959OXvesIxTwp1706oEvp7vD3
         bpplCCwNYy6vrZ6CMdo19UFpLjbAHUfQLTErwvnjz58E0P3M0YeDPgDH00VOXa3wW56B
         fNDzQP2Y8iwC4KXuOLxiMSar7sUR81wGFEO6COBayp2ZEf6yUSCgM87G8+3DJylxB5uE
         Xq7zWMiJ4BJBRT469/wxxcWbje47LKKsAA9bEIBg8yBSiJBVVZTy3bC3jUjajdoCfuAH
         g5Ke64tmCALU2Z2xu/zzt7benuHZ5Hwh29FIZ1bUlWCAFnpki5RDvEPtaUmB60T8DWXs
         X6UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=FvnNvQz9motur8HdahPKw5z2Tb/fgtgWFCIdKeGSqps=;
        fh=kQZTyeb87oU22/EHaxSYNvBM+P63+Xk/xxPPHG2tdbM=;
        b=UsUOYuB0XwQPYaQfW+sAYC0xMvmye22Exbj/5H7eVk24edoX87UD2MbXSdnZr3d/6T
         JRb0nN7R8z9mOOtqSbC3LAFjm6skTqKd2UDhZkrykOuVjng6dieGHG8bttlfgQk7+K2f
         +0gnAEoCwb50C4JHTVGL+DMSFB3ngTE8/xbYqMOdf4lPX4nf5smcMbxPG+LYD2OO/FEW
         S3xLxulyc10o4N/dxOwcwjUYprfPRXaXq3iwqYbxs8mo+zFSl9K9hoBYsdFXyiQPgTUm
         ZDSlZhXuWHvK82CdrBy7Cd2cjwn5UUM6EGdZP4JQdKAGyBz82Tj5oTHZZRUR/qJBBB8q
         GtuA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231052; x=1768835852; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FvnNvQz9motur8HdahPKw5z2Tb/fgtgWFCIdKeGSqps=;
        b=PSDeAYerqMFWmge8Ks+au+ScJ0wXK0mrLkARig/aK7xlg5toOJVXnOrV5ZTb92aayW
         Oi6SoFrIt0csy61o3LurOLGY/dBB3YkKJi5c9zqgT/WQDD0K7ICcQJpRfPIKoXbBfAQj
         q9URZhuzYwHfndI1k0e7tmjNsd5o4QVcvPS45JVlZSLCTIfW0pV8Qh3SP6No2yDdDe/C
         bN0e+zZSa+A597Mt8aLE+nkJx6TH/P/KPL000TSRr8YYft5l/XdQ9PA5Vs++m+fLNPnc
         8U/4LBFvD28/eh9WalL4xHzwwxFHRGnYGEZx4Dtd+xV4SQtZu/LlH+2joo7+tb0wgtAj
         sNyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231052; x=1768835852;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FvnNvQz9motur8HdahPKw5z2Tb/fgtgWFCIdKeGSqps=;
        b=BCCkkpVCXqzrMZKReviA2I+EEv0JivtHNkPspO80gRIjkKncIQf3KrrdajymijVl5f
         YMSNsurNvEnWEY4QxdkmwXGlJcuse5dnpxs2knHGg8sRfCxIvLfYL9W7pR2KOKX5pAmC
         Yx5Hx6NQuRAOOhYJ+H0qF2+8t0kxWAUWfhwjouRYiDQ3zjfEBTkRcixI6TQxKFFeoF48
         NAxirKjMEry/oTCUrWKK3GUPVrGzv9Zw/J7Whvzq2hSmW+6uyTuNgB8JCUiq1P39aAs7
         StVhBqnmyI6+xTSdVq7Vc9MzPxZBT1Ozr2vSpLNlZaKbypIOIAgVAtF5I73K7Uz8UCYq
         ZMeA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWFN3cjXcZKZY/GtJG6NY679f07Skk238p0vuA4blp0nbWosCvEkqWKXIR6snxrceFo6aGVkQ==@lfdr.de
X-Gm-Message-State: AOJu0YzFj6ezZrbdCEy8T2duQstHEtFZljb2gqjXnn402Y9VaHR7p8l1
	C8cdAsTBMFJt4TMJ7M1wrUjW/tyXE8vATl/9mSQ1T22Nk4MxErpyt6k/
X-Google-Smtp-Source: AGHT+IEGB0x6uObQF+HDUYyC6fJegg5sYmONI76Q/cgAy9agf9+NCaOfagnYgS3qeZJOPscuuoJqyQ==
X-Received: by 2002:a05:6402:4408:b0:64b:83cb:d943 with SMTP id 4fb4d7f45d1cf-65097dcba4fmr17893237a12.6.1768231052401;
        Mon, 12 Jan 2026 07:17:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FDKcT5kOUSSmeqdhhYWqsZu4ql5zPd3TfchqySzsemJA=="
Received: by 2002:aa7:c487:0:b0:64d:faf4:f73e with SMTP id 4fb4d7f45d1cf-650743340b5ls5792471a12.0.-pod-prod-05-eu;
 Mon, 12 Jan 2026 07:17:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWtZ3QjrRyO/BhxK6/1ioVho4VMi1vcXT8z92wfOJBGbjy0WimRx4WLVqLJyfOH4N9uSkart/tNjrE=@googlegroups.com
X-Received: by 2002:a17:907:a08:b0:b72:7cd3:d55b with SMTP id a640c23a62f3a-b84451694e0mr1899992066b.12.1768231049923;
        Mon, 12 Jan 2026 07:17:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231049; cv=none;
        d=google.com; s=arc-20240605;
        b=DdAkN0GELL8P15GJQOQHFFLFIjlm3ktSiBWjZMoW7fgAbBjOLIpqTZBR8nuMbidlze
         UOwYleCdJ9puNeXcHu0xjiemOPCTB1R54gOrij+kJj4/9SggrcazMNnLMOxd2GPWmgV7
         tfe6fTQvl194CyIb2ITm9ZUuGbMMYGa1Xdbqu7VYsXSRcbtJFgvbe+5QNBkDBIpDZWaa
         7/rIl+n03Xg92/qCilacOuYnBUeXlz4Y8lcEYz5OHTA88TwRMvXDxgTeBKr29PuvXSAZ
         Kt2z5ar/1LctVaj1bM4JNQMhyM1UoAwQmFcewau6z6pWZ0ZMlAt0BqwEn6b/21R0SXcq
         3Z/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=w348dUZyoPi7wkt0W2Bp5ZFw39tDylKXV3508KD8AX8=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=aswxN9Xl9OC3F4Ysux7uHKeNCYAJncgSPUXb4RbkHp3TpymyGs0JB7NRosdWHCeYrK
         4f3Jt1X+aHZvsM8CpLveHLYjtsNHF9MsYeAa6L643znhOJOMp7YbGA5xpOcNwpYlaRwK
         wnwTU7D7bSp0GjcnMVPn0+3mEn1+NtPSI0ZatT9dE4CyM608whuLE8w9aMJrmFy66Piq
         E4+qtHZHnCcFoV+qB/MX0jbGqq9Z4LlfG4m0N6/0fui/tsw5L4xKhm47JunmF4aCUUXn
         +evup9fY5sZnKPcBDLTSYnzYR1G3fc0EYiVgH0hcT4d72GAVz3A3sGnS0+m3NCwfLgzv
         wGmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b870059843csi11378866b.1.2026.01.12.07.17.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:29 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A4A0C5BCD8;
	Mon, 12 Jan 2026 15:16:59 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 886A23EA65;
	Mon, 12 Jan 2026 15:16:59 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id EB0MIWsQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:59 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:17:14 +0100
Subject: [PATCH RFC v2 20/20] mm/slub: cleanup and repurpose some stat
 items
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-20-98225cfb50cf@suse.cz>
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
X-Rspamd-Queue-Id: A4A0C5BCD8
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Level: 
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Spam-Flag: NO
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

A number of stat items related to cpu slabs became unused, remove them.

Two of those were ALLOC_FASTPATH and FREE_FASTPATH. But instead of
removing those, use them instead of ALLOC_PCS and FREE_PCS, since
sheaves are the new (and only) fastpaths, Remove the recently added
_PCS variants instead.

Change where FREE_SLOWPATH is counted so that it only counts freeing of
objects by slab users that (for whatever reason) do not go to a percpu
sheaf, and not all (including internal) callers of __slab_free(). Thus
flushing sheaves (counted by SHEAF_FLUSH) no longer also increments
FREE_SLOWPATH. This matches how ALLOC_SLOWPATH doesn't count sheaf
refills (counted by SHEAF_REFILL).

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 77 +++++++++++++++++----------------------------------------------
 1 file changed, 21 insertions(+), 56 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index a473fa29a905..70314c72773e 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -330,33 +330,19 @@ enum add_mode {
 };
 
 enum stat_item {
-	ALLOC_PCS,		/* Allocation from percpu sheaf */
-	ALLOC_FASTPATH,		/* Allocation from cpu slab */
-	ALLOC_SLOWPATH,		/* Allocation by getting a new cpu slab */
-	FREE_PCS,		/* Free to percpu sheaf */
+	ALLOC_FASTPATH,		/* Allocation from percpu sheaves */
+	ALLOC_SLOWPATH,		/* Allocation from partial or new slab */
 	FREE_RCU_SHEAF,		/* Free to rcu_free sheaf */
 	FREE_RCU_SHEAF_FAIL,	/* Failed to free to a rcu_free sheaf */
-	FREE_FASTPATH,		/* Free to cpu slab */
-	FREE_SLOWPATH,		/* Freeing not to cpu slab */
+	FREE_FASTPATH,		/* Free to percpu sheaves */
+	FREE_SLOWPATH,		/* Free to a slab */
 	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
 	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
-	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from node partial list */
-	ALLOC_SLAB,		/* Cpu slab acquired from page allocator */
-	ALLOC_REFILL,		/* Refill cpu slab from slab freelist */
-	ALLOC_NODE_MISMATCH,	/* Switching cpu slab */
+	ALLOC_SLAB,		/* New slab acquired from page allocator */
+	ALLOC_NODE_MISMATCH,	/* Requested node different from cpu sheaf */
 	FREE_SLAB,		/* Slab freed to the page allocator */
-	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
-	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
-	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
-	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
-	DEACTIVATE_BYPASS,	/* Implicit deactivation */
 	ORDER_FALLBACK,		/* Number of times fallback was necessary */
-	CMPXCHG_DOUBLE_CPU_FAIL,/* Failures of this_cpu_cmpxchg_double */
 	CMPXCHG_DOUBLE_FAIL,	/* Failures of slab freelist update */
-	CPU_PARTIAL_ALLOC,	/* Used cpu partial on alloc */
-	CPU_PARTIAL_FREE,	/* Refill cpu partial on free */
-	CPU_PARTIAL_NODE,	/* Refill cpu partial from node partial */
-	CPU_PARTIAL_DRAIN,	/* Drain cpu partial to node partial */
 	SHEAF_FLUSH,		/* Objects flushed from a sheaf */
 	SHEAF_REFILL,		/* Objects refilled to a sheaf */
 	SHEAF_ALLOC,		/* Allocation of an empty sheaf */
@@ -4330,8 +4316,10 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
 	 * We assume the percpu sheaves contain only local objects although it's
 	 * not completely guaranteed, so we verify later.
 	 */
-	if (unlikely(node_requested && node != numa_mem_id()))
+	if (unlikely(node_requested && node != numa_mem_id())) {
+		stat(s, ALLOC_NODE_MISMATCH);
 		return NULL;
+	}
 
 	if (!local_trylock(&s->cpu_sheaves->lock))
 		return NULL;
@@ -4354,6 +4342,7 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
 		 */
 		if (page_to_nid(virt_to_page(object)) != node) {
 			local_unlock(&s->cpu_sheaves->lock);
+			stat(s, ALLOC_NODE_MISMATCH);
 			return NULL;
 		}
 	}
@@ -4362,7 +4351,7 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
 
 	local_unlock(&s->cpu_sheaves->lock);
 
-	stat(s, ALLOC_PCS);
+	stat(s, ALLOC_FASTPATH);
 
 	return object;
 }
@@ -4434,7 +4423,7 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, gfp_t gfp, size_t size,
 
 	local_unlock(&s->cpu_sheaves->lock);
 
-	stat_add(s, ALLOC_PCS, batch);
+	stat_add(s, ALLOC_FASTPATH, batch);
 
 	allocated += batch;
 
@@ -5101,8 +5090,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 	unsigned long flags;
 	bool on_node_partial;
 
-	stat(s, FREE_SLOWPATH);
-
 	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
 		free_to_partial_list(s, slab, head, tail, cnt, addr);
 		return;
@@ -5408,7 +5395,7 @@ bool free_to_pcs(struct kmem_cache *s, void *object, bool allow_spin)
 
 	local_unlock(&s->cpu_sheaves->lock);
 
-	stat(s, FREE_PCS);
+	stat(s, FREE_FASTPATH);
 
 	return true;
 }
@@ -5659,7 +5646,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 
 	local_unlock(&s->cpu_sheaves->lock);
 
-	stat_add(s, FREE_PCS, batch);
+	stat_add(s, FREE_FASTPATH, batch);
 
 	if (batch < size) {
 		p += batch;
@@ -5681,10 +5668,12 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 	 */
 fallback:
 	__kmem_cache_free_bulk(s, size, p);
+	stat_add(s, FREE_SLOWPATH, size);
 
 flush_remote:
 	if (remote_nr) {
 		__kmem_cache_free_bulk(s, remote_nr, &remote_objects[0]);
+		stat_add(s, FREE_SLOWPATH, remote_nr);
 		if (i < size) {
 			remote_nr = 0;
 			goto next_remote_batch;
@@ -5777,6 +5766,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	}
 
 	__slab_free(s, slab, object, object, 1, addr);
+	stat(s, FREE_SLOWPATH);
 }
 
 #ifdef CONFIG_MEMCG
@@ -5799,8 +5789,10 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
 	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
 	 * to remove objects, whose reuse must be delayed.
 	 */
-	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
+	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt))) {
 		__slab_free(s, slab, head, tail, cnt, addr);
+		stat_add(s, FREE_SLOWPATH, cnt);
+	}
 }
 
 #ifdef CONFIG_SLUB_RCU_DEBUG
@@ -6699,6 +6691,7 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 		i = refill_objects(s, p, flags, size, size);
 		if (i < size)
 			goto error;
+		stat_add(s, ALLOC_SLOWPATH, i);
 	}
 
 	return i;
@@ -8698,33 +8691,19 @@ static ssize_t text##_store(struct kmem_cache *s,		\
 }								\
 SLAB_ATTR(text);						\
 
-STAT_ATTR(ALLOC_PCS, alloc_cpu_sheaf);
 STAT_ATTR(ALLOC_FASTPATH, alloc_fastpath);
 STAT_ATTR(ALLOC_SLOWPATH, alloc_slowpath);
-STAT_ATTR(FREE_PCS, free_cpu_sheaf);
 STAT_ATTR(FREE_RCU_SHEAF, free_rcu_sheaf);
 STAT_ATTR(FREE_RCU_SHEAF_FAIL, free_rcu_sheaf_fail);
 STAT_ATTR(FREE_FASTPATH, free_fastpath);
 STAT_ATTR(FREE_SLOWPATH, free_slowpath);
 STAT_ATTR(FREE_ADD_PARTIAL, free_add_partial);
 STAT_ATTR(FREE_REMOVE_PARTIAL, free_remove_partial);
-STAT_ATTR(ALLOC_FROM_PARTIAL, alloc_from_partial);
 STAT_ATTR(ALLOC_SLAB, alloc_slab);
-STAT_ATTR(ALLOC_REFILL, alloc_refill);
 STAT_ATTR(ALLOC_NODE_MISMATCH, alloc_node_mismatch);
 STAT_ATTR(FREE_SLAB, free_slab);
-STAT_ATTR(CPUSLAB_FLUSH, cpuslab_flush);
-STAT_ATTR(DEACTIVATE_FULL, deactivate_full);
-STAT_ATTR(DEACTIVATE_EMPTY, deactivate_empty);
-STAT_ATTR(DEACTIVATE_REMOTE_FREES, deactivate_remote_frees);
-STAT_ATTR(DEACTIVATE_BYPASS, deactivate_bypass);
 STAT_ATTR(ORDER_FALLBACK, order_fallback);
-STAT_ATTR(CMPXCHG_DOUBLE_CPU_FAIL, cmpxchg_double_cpu_fail);
 STAT_ATTR(CMPXCHG_DOUBLE_FAIL, cmpxchg_double_fail);
-STAT_ATTR(CPU_PARTIAL_ALLOC, cpu_partial_alloc);
-STAT_ATTR(CPU_PARTIAL_FREE, cpu_partial_free);
-STAT_ATTR(CPU_PARTIAL_NODE, cpu_partial_node);
-STAT_ATTR(CPU_PARTIAL_DRAIN, cpu_partial_drain);
 STAT_ATTR(SHEAF_FLUSH, sheaf_flush);
 STAT_ATTR(SHEAF_REFILL, sheaf_refill);
 STAT_ATTR(SHEAF_ALLOC, sheaf_alloc);
@@ -8800,33 +8779,19 @@ static struct attribute *slab_attrs[] = {
 	&remote_node_defrag_ratio_attr.attr,
 #endif
 #ifdef CONFIG_SLUB_STATS
-	&alloc_cpu_sheaf_attr.attr,
 	&alloc_fastpath_attr.attr,
 	&alloc_slowpath_attr.attr,
-	&free_cpu_sheaf_attr.attr,
 	&free_rcu_sheaf_attr.attr,
 	&free_rcu_sheaf_fail_attr.attr,
 	&free_fastpath_attr.attr,
 	&free_slowpath_attr.attr,
 	&free_add_partial_attr.attr,
 	&free_remove_partial_attr.attr,
-	&alloc_from_partial_attr.attr,
 	&alloc_slab_attr.attr,
-	&alloc_refill_attr.attr,
 	&alloc_node_mismatch_attr.attr,
 	&free_slab_attr.attr,
-	&cpuslab_flush_attr.attr,
-	&deactivate_full_attr.attr,
-	&deactivate_empty_attr.attr,
-	&deactivate_remote_frees_attr.attr,
-	&deactivate_bypass_attr.attr,
 	&order_fallback_attr.attr,
 	&cmpxchg_double_fail_attr.attr,
-	&cmpxchg_double_cpu_fail_attr.attr,
-	&cpu_partial_alloc_attr.attr,
-	&cpu_partial_free_attr.attr,
-	&cpu_partial_node_attr.attr,
-	&cpu_partial_drain_attr.attr,
 	&sheaf_flush_attr.attr,
 	&sheaf_refill_attr.attr,
 	&sheaf_alloc_attr.attr,

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-20-98225cfb50cf%40suse.cz.

Return-Path: <kasan-dev+bncBDXYDPH3S4OBBP7G5DDQMGQEMUWGVHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id C21F5C018CD
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:05 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-47496b3c1dcsf6233665e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227585; cv=pass;
        d=google.com; s=arc-20240605;
        b=WP37Xv0syP2SCmtNIw9komL5Bg9yJPJd58u46XnQHX54+Hyg8+7voJNf3O7m9e6KP+
         2Spf1F8PZ/AjIBCQcPeIgzgpvKyom/rBtB5RjEuSkgenRd/xvvyNd1759Zm2mNBk726j
         NVy2we8QQplA+ARw/jIDPvFO/96xvE7VLW75cBj6gMDj2YJl5XOO6CmDCgDIUwPQ7h0z
         rC9qBl4Dy3wmIYXTqmiVHTpRRdWewVm10D+qLRJEkstWXcRmbLxCzq1aexYy0vuYdKAh
         L9EmG2w5UznSybBSrVtQITKQLxVcoMloCi0pfWQ/LdhrZ6rXh4suPiHfgyzS4bZ+OGJB
         IzqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=tS3HXnn3WMJQGh2NIWL4zPfmuv1upO3KHnV2NeFcaro=;
        fh=jKL8OMLI9Symuicn0314hEjq9D0ngDpvVZajowoRGXU=;
        b=DZRV6wM+vPCGTqxta6Z58BjYxAlOwY+WfLH1Aa0EkMf0YfFRXu1NelL8wzRmWkD4gk
         PhzBD1RlXQwP7hBQTlH5waDYA3ZC93lGGqpRnFHOoxTJf6da4ddwJ/MDjcQvig1TNuZe
         LNYfQSyWnGz6zW3xQubmBXoKvviuZyw6CQsOFH5wRICw8BRV25sZBsA1LZ9Ao68YJhc7
         oLAoTd8gq71ATSHVLq/ONiq6R46p7FriE33kttdYMWLg7Y2gRPatmyntKO96NWk+KbzO
         RhnKRqQTBtPpxydZaitVL/hFUPFgGaP40Qx15w5CzeGESLBlVPLlK8ae5+46W1JhsSdF
         wzog==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227585; x=1761832385; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tS3HXnn3WMJQGh2NIWL4zPfmuv1upO3KHnV2NeFcaro=;
        b=t76kT9JjsmnRfd7lyXy3lJA3sh4VLzRi7vzcsjrF2l/UATX2BnMgFgQ2lH7429tzur
         bnl/BM7i0Zelr3N7F8yUhFLFZ6sFfH8qDPrAL6ORoApm0cn9Hh9+vl3JgdJE+z44Z4uS
         cT91QiHi2DvvUESmPM/0PHLLnUN+L2c5bg3iXpBoHlEc0BJPOoqq0Vg8yRVgCBhbfJH0
         /BWROdlpT0x/49WOC73wyGeTZzo/4yQj6GGLvcMIhRBYr9H8ogVd8gHiQyXjOsmFIM4f
         AZmYnulJF9ohqer0h5J5TDIt5k3UmrMAvXQffLCusF4DATCh96GEsPP+BMXcpLewSkSs
         oEmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227585; x=1761832385;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tS3HXnn3WMJQGh2NIWL4zPfmuv1upO3KHnV2NeFcaro=;
        b=EBY0zqfOHkV0QWXkqbzC9O72sfGUZIgZGPBu13Uh5+Yywq6PxALInglOzudpq66HeZ
         KNN7qiiWtuXiPta+U22Zc1IXMinEYiHy0AOGIzJ8ufyGENh2Xm5IRbGBmJgOavtyIQym
         xGT/2QGiFi24LJd4XmcII/nPRJAh6qH7wr7JgVTCPmrB4S2zk7m0aM58tYsXraeqBH1y
         FuQAvR/XVdkcXqGJu5NYoqwquhYoj2joEm69q2TZ341iXlNPQOw9TPX/t9dMpz3aS6HP
         q4l74fb8yBCJFQ+WWlUH61+s56yXSTP2psPr8vOjptzwRxcPbJ1qVCRFdEf3epNCA01b
         GTWA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUpYkZV2ZzJ+lp8IW9tjsEf4h0Oi30Z+0PKTw7DzbHB+pz8nXSnP8lk2FQrg2biHuw0600KuA==@lfdr.de
X-Gm-Message-State: AOJu0YynCIucUbNeTeY3RHwTCAuKPYZyk9GTw38dUhaWlATtlhTzPUkl
	puLDdNctDxYicIvuVKutsyMMHW8OkFoxeU5jUs2ukQiWmGwXnwy7TQnp
X-Google-Smtp-Source: AGHT+IEVJo7qYvNbUApP81IKMVotRlU2wqF+z2vwIZUNM5cAS1xcnY6v5Nw+v1hYPOuW0r6OntqG+A==
X-Received: by 2002:a05:600c:3b0a:b0:46e:4499:ba30 with SMTP id 5b1f17b1804b1-47117917a33mr209418595e9.30.1761227584754;
        Thu, 23 Oct 2025 06:53:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5A2VebWsq31uK0KD1M7RY/jiENb9Tju+15u5KTx5Uiaw=="
Received: by 2002:a05:600c:5253:b0:471:1492:474a with SMTP id
 5b1f17b1804b1-475caa7c0afls4207115e9.1.-pod-prod-02-eu; Thu, 23 Oct 2025
 06:53:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWsnnm8e70qNfX1Fn1TMpQY2fLGxEt6ZbARvVVjgucLOTL6JyAcWPdGSmdeO+7NWpi4l9qeg8Fshdg=@googlegroups.com
X-Received: by 2002:a05:600c:3513:b0:46e:32a5:bd8d with SMTP id 5b1f17b1804b1-471178726f9mr187285165e9.3.1761227581843;
        Thu, 23 Oct 2025 06:53:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227581; cv=none;
        d=google.com; s=arc-20240605;
        b=fJXFLf1hD56DPb5lqZ80NE46PHnqEa1t8ObD9kLSLRVLmXtaFl3uLNqcykXXF9a64S
         BWI6TQd24dje3/FTP7zVOFXS/+4kGEqOTj5KGbFJ4/X/LuII40MicDgG26tG+I9USI7e
         K0XPftPQSOHJz3Mh+cP9sjrobpZHmpbf1s9F1g8fZXGlczOiUVpxgqgsatCppwHtL6Lj
         r/3wGTNnULg1rbp26UzTVTFyMP6MKOKS38ZIKhgzX611GGWz+32sBAOmPPwFoy4UOaC6
         7ur3xwhtDD7NrtavaGnWuYJ7UHZYEQya1DjPLE5i/wydbg3YQYHwaFO4K5pGldrFi0t2
         GlYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=eS6GuMY77XE9huzfJRU6LAG6pUzwD4wWadGk/P9jC08=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=WxC1tkwTOVC3z3kgL8LngHJqQgyUMPT36LwOwB7y/z/xYl+0uvzXhLp1Vm7FVyYFE+
         ypiWfpXh+d9H7tP1eEgjUfVcsxP2Ejo1CWu10rlC3T3JGwYgGdFza5ZMTKREemNDEnqs
         HgD+IJif6ENwCG1DSt8aUtVKg6zhP+SvFUxFczNLs/sSGAHdIr9qlivXVX0vvKkw1XcN
         Z2n5FcAPoluHwaOxYlM8ln0HUlHoMCOzslMC4CEWWnzL3Cel+5W9UC9SYZfmNeXgmzOv
         lcAPa1dpJf8q09PRSIuKv3G0zIJLYYZHIgL+kzo1MRm1VOKZL3etGbIJynzKH+J6x8iG
         Xggg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-474949e008csi2371625e9.0.2025.10.23.06.53.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 75E561F769;
	Thu, 23 Oct 2025 13:53:01 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id ACAA713B03;
	Thu, 23 Oct 2025 13:52:53 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id QOvcKTUz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:53 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:29 +0200
Subject: [PATCH RFC 07/19] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-7-6ffa2c9941c0@suse.cz>
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
X-Rspamd-Queue-Id: 75E561F769
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

Before we enable percpu sheaves for kmalloc caches, we need to make sure
kmalloc_nolock() and kfree_nolock() will continue working properly and
not spin when not allowed to.

Percpu sheaves themselves use local_trylock() so they are already
compatible. We just need to be careful with the barn->lock spin_lock.
Pass a new allow_spin parameter where necessary to use
spin_trylock_irqsave().

In kmalloc_nolock_noprof() we can now attempt alloc_from_pcs() safely,
for now it will always fail until we enable sheaves for kmalloc caches
next. Similarly in kfree_nolock() we can attempt free_to_pcs().

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 74 ++++++++++++++++++++++++++++++++++++++++++++-------------------
 1 file changed, 52 insertions(+), 22 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index ecb10ed5acfe..5d0b2cf66520 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2876,7 +2876,8 @@ static void pcs_destroy(struct kmem_cache *s)
 	s->cpu_sheaves = NULL;
 }
 
-static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn)
+static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn,
+					       bool allow_spin)
 {
 	struct slab_sheaf *empty = NULL;
 	unsigned long flags;
@@ -2884,7 +2885,10 @@ static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn)
 	if (!data_race(barn->nr_empty))
 		return NULL;
 
-	spin_lock_irqsave(&barn->lock, flags);
+	if (likely(allow_spin))
+		spin_lock_irqsave(&barn->lock, flags);
+	else if (!spin_trylock_irqsave(&barn->lock, flags))
+		return NULL;
 
 	if (likely(barn->nr_empty)) {
 		empty = list_first_entry(&barn->sheaves_empty,
@@ -2961,7 +2965,8 @@ static struct slab_sheaf *barn_get_full_or_empty_sheaf(struct node_barn *barn)
  * change.
  */
 static struct slab_sheaf *
-barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
+barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty,
+			 bool allow_spin)
 {
 	struct slab_sheaf *full = NULL;
 	unsigned long flags;
@@ -2969,7 +2974,10 @@ barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
 	if (!data_race(barn->nr_full))
 		return NULL;
 
-	spin_lock_irqsave(&barn->lock, flags);
+	if (likely(allow_spin))
+		spin_lock_irqsave(&barn->lock, flags);
+	else if (!spin_trylock_irqsave(&barn->lock, flags))
+		return NULL;
 
 	if (likely(barn->nr_full)) {
 		full = list_first_entry(&barn->sheaves_full, struct slab_sheaf,
@@ -2990,7 +2998,8 @@ barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
  * barn. But if there are too many full sheaves, reject this with -E2BIG.
  */
 static struct slab_sheaf *
-barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
+barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full,
+			bool allow_spin)
 {
 	struct slab_sheaf *empty;
 	unsigned long flags;
@@ -3001,7 +3010,10 @@ barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
 	if (!data_race(barn->nr_empty))
 		return ERR_PTR(-ENOMEM);
 
-	spin_lock_irqsave(&barn->lock, flags);
+	if (likely(allow_spin))
+		spin_lock_irqsave(&barn->lock, flags);
+	else if (!spin_trylock_irqsave(&barn->lock, flags))
+		return NULL;
 
 	if (likely(barn->nr_empty)) {
 		empty = list_first_entry(&barn->sheaves_empty, struct slab_sheaf,
@@ -5000,7 +5012,8 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
 		return NULL;
 	}
 
-	full = barn_replace_empty_sheaf(barn, pcs->main);
+	full = barn_replace_empty_sheaf(barn, pcs->main,
+					gfpflags_allow_spinning(gfp));
 
 	if (full) {
 		stat(s, BARN_GET);
@@ -5017,7 +5030,7 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
 			empty = pcs->spare;
 			pcs->spare = NULL;
 		} else {
-			empty = barn_get_empty_sheaf(barn);
+			empty = barn_get_empty_sheaf(barn, true);
 		}
 	}
 
@@ -5154,7 +5167,8 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
 }
 
 static __fastpath_inline
-unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
+unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, gfp_t gfp, size_t size,
+				 void **p)
 {
 	struct slub_percpu_sheaves *pcs;
 	struct slab_sheaf *main;
@@ -5188,7 +5202,8 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 			return allocated;
 		}
 
-		full = barn_replace_empty_sheaf(barn, pcs->main);
+		full = barn_replace_empty_sheaf(barn, pcs->main,
+						gfpflags_allow_spinning(gfp));
 
 		if (full) {
 			stat(s, BARN_GET);
@@ -5693,7 +5708,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 	gfp_t alloc_gfp = __GFP_NOWARN | __GFP_NOMEMALLOC | gfp_flags;
 	struct kmem_cache *s;
 	bool can_retry = true;
-	void *ret = ERR_PTR(-EBUSY);
+	void *ret;
 
 	VM_WARN_ON_ONCE(gfp_flags & ~(__GFP_ACCOUNT | __GFP_ZERO |
 				      __GFP_NO_OBJ_EXT));
@@ -5720,6 +5735,13 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 		 */
 		return NULL;
 
+	ret = alloc_from_pcs(s, alloc_gfp, node);
+
+	if (ret)
+		goto success;
+
+	ret = ERR_PTR(-EBUSY);
+
 	/*
 	 * Do not call slab_alloc_node(), since trylock mode isn't
 	 * compatible with slab_pre_alloc_hook/should_failslab and
@@ -5756,6 +5778,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 		ret = NULL;
 	}
 
+success:
 	maybe_wipe_obj_freeptr(s, ret);
 	slab_post_alloc_hook(s, NULL, alloc_gfp, 1, &ret,
 			     slab_want_init_on_alloc(alloc_gfp, s), size);
@@ -6047,7 +6070,8 @@ static void __pcs_install_empty_sheaf(struct kmem_cache *s,
  * unlocked.
  */
 static struct slub_percpu_sheaves *
-__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
+__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
+			bool allow_spin)
 {
 	struct slab_sheaf *empty;
 	struct node_barn *barn;
@@ -6071,7 +6095,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
 	put_fail = false;
 
 	if (!pcs->spare) {
-		empty = barn_get_empty_sheaf(barn);
+		empty = barn_get_empty_sheaf(barn, allow_spin);
 		if (empty) {
 			pcs->spare = pcs->main;
 			pcs->main = empty;
@@ -6085,7 +6109,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
 		return pcs;
 	}
 
-	empty = barn_replace_full_sheaf(barn, pcs->main);
+	empty = barn_replace_full_sheaf(barn, pcs->main, allow_spin);
 
 	if (!IS_ERR(empty)) {
 		stat(s, BARN_PUT);
@@ -6093,6 +6117,11 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
 		return pcs;
 	}
 
+	if (!allow_spin) {
+		local_unlock(&s->cpu_sheaves->lock);
+		return NULL;
+	}
+
 	if (PTR_ERR(empty) == -E2BIG) {
 		/* Since we got here, spare exists and is full */
 		struct slab_sheaf *to_flush = pcs->spare;
@@ -6160,7 +6189,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
  * The object is expected to have passed slab_free_hook() already.
  */
 static __fastpath_inline
-bool free_to_pcs(struct kmem_cache *s, void *object)
+bool free_to_pcs(struct kmem_cache *s, void *object, bool allow_spin)
 {
 	struct slub_percpu_sheaves *pcs;
 
@@ -6171,7 +6200,7 @@ bool free_to_pcs(struct kmem_cache *s, void *object)
 
 	if (unlikely(pcs->main->size == s->sheaf_capacity)) {
 
-		pcs = __pcs_replace_full_main(s, pcs);
+		pcs = __pcs_replace_full_main(s, pcs, allow_spin);
 		if (unlikely(!pcs))
 			return false;
 	}
@@ -6278,7 +6307,7 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
 			goto fail;
 		}
 
-		empty = barn_get_empty_sheaf(barn);
+		empty = barn_get_empty_sheaf(barn, true);
 
 		if (empty) {
 			pcs->rcu_free = empty;
@@ -6398,7 +6427,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 		goto no_empty;
 
 	if (!pcs->spare) {
-		empty = barn_get_empty_sheaf(barn);
+		empty = barn_get_empty_sheaf(barn, true);
 		if (!empty)
 			goto no_empty;
 
@@ -6412,7 +6441,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 		goto do_free;
 	}
 
-	empty = barn_replace_full_sheaf(barn, pcs->main);
+	empty = barn_replace_full_sheaf(barn, pcs->main, true);
 	if (IS_ERR(empty)) {
 		stat(s, BARN_PUT_FAIL);
 		goto no_empty;
@@ -6659,7 +6688,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 
 	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())
 	    && likely(!slab_test_pfmemalloc(slab))) {
-		if (likely(free_to_pcs(s, object)))
+		if (likely(free_to_pcs(s, object, true)))
 			return;
 	}
 
@@ -6922,7 +6951,8 @@ void kfree_nolock(const void *object)
 	 * since kasan quarantine takes locks and not supported from NMI.
 	 */
 	kasan_slab_free(s, x, false, false, /* skip quarantine */true);
-	do_slab_free(s, slab, x, x, 0, _RET_IP_);
+	if (!free_to_pcs(s, x, false))
+		do_slab_free(s, slab, x, x, 0, _RET_IP_);
 }
 EXPORT_SYMBOL_GPL(kfree_nolock);
 
@@ -7465,7 +7495,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
 		size--;
 	}
 
-	i = alloc_from_pcs_bulk(s, size, p);
+	i = alloc_from_pcs_bulk(s, flags, size, p);
 
 	if (i < size) {
 		/*

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-7-6ffa2c9941c0%40suse.cz.

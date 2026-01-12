Return-Path: <kasan-dev+bncBDXYDPH3S4OBB4NASTFQMGQEQSPKANI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8ED88D138D4
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:06 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-64c7242a456sf9195894a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231026; cv=pass;
        d=google.com; s=arc-20240605;
        b=OeCElGLXykVskrbmAnK2yQplz8U5bAsYPrKDJjrUPF2HAZGkn4n+B5hDurocfWe6Wt
         fcprCwMmN1mxew4JIZ7ALkZ6DVcCIGw2okBJ2fvyeXTjjmDHp4+V8jEtGh8kGLpMZdTI
         Asz/04WEdSEHVS10f48gwYDsOff4dtjdHjfyXNCNEBbIzx5Scmdoqha5hBXX2NwowcTF
         APC7nWVXdlpHi/OPHIJJrh41Jfr05+06+N6rAeFTmKIZornD0AyWxEwNe/uwpZEMhToA
         k55jIaIqC+4pxkfUya2sCLDGR0GeeqN7PQqXWN0lrcnvO6kVi0vO/y6ATr5SFdvIWEY7
         ewFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=lGNGaj/ON3/kOdXDo8lwphgvrsL8uq7oynthk3sPJIE=;
        fh=7QhqdlTRV6cWvKkIGKyBjwDT19n68kicqnCAS6sJ/uA=;
        b=kYf5ncPncGfD+Xz0Tq30zgytrL7zMppoPfiNLX3pj31wbOukaJiZnTjskxg3CQ/SsW
         lV0jt5HJFEepKlDH21KRheH6AfmC1fFCPkvSf055DSkbITFaYZc6WVeWb3+ZjiVExs9n
         cxaO1riRNTil0EYBP/LxEdKTuRUSA1o9QiGKzrtUAotbGAxo0VP2NR+Q23Sw7gjI5x8Y
         tvhFU6AwjhhROzQuNomlycrS/7ozjVawZS7HlP8H6Trv6U2erVhsdP55gIthxd2bZ4cS
         WaZCWNWqKLlqPMZf5zkAMZ1gAImZBd7FYjRZ/AjTP3DuX32X06zUNZxTRYFU/CFxQpBb
         guHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231026; x=1768835826; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lGNGaj/ON3/kOdXDo8lwphgvrsL8uq7oynthk3sPJIE=;
        b=Pl04RTGvhEmuPvq2y2opcyUnP8OlcKKxYw/awpOvKGfDdZJWnLDmyHzRc2+iDxtAwh
         FVvJ+OxxJ7l45pLe753YoLfAZ95jmEMCPlv1hb6ENx2UOH5TLFG6esH+m0WPZfc/2Cs6
         uyr5huPftWGyIqfxTidxCm0nwRtpT4DIPbOFvk35awi2fA5nhLdhRCVMx5LRZp8Rf/8h
         rLMlGGoc0VVP9eSHzsMYqimkvNyv0veiNTxKUwtDwBz0xCaxPModaFE0Wq+realVzg0c
         PX1eFvBx4s0AOdemhXNkkVGgLJTjep48M6uLAkEz9y6zVtttdjEU46JUHco0lu4EpUCy
         wKPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231026; x=1768835826;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lGNGaj/ON3/kOdXDo8lwphgvrsL8uq7oynthk3sPJIE=;
        b=wH+JZG1Eg1IUktcwHDW4mwnWffrfVjYRC4DaH3JtYH0JyfodHXJgsA1M9QFh1dp7bY
         30lHss1fq/I1NdPgIEBgVTmBfOtgPX6w75s2/H3jyk1e4mCenjRkA23pqmiY6es7uvXg
         bOqP7VcS0t4HVG9c1BFWsTS8vZ1ksiL2V+uJ2eUDwZOA1kwhzu8VUJDbJwzPH80D2OmS
         v42TyZcfuN/9k4ccvGwvXpzXuoInDmVFlP2LrzCjuaY10ZjfAqVpqrXnrntI6ZVCwFwp
         k/JR1g7VI9CFalAyprPyH6XGnA7yxdmAhPsjG0Njjr31NftbxGvRTXrJ+1WNtciQMt7e
         ekgg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXlc2rCjf4XhrDerWhmdPtyqqyxJqVKS/Q9aXLrmCuJMbr8pE3mtREp1bFjT5LQUha4GPnXcA==@lfdr.de
X-Gm-Message-State: AOJu0YznDPH6LGqQzUD8vkgzI+oNGIed+mApDOPsDFmNrkvRUl9fAC79
	HZ4GWbzLMl9HGBegtAuMC/fc82ykNOThmh8Rqb24LrLN/7AVzja5Pmkn
X-Google-Smtp-Source: AGHT+IF2wXOpkKYftOClbnpn/NUPmFeM726lN7T2gEKF71T0JH9wxiihiYf0BeKAMk5Ul2Jq9k83BQ==
X-Received: by 2002:a05:6402:3546:b0:649:ce39:3bd0 with SMTP id 4fb4d7f45d1cf-65097ea5f12mr18076533a12.34.1768231025768;
        Mon, 12 Jan 2026 07:17:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GLR0QidOOcDpEPMhzZMM4AYUdUKaULmzzLka3sL6vaIw=="
Received: by 2002:a50:bb44:0:b0:64b:58c2:9ba4 with SMTP id 4fb4d7f45d1cf-65074a01691ls6598408a12.2.-pod-prod-01-eu;
 Mon, 12 Jan 2026 07:17:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW97vig+1H8G2Rz/lBfCd889sai0faYuo30wXhpJ0tAQV/44C7AVI6FZwf+YHt2TQ3HkYUpEn5g9lM=@googlegroups.com
X-Received: by 2002:a17:907:3e18:b0:b7d:3728:7d11 with SMTP id a640c23a62f3a-b84453d8cfcmr1862827366b.50.1768231023179;
        Mon, 12 Jan 2026 07:17:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231023; cv=none;
        d=google.com; s=arc-20240605;
        b=aMn1R0+RrqOm1aMbq4pNd1Z+yUJavavx+5hREPFQfqIVUT6ytMiZ4duGd78c3K2SwZ
         je7mZotD56cVPVu0RCb9joPiguk8RbNgPpG2mRTciI02yXJKnPjBV0mrvB9glGWJtgwP
         sDPJkzE+j7Jjoql09VoF5gKPwq4iFacWx1CroNbaiBRv2nyoCxjOV07GNIMN91SjRQR6
         yARqpNaxUoGgV+/Bx1cjvIq1KppW6Vj+xjwPbc2021bbFIrKBvSvXORQpTTSr4WA/1yD
         0HYVKZqNQPt0/DuNnFthAdpAVG0NRQEowg+dIGRMDpvqMPxKAwX3+gwj7hYH+gpmac0s
         E31w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=YgRo0U1eQX3053yfEX3HkjzLrN5POOScjwntLhWkHDs=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=Vdt1cxM75463VNeuxeP/sam0F4xNnv1KcT9jXaBMpALUZWpvArR8xnjtPoVvVJJeHp
         wzflxp2pfwEvUisRaHVuGri4Si+9sO+9GVwhTO1k4CaP4HrKwcglglqiOZikw/QJkVDV
         MK0MUvC6J8astYyUjssWsBl7rKatCtdAPqDnVpMLkKCHeOqWdQz3rrgmuyBUZp0+ZpKX
         gGyitnnsGwfHSqq34iA7dsSiAeg0L+6Nv/K6nzfqW+UMG5EOLs/CAF/jR4IFyQK5awzn
         8ZMEcfhgtm8ng2ltzc97RR30gLL+zxB+xNmo+wnt/KdgC49RbDqNMykrOzQSAYTLkI4+
         zq8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d705352si355815a12.4.2026.01.12.07.17.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:03 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 185A03368B;
	Mon, 12 Jan 2026 15:16:58 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id F02323EA66;
	Mon, 12 Jan 2026 15:16:57 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id WJVaOmkQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:57 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:17:00 +0100
Subject: [PATCH RFC v2 06/20] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-6-98225cfb50cf@suse.cz>
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
X-Rspamd-Queue-Id: 185A03368B
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
 mm/slub.c | 79 +++++++++++++++++++++++++++++++++++++++++++++------------------
 1 file changed, 57 insertions(+), 22 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 06d5cf794403..0177a654a06a 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2881,7 +2881,8 @@ static void pcs_destroy(struct kmem_cache *s)
 	s->cpu_sheaves = NULL;
 }
 
-static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn)
+static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn,
+					       bool allow_spin)
 {
 	struct slab_sheaf *empty = NULL;
 	unsigned long flags;
@@ -2889,7 +2890,10 @@ static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn)
 	if (!data_race(barn->nr_empty))
 		return NULL;
 
-	spin_lock_irqsave(&barn->lock, flags);
+	if (likely(allow_spin))
+		spin_lock_irqsave(&barn->lock, flags);
+	else if (!spin_trylock_irqsave(&barn->lock, flags))
+		return NULL;
 
 	if (likely(barn->nr_empty)) {
 		empty = list_first_entry(&barn->sheaves_empty,
@@ -2966,7 +2970,8 @@ static struct slab_sheaf *barn_get_full_or_empty_sheaf(struct node_barn *barn)
  * change.
  */
 static struct slab_sheaf *
-barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
+barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty,
+			 bool allow_spin)
 {
 	struct slab_sheaf *full = NULL;
 	unsigned long flags;
@@ -2974,7 +2979,10 @@ barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
 	if (!data_race(barn->nr_full))
 		return NULL;
 
-	spin_lock_irqsave(&barn->lock, flags);
+	if (likely(allow_spin))
+		spin_lock_irqsave(&barn->lock, flags);
+	else if (!spin_trylock_irqsave(&barn->lock, flags))
+		return NULL;
 
 	if (likely(barn->nr_full)) {
 		full = list_first_entry(&barn->sheaves_full, struct slab_sheaf,
@@ -2995,7 +3003,8 @@ barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
  * barn. But if there are too many full sheaves, reject this with -E2BIG.
  */
 static struct slab_sheaf *
-barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
+barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full,
+			bool allow_spin)
 {
 	struct slab_sheaf *empty;
 	unsigned long flags;
@@ -3006,7 +3015,10 @@ barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
 	if (!data_race(barn->nr_empty))
 		return ERR_PTR(-ENOMEM);
 
-	spin_lock_irqsave(&barn->lock, flags);
+	if (likely(allow_spin))
+		spin_lock_irqsave(&barn->lock, flags);
+	else if (!spin_trylock_irqsave(&barn->lock, flags))
+		return ERR_PTR(-EBUSY);
 
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
 
@@ -5157,7 +5170,8 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
 }
 
 static __fastpath_inline
-unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
+unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, gfp_t gfp, size_t size,
+				 void **p)
 {
 	struct slub_percpu_sheaves *pcs;
 	struct slab_sheaf *main;
@@ -5191,7 +5205,8 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 			return allocated;
 		}
 
-		full = barn_replace_empty_sheaf(barn, pcs->main);
+		full = barn_replace_empty_sheaf(barn, pcs->main,
+						gfpflags_allow_spinning(gfp));
 
 		if (full) {
 			stat(s, BARN_GET);
@@ -5700,7 +5715,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 	gfp_t alloc_gfp = __GFP_NOWARN | __GFP_NOMEMALLOC | gfp_flags;
 	struct kmem_cache *s;
 	bool can_retry = true;
-	void *ret = ERR_PTR(-EBUSY);
+	void *ret;
 
 	VM_WARN_ON_ONCE(gfp_flags & ~(__GFP_ACCOUNT | __GFP_ZERO |
 				      __GFP_NO_OBJ_EXT));
@@ -5727,6 +5742,12 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 		 */
 		return NULL;
 
+	ret = alloc_from_pcs(s, alloc_gfp, node);
+	if (ret)
+		goto success;
+
+	ret = ERR_PTR(-EBUSY);
+
 	/*
 	 * Do not call slab_alloc_node(), since trylock mode isn't
 	 * compatible with slab_pre_alloc_hook/should_failslab and
@@ -5763,6 +5784,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 		ret = NULL;
 	}
 
+success:
 	maybe_wipe_obj_freeptr(s, ret);
 	slab_post_alloc_hook(s, NULL, alloc_gfp, 1, &ret,
 			     slab_want_init_on_alloc(alloc_gfp, s), size);
@@ -6083,7 +6105,8 @@ static void __pcs_install_empty_sheaf(struct kmem_cache *s,
  * unlocked.
  */
 static struct slub_percpu_sheaves *
-__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
+__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
+			bool allow_spin)
 {
 	struct slab_sheaf *empty;
 	struct node_barn *barn;
@@ -6107,7 +6130,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
 	put_fail = false;
 
 	if (!pcs->spare) {
-		empty = barn_get_empty_sheaf(barn);
+		empty = barn_get_empty_sheaf(barn, allow_spin);
 		if (empty) {
 			pcs->spare = pcs->main;
 			pcs->main = empty;
@@ -6121,7 +6144,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
 		return pcs;
 	}
 
-	empty = barn_replace_full_sheaf(barn, pcs->main);
+	empty = barn_replace_full_sheaf(barn, pcs->main, allow_spin);
 
 	if (!IS_ERR(empty)) {
 		stat(s, BARN_PUT);
@@ -6129,6 +6152,17 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
 		return pcs;
 	}
 
+	if (!allow_spin) {
+		/*
+		 * sheaf_flush_unused() or alloc_empty_sheaf() don't support
+		 * !allow_spin and instead of trying to support them it's
+		 * easier to fall back to freeing the object directly without
+		 * sheaves
+		 */
+		local_unlock(&s->cpu_sheaves->lock);
+		return NULL;
+	}
+
 	if (PTR_ERR(empty) == -E2BIG) {
 		/* Since we got here, spare exists and is full */
 		struct slab_sheaf *to_flush = pcs->spare;
@@ -6196,7 +6230,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
  * The object is expected to have passed slab_free_hook() already.
  */
 static __fastpath_inline
-bool free_to_pcs(struct kmem_cache *s, void *object)
+bool free_to_pcs(struct kmem_cache *s, void *object, bool allow_spin)
 {
 	struct slub_percpu_sheaves *pcs;
 
@@ -6207,7 +6241,7 @@ bool free_to_pcs(struct kmem_cache *s, void *object)
 
 	if (unlikely(pcs->main->size == s->sheaf_capacity)) {
 
-		pcs = __pcs_replace_full_main(s, pcs);
+		pcs = __pcs_replace_full_main(s, pcs, allow_spin);
 		if (unlikely(!pcs))
 			return false;
 	}
@@ -6314,7 +6348,7 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
 			goto fail;
 		}
 
-		empty = barn_get_empty_sheaf(barn);
+		empty = barn_get_empty_sheaf(barn, true);
 
 		if (empty) {
 			pcs->rcu_free = empty;
@@ -6435,7 +6469,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 		goto no_empty;
 
 	if (!pcs->spare) {
-		empty = barn_get_empty_sheaf(barn);
+		empty = barn_get_empty_sheaf(barn, true);
 		if (!empty)
 			goto no_empty;
 
@@ -6449,7 +6483,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 		goto do_free;
 	}
 
-	empty = barn_replace_full_sheaf(barn, pcs->main);
+	empty = barn_replace_full_sheaf(barn, pcs->main, true);
 	if (IS_ERR(empty)) {
 		stat(s, BARN_PUT_FAIL);
 		goto no_empty;
@@ -6699,7 +6733,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 
 	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())
 	    && likely(!slab_test_pfmemalloc(slab))) {
-		if (likely(free_to_pcs(s, object)))
+		if (likely(free_to_pcs(s, object, true)))
 			return;
 	}
 
@@ -6960,7 +6994,8 @@ void kfree_nolock(const void *object)
 	 * since kasan quarantine takes locks and not supported from NMI.
 	 */
 	kasan_slab_free(s, x, false, false, /* skip quarantine */true);
-	do_slab_free(s, slab, x, x, 0, _RET_IP_);
+	if (!free_to_pcs(s, x, false))
+		do_slab_free(s, slab, x, x, 0, _RET_IP_);
 }
 EXPORT_SYMBOL_GPL(kfree_nolock);
 
@@ -7512,7 +7547,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
 		size--;
 	}
 
-	i = alloc_from_pcs_bulk(s, size, p);
+	i = alloc_from_pcs_bulk(s, flags, size, p);
 
 	if (i < size) {
 		/*

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-6-98225cfb50cf%40suse.cz.

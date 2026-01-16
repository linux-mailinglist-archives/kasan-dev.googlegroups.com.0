Return-Path: <kasan-dev+bncBDXYDPH3S4OBB4E3VHFQMGQEMTUXGGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 79E9CD32C57
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:40:49 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-64ba9c07ea2sf3362152a12.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:40:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574449; cv=pass;
        d=google.com; s=arc-20240605;
        b=iqJHQw8f+f8jeTxhZLov5VHqvyJ66MKgB+skiGgRRyMhHdq5i8qVKTk9TIMtR5z0dN
         uXypsjl1rxzZ6XscXGObB8a6LuCz0P9hY7bCN3syKRiD+aQNRBfgsFsp1bRD9gNFXyDZ
         3c6ZWkWgOi5PzNaDtH1NPmTDKb0buhwMS1RtzqHum8WeVkRsRq1EieOaH+WpGgbsxFTd
         eY/CPTMLLYW4pfZnhfD7hfQtgldluNTx6Fnk5qY0iSjcT/QCREfW/3G1KCt9jZvxnMwc
         76isuOIq3QeQEhyW9x7nv1PpSS4v7+FNJZCXyGBaX3BwYOre2clEOxtyv3ZPfWUNTcYv
         AdLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=9ecMtZICxtYQJsKmuLoEAbx4pKlJoI/AhtD3wzJXJWI=;
        fh=qsRynzfI6va0gWAgbGIZHCVFewOOcA84SZgCei8ajls=;
        b=G8OJ3sQp1gfqd6ke3y+YLoHZe+8JJ9ldO5JXjGTeQ8Dd/FCBTQvOA8wASvhmVpiH0/
         8/VqJ++US4Q5IhDLbDiXZXs4IbMFT401fcmhpoP6mhrtRLOi9RdlA0j9ZNysWx3BQUyN
         DIoHSfzwpkJvoonKS3TeN/iEYViMHguy9x9hVO30ptx1o/VVL08J30Q2kQ+i/WysSeU+
         u7e++wbJ9fa7jxaCq/9jQqplUYhZ+76JgveRFYcvBE9g4ObJ06aYEgVkOUi4oCeGzXcW
         0HZVMsiOlS9elqbCVF/lSGxBfoTFl0B6grGPCDEYMxZU5pG3LEIbxgJx2fQNvVByqPZu
         s0wA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=eBUInVZl;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=eBUInVZl;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574449; x=1769179249; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9ecMtZICxtYQJsKmuLoEAbx4pKlJoI/AhtD3wzJXJWI=;
        b=AFrifz2EQeQZ1V93wqa8yxO0NBEUACzE34WT19gOHF8U3JHygAHIha8cv137nu+fyk
         YYDeRpoTMjtJ6P3OtdaW0Ax82BkEpiT+obIQ8/ZQrvqpg2o/gL1S9bHMlip6g3QsJBYg
         bLeOOh9JHX3TpAqftggjr+nKFqQgp+fsuVbO47OoOUDsw4M19j5Ie70BZkbII37EOWNO
         tuNCOZ/qAhzCKS0iSUW2eMVlRCBrJM9h7d7adln6BweWSXHU4ysFagw4h+U+nh8j7P3K
         i9ASW+5esXvFtyerv+syTcXS/73FbQ9ftI+f1OQEdEqfUrEgzXSQsSDaiQP5RRG0geHu
         Ugsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574449; x=1769179249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9ecMtZICxtYQJsKmuLoEAbx4pKlJoI/AhtD3wzJXJWI=;
        b=J361WLtUgOvKcxMsXw8PSCq+OUOvTHnGGf10epN4AEmQF/FvCzaLYQPcsoD/8w7VUk
         Fn5bwKyPSiySzBGRqbX738yjTM6XqNCa7v9YZIqYZyGMwlTePgpuyjMMO5fvRyTUpxEq
         mBeA6hDo/z1sDaRlh97Du2N9MSE35UvSwV8CZuEqDXdhyq8XXhlgj9NbpUQvUIbz375n
         H0FZyPdPZ8HtI9SLZPI15epGKifCmPNXW0foAGk+KgbuFTJFXolNJzgQ1onxurDg69Zt
         RsgUehEqHv6OTJHSfP07i8g9T7ahq1490Qux+Z1/RMcX16AG2cAM8ZvFNZH2ZyyCfXqQ
         +iqQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWwLDsFgORPn3jtjYJB3c9huhhfsFBrQm0+uZgtpv0HVjhFQ+93HdJ11J8ayYogSCBLjutJlg==@lfdr.de
X-Gm-Message-State: AOJu0Yx6butaXLfp0JsCl/ft93LJm0ARveyFsIUbGvu33BqZ2aq2ISzb
	pzfqJS0qeT+cXEzowFvlKKTt03QO+sMN/TaHTO6VyFA2jl58JB0A1Ds5
X-Received: by 2002:a05:6402:1454:b0:64b:42d8:918 with SMTP id 4fb4d7f45d1cf-654525cc106mr2106152a12.9.1768574448460;
        Fri, 16 Jan 2026 06:40:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H5rV1hKKTnAc/Juj5/6BBUQXuibq0Kabl359PSo4OrLg=="
Received: by 2002:a05:6402:4044:20b0:64b:403b:d9ba with SMTP id
 4fb4d7f45d1cf-6541c6d9c5als1861175a12.1.-pod-prod-01-eu; Fri, 16 Jan 2026
 06:40:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXygGdWOanuDbrpKJX4ki/UW12/ag5IakJKUQ/PklomwTnpndXw0GG4Q2K1WB6+koQRLRWOWVGoaHQ=@googlegroups.com
X-Received: by 2002:a05:6402:234a:b0:650:a098:ff2e with SMTP id 4fb4d7f45d1cf-65452acb5a1mr2404443a12.18.1768574446337;
        Fri, 16 Jan 2026 06:40:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574446; cv=none;
        d=google.com; s=arc-20240605;
        b=Q8aDFaNPbm5Wuakb5niEzH4I0vXaKvIz0ryjFqkVDXuyeIuIPR+Te0nXSOZSGjvKjA
         NWNZv2yK5ZaLOXoMxtBTtwMw5TVk9hgM26JaGqAgo/7FdIgEqDQbVZlOFGtfyWGx9zLV
         bdbojIP8km7YlFidj2Y3HLpSEHJNicRo4Q3ihuPQVkDE2n7FZOi1bdw2Clx23Ngt7quz
         Jhg6LYnOrgBOJcgKMUXl4Sod29OZs+mLtWBvnjKSQi5tmW1+gbzIVdOJllKQpDS87MBV
         XGouAzLQ2brGFZh5kdHsAm9LmbxkZrinP3d5zXSK5RV6mqHQrwKxu9AKNnvT9S5s/sZX
         6p3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=yl3tYq1zkCSfFGXX17TFoPzKLhUlXL9wcLcMPsj5qcU=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=PVbgNZjF9d1YWQzvfKOG5xu37SYqs80uRpZgIJYyQgMVfutnk8VGYOVz+hiQRfm7yb
         PHqYN3UOtPNYJ1C0Iv8HiblGCXKOV9Kts1K+qgy0YyXIos4U2/gBUDr9CqLCA85H/Vei
         Mt4df19PJwIsJUgT0z/DbcWauL5MjqwL7Ap5WcH+WkdRMTZYGqSTTUIjg4ynSKRFh5K8
         A5X1HJRjaQBysKIrfV3alKRlAri54qfjsafKlrmGa4SUS5afjmHQH6VvzgmUUWDwISQC
         kVC8bx+rjNimdw9Pq7NNDxg4m0ti0lYnRQO6v8EqQ4l03diTpBU0K0peHtIj5u4eOSXQ
         1hjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=eBUInVZl;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=eBUInVZl;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-654532cef9dsi55965a12.6.2026.01.16.06.40.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:40:46 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 608FB5BE8E;
	Fri, 16 Jan 2026 14:40:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 44C6A3EA63;
	Fri, 16 Jan 2026 14:40:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id oBFwEOVNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:37 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:27 +0100
Subject: [PATCH v3 07/21] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-7-5595cb000772@suse.cz>
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
X-Spam-Score: -4.30
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
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=eBUInVZl;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=eBUInVZl;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
 mm/slub.c | 79 ++++++++++++++++++++++++++++++++++++++++++++-------------------
 1 file changed, 56 insertions(+), 23 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 706cb6398f05..b385247c219f 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2893,7 +2893,8 @@ static void pcs_destroy(struct kmem_cache *s)
 	s->cpu_sheaves = NULL;
 }
 
-static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn)
+static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn,
+					       bool allow_spin)
 {
 	struct slab_sheaf *empty = NULL;
 	unsigned long flags;
@@ -2901,7 +2902,10 @@ static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn)
 	if (!data_race(barn->nr_empty))
 		return NULL;
 
-	spin_lock_irqsave(&barn->lock, flags);
+	if (likely(allow_spin))
+		spin_lock_irqsave(&barn->lock, flags);
+	else if (!spin_trylock_irqsave(&barn->lock, flags))
+		return NULL;
 
 	if (likely(barn->nr_empty)) {
 		empty = list_first_entry(&barn->sheaves_empty,
@@ -2978,7 +2982,8 @@ static struct slab_sheaf *barn_get_full_or_empty_sheaf(struct node_barn *barn)
  * change.
  */
 static struct slab_sheaf *
-barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
+barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty,
+			 bool allow_spin)
 {
 	struct slab_sheaf *full = NULL;
 	unsigned long flags;
@@ -2986,7 +2991,10 @@ barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
 	if (!data_race(barn->nr_full))
 		return NULL;
 
-	spin_lock_irqsave(&barn->lock, flags);
+	if (likely(allow_spin))
+		spin_lock_irqsave(&barn->lock, flags);
+	else if (!spin_trylock_irqsave(&barn->lock, flags))
+		return NULL;
 
 	if (likely(barn->nr_full)) {
 		full = list_first_entry(&barn->sheaves_full, struct slab_sheaf,
@@ -3007,7 +3015,8 @@ barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
  * barn. But if there are too many full sheaves, reject this with -E2BIG.
  */
 static struct slab_sheaf *
-barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
+barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full,
+			bool allow_spin)
 {
 	struct slab_sheaf *empty;
 	unsigned long flags;
@@ -3018,7 +3027,10 @@ barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
 	if (!data_race(barn->nr_empty))
 		return ERR_PTR(-ENOMEM);
 
-	spin_lock_irqsave(&barn->lock, flags);
+	if (likely(allow_spin))
+		spin_lock_irqsave(&barn->lock, flags);
+	else if (!spin_trylock_irqsave(&barn->lock, flags))
+		return ERR_PTR(-EBUSY);
 
 	if (likely(barn->nr_empty)) {
 		empty = list_first_entry(&barn->sheaves_empty, struct slab_sheaf,
@@ -5012,7 +5024,8 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
 		return NULL;
 	}
 
-	full = barn_replace_empty_sheaf(barn, pcs->main);
+	full = barn_replace_empty_sheaf(barn, pcs->main,
+					gfpflags_allow_spinning(gfp));
 
 	if (full) {
 		stat(s, BARN_GET);
@@ -5029,7 +5042,7 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
 			empty = pcs->spare;
 			pcs->spare = NULL;
 		} else {
-			empty = barn_get_empty_sheaf(barn);
+			empty = barn_get_empty_sheaf(barn, true);
 		}
 	}
 
@@ -5169,7 +5182,8 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
 }
 
 static __fastpath_inline
-unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
+unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, gfp_t gfp, size_t size,
+				 void **p)
 {
 	struct slub_percpu_sheaves *pcs;
 	struct slab_sheaf *main;
@@ -5203,7 +5217,8 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 			return allocated;
 		}
 
-		full = barn_replace_empty_sheaf(barn, pcs->main);
+		full = barn_replace_empty_sheaf(barn, pcs->main,
+						gfpflags_allow_spinning(gfp));
 
 		if (full) {
 			stat(s, BARN_GET);
@@ -5701,7 +5716,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 	gfp_t alloc_gfp = __GFP_NOWARN | __GFP_NOMEMALLOC | gfp_flags;
 	struct kmem_cache *s;
 	bool can_retry = true;
-	void *ret = ERR_PTR(-EBUSY);
+	void *ret;
 
 	VM_WARN_ON_ONCE(gfp_flags & ~(__GFP_ACCOUNT | __GFP_ZERO |
 				      __GFP_NO_OBJ_EXT));
@@ -5732,6 +5747,12 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
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
@@ -5768,6 +5789,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 		ret = NULL;
 	}
 
+success:
 	maybe_wipe_obj_freeptr(s, ret);
 	slab_post_alloc_hook(s, NULL, alloc_gfp, 1, &ret,
 			     slab_want_init_on_alloc(alloc_gfp, s), size);
@@ -6088,7 +6110,8 @@ static void __pcs_install_empty_sheaf(struct kmem_cache *s,
  * unlocked.
  */
 static struct slub_percpu_sheaves *
-__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
+__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
+			bool allow_spin)
 {
 	struct slab_sheaf *empty;
 	struct node_barn *barn;
@@ -6112,7 +6135,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
 	put_fail = false;
 
 	if (!pcs->spare) {
-		empty = barn_get_empty_sheaf(barn);
+		empty = barn_get_empty_sheaf(barn, allow_spin);
 		if (empty) {
 			pcs->spare = pcs->main;
 			pcs->main = empty;
@@ -6126,7 +6149,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
 		return pcs;
 	}
 
-	empty = barn_replace_full_sheaf(barn, pcs->main);
+	empty = barn_replace_full_sheaf(barn, pcs->main, allow_spin);
 
 	if (!IS_ERR(empty)) {
 		stat(s, BARN_PUT);
@@ -6134,7 +6157,8 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
 		return pcs;
 	}
 
-	if (PTR_ERR(empty) == -E2BIG) {
+	/* sheaf_flush_unused() doesn't support !allow_spin */
+	if (PTR_ERR(empty) == -E2BIG && allow_spin) {
 		/* Since we got here, spare exists and is full */
 		struct slab_sheaf *to_flush = pcs->spare;
 
@@ -6159,6 +6183,14 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
 alloc_empty:
 	local_unlock(&s->cpu_sheaves->lock);
 
+	/*
+	 * alloc_empty_sheaf() doesn't support !allow_spin and it's
+	 * easier to fall back to freeing directly without sheaves
+	 * than add the support (and to sheaf_flush_unused() above)
+	 */
+	if (!allow_spin)
+		return NULL;
+
 	empty = alloc_empty_sheaf(s, GFP_NOWAIT);
 	if (empty)
 		goto got_empty;
@@ -6201,7 +6233,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
  * The object is expected to have passed slab_free_hook() already.
  */
 static __fastpath_inline
-bool free_to_pcs(struct kmem_cache *s, void *object)
+bool free_to_pcs(struct kmem_cache *s, void *object, bool allow_spin)
 {
 	struct slub_percpu_sheaves *pcs;
 
@@ -6212,7 +6244,7 @@ bool free_to_pcs(struct kmem_cache *s, void *object)
 
 	if (unlikely(pcs->main->size == s->sheaf_capacity)) {
 
-		pcs = __pcs_replace_full_main(s, pcs);
+		pcs = __pcs_replace_full_main(s, pcs, allow_spin);
 		if (unlikely(!pcs))
 			return false;
 	}
@@ -6319,7 +6351,7 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
 			goto fail;
 		}
 
-		empty = barn_get_empty_sheaf(barn);
+		empty = barn_get_empty_sheaf(barn, true);
 
 		if (empty) {
 			pcs->rcu_free = empty;
@@ -6437,7 +6469,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 		goto no_empty;
 
 	if (!pcs->spare) {
-		empty = barn_get_empty_sheaf(barn);
+		empty = barn_get_empty_sheaf(barn, true);
 		if (!empty)
 			goto no_empty;
 
@@ -6451,7 +6483,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 		goto do_free;
 	}
 
-	empty = barn_replace_full_sheaf(barn, pcs->main);
+	empty = barn_replace_full_sheaf(barn, pcs->main, true);
 	if (IS_ERR(empty)) {
 		stat(s, BARN_PUT_FAIL);
 		goto no_empty;
@@ -6703,7 +6735,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 
 	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())
 	    && likely(!slab_test_pfmemalloc(slab))) {
-		if (likely(free_to_pcs(s, object)))
+		if (likely(free_to_pcs(s, object, true)))
 			return;
 	}
 
@@ -6964,7 +6996,8 @@ void kfree_nolock(const void *object)
 	 * since kasan quarantine takes locks and not supported from NMI.
 	 */
 	kasan_slab_free(s, x, false, false, /* skip quarantine */true);
-	do_slab_free(s, slab, x, x, 0, _RET_IP_);
+	if (!free_to_pcs(s, x, false))
+		do_slab_free(s, slab, x, x, 0, _RET_IP_);
 }
 EXPORT_SYMBOL_GPL(kfree_nolock);
 
@@ -7516,7 +7549,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-7-5595cb000772%40suse.cz.

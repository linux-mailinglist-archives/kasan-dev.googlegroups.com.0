Return-Path: <kasan-dev+bncBDXYDPH3S4OBBYNGVTEAMGQEWIMKS3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 28310C34ACB
	for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 10:05:39 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-47113538d8csf35982315e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 01:05:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762333538; cv=pass;
        d=google.com; s=arc-20240605;
        b=gTvpE7LEp7GPDSbqMaAqYfoSozrqQz9muxc391f5ROe9Q5TOKJPrbhb7H5t3D6wjMa
         SfnUpGPdvi74EEwvrIwxtcBvzQ0loNQ1zbhn2oNJvleJgMB8JzSQp74vQbR91xB9a7hz
         RklTUqmIA/B7n3lv1ZwhFpisqnj9wXRmZ27LPfuhguvGqqp7tfx06vjPk18jD/qiSH81
         kYyG4Zct92x51+nplbelz64awb9TtM7q87VPDczgOe1Vf+kwYn9SICVJebigfRiYVxwl
         a6zXr/gVOtoArUHFoSudfCjtAizTMijy2PF/R1MA0SD3AoWhatFieY6wYiPseEv/cT+O
         vYWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=gl/Gvee+X4b6Js9Wm0vuI4rNOAMS6d/pMv+5/nni858=;
        fh=XCuV4/8fnh1RtjhYzS7yT0iw3wEFTcbmzYnHgH1FfWA=;
        b=leQJP6Bf8JeKZDijFr5JYrPXYXNjw5NMKaCgzYHC+pZp+QF9OhfobyDUzx1F8qSHMa
         0hyeDvPRmGVESLhkGx9Tt746KndUBkd4Fx9Ldlje4s2c8sUSNUzsztJ++45l+3Jm+fme
         pmK2GUETH3NR8Zn8CrqubERrjw8+l+feS9uaz0Ef1y/1OxiFrJGjsdmSTA5bB2PyS9w2
         bGPimRUXbxD9cmFQ4Mcsy9YExZYpcGvjpYj9Oayv0Obh7joGUvfzHtAlqDFZsc6llFgZ
         oOsBKaJUaTzmCK4GLib2mYYHebeyol26Qcd2NfAAxOAUIOYue8cmZKa/lEZxfmjwyJcV
         I0sg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dRvvKLgY;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dRvvKLgY;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762333538; x=1762938338; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:in-reply-to:references:message-id:mime-version
         :subject:date:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gl/Gvee+X4b6Js9Wm0vuI4rNOAMS6d/pMv+5/nni858=;
        b=etgDWZadocRWVl4aarB15ojpGvTp4DMaPOIaz+Pk7AIzdAHZaxFI/vp0srLofQ8lOK
         2ju8a8FM3KE8M6szOz7/uNYigynuL43lHUeitmqau8naoEJSuqs6xyvBoTC/CDN+elBx
         MSenQC2HX+3nzDUxt3gUnXZRz9njpaHMBpyOnrfBzyDdAmk9K3P+t8lmorZzXFamUHrX
         TsJzVSk25GTDj6PKOqFfj89TR42kjo5gyPmiY8HCIIhdCjEfmgk2ZugDz/SNUePSVoid
         jYhSqSR4SojT2HPGwn/bpMbaDzPEfpg8K6H98XZY/QJrRmJfz2PFeCeeiVVoC1YQj0Q4
         yUrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762333538; x=1762938338;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gl/Gvee+X4b6Js9Wm0vuI4rNOAMS6d/pMv+5/nni858=;
        b=LMdm9eP3TaiwlSqaKe3FAMAuUPAObt/c3O1ixsFgWHrd4X4cB9/frT/g+DdwHLKF5R
         Uq9iqyCvDdHT3OFRSCuRtLIh/J33KX1vS05nqcjVh2GE5bkTj62TXzgtQcwvFgjMnZ/Y
         HTd/zeIVEATDhY5ZudKeoK/81U+p+aQwwKuTH71C98R9KATipzgmjOZxMEqJ1DtVAzaY
         /fh7AvCDSRb3NliFbRHUryf/w2pqAoFqYf3xf6DAKztdRxl9zOS+EsOVc3cRsQ6GZ5uk
         odA4dW+pTpSEBs7gJvVFYBkreSSksI2O7s3JS6wXuLk0ctmHDABePdFMqGepxSvl/zJc
         LecQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV5VaLulyT91FnDIJ2ReaROZQMsNZMccCFr/6fAj7T1/iDwdyRKuImhQXj1k8LRgYhtWbCbug==@lfdr.de
X-Gm-Message-State: AOJu0YyU11qAOIvb6AUlYM4Z0bFRUUqHmoEIxAbeLtND+fae1fmQZ6Xr
	uqtYZGB9S/1qzfvn1NRwrwIDE1rDp9m8gdDu9tCjNVme7kvcbUyqExxz
X-Google-Smtp-Source: AGHT+IGPUVX3Jb8+dAprVNQb7B60aYJ9MwIvcFRs7vA7AOC1JWgy1w7vZVi31KYKhUSUtG6PPq0LWQ==
X-Received: by 2002:a05:600c:3596:b0:46e:206a:78cc with SMTP id 5b1f17b1804b1-4775ce14c1dmr22629205e9.28.1762333538342;
        Wed, 05 Nov 2025 01:05:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bOW58Nf5m7kNN6GmQtXWz6dueWcXiIMiTLdTlmdW2rkQ=="
Received: by 2002:a05:600c:6094:b0:477:5d33:983b with SMTP id
 5b1f17b1804b1-4775d33999fls2931885e9.2.-pod-prod-01-eu; Wed, 05 Nov 2025
 01:05:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUXlWJmSROopXfmRQi5bGkzZQdHjJXOevt6ndb4y1VOfajD9aPPqFqVY2u1Ss7FbL5VP367phlWy00=@googlegroups.com
X-Received: by 2002:a05:600c:1e1e:b0:477:f1f:5c65 with SMTP id 5b1f17b1804b1-4775cdf2719mr14838765e9.23.1762333534461;
        Wed, 05 Nov 2025 01:05:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762333534; cv=none;
        d=google.com; s=arc-20240605;
        b=T2wwp4YMIp+3rnEwxsyCrMWtIxnB+CYDzjBeCJX1YQgAv7KdSHAt14XH1b3R8V4pVv
         EE2EipsZ5URM1MrpAv1idFFmd4spxrldoTCVW6LW2N1YAIhgkV782XZw6KNaBhkML2fD
         3VMIuPMaj4tDBmf0RCHiMYIHxYtgEyHG31vxG/TzvY68ZLyg+51kVWGeGKoKKPeygskI
         uvc355dxql7dHkiv1daC9y346VFuxBCnFp3b2lZPUh1hAuBKcPtz4dfpeMzhfEw3eone
         Ca4KBladiRhKqAkQTlnWzrIEjuqzhSdgEKQ6McNAtlZ8CIW1Z6tCuKsGBViSCooshSPY
         g7+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=tVqdfrjinTijcg8TfrfGQECaxpdrWMMyTcELwLOOflY=;
        fh=dklpSMYSEC41gVZaXcntr2MBCAntdHiJG8gGN2y0lZI=;
        b=jcheuFflMOP7FRlA376CWeB5zISjkunx/GhI1QeimdAHHEVqnr0mL+hYfETN5oA5Z7
         s0irMw4pExMPmRhw4V4yoWcGg7u1LnD0vOB4tljoQEd5FDL399rUFfZQ+cY94zFHc5kN
         EmOsHxSO2gcn92zMdUZ4+nHfEWHyL1JMtbBHKgAc2OHF3LXz/LgolSXl0kSLIRbKs+jP
         hNSjfSFYnWB3WibI1Geb+pmqbPhEGKZm2iLlGgdhJEEkp7vW/NQSLlDGfoXlyHmh7htH
         QTQG2TAgpSeUw8hBYvy+ukLP2igzHfn2VSkSBKgbpz8KNK3y2bs9uSSkEAjliBEvBs7Z
         WUnA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dRvvKLgY;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dRvvKLgY;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-429dc1f2ec7si77646f8f.7.2025.11.05.01.05.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Nov 2025 01:05:34 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id CCF9B21193;
	Wed,  5 Nov 2025 09:05:30 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id B303613ADD;
	Wed,  5 Nov 2025 09:05:30 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id iKJyK1oTC2lSBAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 05 Nov 2025 09:05:30 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 05 Nov 2025 10:05:31 +0100
Subject: [PATCH 3/5] slab: handle pfmemalloc slabs properly with sheaves
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251105-sheaves-cleanups-v1-3-b8218e1ac7ef@suse.cz>
References: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz>
In-Reply-To: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, Alexei Starovoitov <ast@kernel.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, bpf@vger.kernel.org, 
 kasan-dev@googlegroups.com, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.3
X-Spam-Level: 
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.996];
	MIME_GOOD(-0.10)[text/plain];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[13];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:mid,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=dRvvKLgY;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=dRvvKLgY;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

When a pfmemalloc allocation actually dips into reserves, the slab is
marked accordingly and non-pfmemalloc allocations should not be allowed
to allocate from it. The sheaves percpu caching currently doesn't follow
this rule, so implement it before we expand sheaves usage to all caches.

Make sure objects from pfmemalloc slabs don't end up in percpu sheaves.
When freeing, skip sheaves when freeing an object from pfmemalloc slab.
When refilling sheaves, use __GFP_NOMEMALLOC to override any pfmemalloc
context - the allocation will fallback to regular slab allocations when
sheaves are depleted and can't be refilled because of the override.

For kfree_rcu(), detect pfmemalloc slabs after processing the rcu_sheaf
after the grace period in __rcu_free_sheaf_prepare() and simply flush
it if any object is from pfmemalloc slabs.

For prefilled sheaves, try to refill them first with __GFP_NOMEMALLOC
and if it fails, retry without __GFP_NOMEMALLOC but then mark the sheaf
pfmemalloc, which makes it flushed back to slabs when returned.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 69 ++++++++++++++++++++++++++++++++++++++++++++++++++-------------
 1 file changed, 55 insertions(+), 14 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 0237a329d4e5..bb744e8044f0 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -469,7 +469,10 @@ struct slab_sheaf {
 		struct rcu_head rcu_head;
 		struct list_head barn_list;
 		/* only used for prefilled sheafs */
-		unsigned int capacity;
+		struct {
+			unsigned int capacity;
+			bool pfmemalloc;
+		};
 	};
 	struct kmem_cache *cache;
 	unsigned int size;
@@ -2651,7 +2654,7 @@ static struct slab_sheaf *alloc_full_sheaf(struct kmem_cache *s, gfp_t gfp)
 	if (!sheaf)
 		return NULL;
 
-	if (refill_sheaf(s, sheaf, gfp)) {
+	if (refill_sheaf(s, sheaf, gfp | __GFP_NOMEMALLOC)) {
 		free_empty_sheaf(s, sheaf);
 		return NULL;
 	}
@@ -2729,12 +2732,13 @@ static void sheaf_flush_unused(struct kmem_cache *s, struct slab_sheaf *sheaf)
 	sheaf->size = 0;
 }
 
-static void __rcu_free_sheaf_prepare(struct kmem_cache *s,
+static bool __rcu_free_sheaf_prepare(struct kmem_cache *s,
 				     struct slab_sheaf *sheaf)
 {
 	bool init = slab_want_init_on_free(s);
 	void **p = &sheaf->objects[0];
 	unsigned int i = 0;
+	bool pfmemalloc = false;
 
 	while (i < sheaf->size) {
 		struct slab *slab = virt_to_slab(p[i]);
@@ -2747,8 +2751,13 @@ static void __rcu_free_sheaf_prepare(struct kmem_cache *s,
 			continue;
 		}
 
+		if (slab_test_pfmemalloc(slab))
+			pfmemalloc = true;
+
 		i++;
 	}
+
+	return pfmemalloc;
 }
 
 static void rcu_free_sheaf_nobarn(struct rcu_head *head)
@@ -5041,7 +5050,7 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
 		return NULL;
 
 	if (empty) {
-		if (!refill_sheaf(s, empty, gfp)) {
+		if (!refill_sheaf(s, empty, gfp | __GFP_NOMEMALLOC)) {
 			full = empty;
 		} else {
 			/*
@@ -5341,6 +5350,26 @@ void *kmem_cache_alloc_node_noprof(struct kmem_cache *s, gfp_t gfpflags, int nod
 }
 EXPORT_SYMBOL(kmem_cache_alloc_node_noprof);
 
+static int __prefill_sheaf_pfmemalloc(struct kmem_cache *s,
+				      struct slab_sheaf *sheaf, gfp_t gfp)
+{
+	int ret = 0;
+
+	ret = refill_sheaf(s, sheaf, gfp | __GFP_NOMEMALLOC);
+
+	if (likely(!ret || !gfp_pfmemalloc_allowed(gfp)))
+		return ret;
+
+	/*
+	 * if we are allowed to, refill sheaf with pfmemalloc but then remember
+	 * it for when it's returned
+	 */
+	ret = refill_sheaf(s, sheaf, gfp);
+	sheaf->pfmemalloc = true;
+
+	return ret;
+}
+
 /*
  * returns a sheaf that has at least the requested size
  * when prefilling is needed, do so with given gfp flags
@@ -5375,6 +5404,10 @@ kmem_cache_prefill_sheaf(struct kmem_cache *s, gfp_t gfp, unsigned int size)
 		sheaf->cache = s;
 		sheaf->capacity = size;
 
+		/*
+		 * we do not need to care about pfmemalloc here because oversize
+		 * sheaves area always flushed and freed when returned
+		 */
 		if (!__kmem_cache_alloc_bulk(s, gfp, size,
 					     &sheaf->objects[0])) {
 			kfree(sheaf);
@@ -5411,17 +5444,18 @@ kmem_cache_prefill_sheaf(struct kmem_cache *s, gfp_t gfp, unsigned int size)
 	if (!sheaf)
 		sheaf = alloc_empty_sheaf(s, gfp);
 
-	if (sheaf && sheaf->size < size) {
-		if (refill_sheaf(s, sheaf, gfp)) {
+	if (sheaf) {
+		sheaf->capacity = s->sheaf_capacity;
+		sheaf->pfmemalloc = false;
+
+		if (sheaf->size < size &&
+		    __prefill_sheaf_pfmemalloc(s, sheaf, gfp)) {
 			sheaf_flush_unused(s, sheaf);
 			free_empty_sheaf(s, sheaf);
 			sheaf = NULL;
 		}
 	}
 
-	if (sheaf)
-		sheaf->capacity = s->sheaf_capacity;
-
 	return sheaf;
 }
 
@@ -5441,7 +5475,8 @@ void kmem_cache_return_sheaf(struct kmem_cache *s, gfp_t gfp,
 	struct slub_percpu_sheaves *pcs;
 	struct node_barn *barn;
 
-	if (unlikely(sheaf->capacity != s->sheaf_capacity)) {
+	if (unlikely((sheaf->capacity != s->sheaf_capacity)
+		     || sheaf->pfmemalloc)) {
 		sheaf_flush_unused(s, sheaf);
 		kfree(sheaf);
 		return;
@@ -5507,7 +5542,7 @@ int kmem_cache_refill_sheaf(struct kmem_cache *s, gfp_t gfp,
 
 	if (likely(sheaf->capacity >= size)) {
 		if (likely(sheaf->capacity == s->sheaf_capacity))
-			return refill_sheaf(s, sheaf, gfp);
+			return __prefill_sheaf_pfmemalloc(s, sheaf, gfp);
 
 		if (!__kmem_cache_alloc_bulk(s, gfp, sheaf->capacity - sheaf->size,
 					     &sheaf->objects[sheaf->size])) {
@@ -6215,8 +6250,12 @@ static void rcu_free_sheaf(struct rcu_head *head)
 	 * handles it fine. The only downside is that sheaf will serve fewer
 	 * allocations when reused. It only happens due to debugging, which is a
 	 * performance hit anyway.
+	 *
+	 * If it returns true, there was at least one object from pfmemalloc
+	 * slab so simply flush everything.
 	 */
-	__rcu_free_sheaf_prepare(s, sheaf);
+	if (__rcu_free_sheaf_prepare(s, sheaf))
+		goto flush;
 
 	n = get_node(s, sheaf->node);
 	if (!n)
@@ -6371,7 +6410,8 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 			continue;
 		}
 
-		if (unlikely(IS_ENABLED(CONFIG_NUMA) && slab_nid(slab) != node)) {
+		if (unlikely((IS_ENABLED(CONFIG_NUMA) && slab_nid(slab) != node)
+			     || slab_test_pfmemalloc(slab))) {
 			remote_objects[remote_nr] = p[i];
 			p[i] = p[--size];
 			if (++remote_nr >= PCS_BATCH_MAX)
@@ -6669,7 +6709,8 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 		return;
 
 	if (s->cpu_sheaves && likely(!IS_ENABLED(CONFIG_NUMA) ||
-				     slab_nid(slab) == numa_mem_id())) {
+				     slab_nid(slab) == numa_mem_id())
+			   && likely(!slab_test_pfmemalloc(slab))) {
 		if (likely(free_to_pcs(s, object)))
 			return;
 	}

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251105-sheaves-cleanups-v1-3-b8218e1ac7ef%40suse.cz.

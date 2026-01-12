Return-Path: <kasan-dev+bncBDXYDPH3S4OBB5FASTFQMGQEHCECUQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 452C3D138E0
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:10 +0100 (CET)
Received: by mail-ej1-x63d.google.com with SMTP id a640c23a62f3a-b870f354682sf150822666b.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231029; cv=pass;
        d=google.com; s=arc-20240605;
        b=SjxN+IgMhlcfjFxRw9qSqsi95/xycNi/CLuCZGvQ/AxnTVceWpkfBvLay8305+H8xU
         RPwrGoXxHPqQju/ABQYUY1lEWWBsX7uXZqQaOHG8sbTL/jv6IF53CwC20BG/AaZDWI/c
         ZAqa8JtnWHVtx3vb05UG6RBMm/rAlPuGrW0tdzmIqI45xqrcrsM8MfJZ8cAvhe6nqtjI
         msnZsXkwhFeYfE++8QRBsTAgK/bnX4yJE09q3pLqBN3t0KsyLakszRRtJMMPoz0IgpGD
         hDsUL+FUHti5Kn+Ym66/OyHf0egRnYkp16upH/FX0IccaO/ZD1KVLEjsCB+ATCN4JBTO
         ps1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=1D9db5ZF7CUAugaxRjyt1cjNq5FVgArrQKhmT1F8+jQ=;
        fh=rkXTGE8ZlGGDw1RW1gpHxn7GQUK9pUcQVkm0kX8gQcA=;
        b=USVhNIa0+2EBCub1zLeOh3GPsFSs8VPnaHTvevSHtR5YsZ/sFLwo0m0bvqkXeb6VnS
         3pn5oeHGjaKevmTpTZqzYHLHhfpBdNHoySYTJpHll1qRNy22jmofqYTbYUy+0GO+jLSF
         Boprtev6ELjE3DvG8QiwDVuL8CYMiDNgoOYbMZkWZwe+Ml0S7nBQ5+nemBKi7ehP2h2G
         YfSY3wsY0K/McJ9faO1xk6REEEwwveuUNw0KLI9l09MnPb33+JBX32WwPGN/JVkyI62X
         CUEv9zeBIaA/fIxifGFMBh49aPZJzOqTKxn/MgxJvOn8/2rPy2X//KMGnBvRXpnEXcZB
         8eYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231029; x=1768835829; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1D9db5ZF7CUAugaxRjyt1cjNq5FVgArrQKhmT1F8+jQ=;
        b=rhEgvEZesGf54tTynu98Nhx2v/MGHstJzAqEvg58Pt1Dup2pBizRXfzLLv16oD5EKv
         V3qOvtUse7u2wRTTiZeZJe4CPZhJgV7IeY9i39d3LHrhPecCtlhl4baA3jcTe6RIbU7f
         K5UKffN1NFEjGfEMgXyq0mRRk1YgVS0+B2aNTYjcVtMmW3AJvbKM4zLJSf7kSe114PpY
         YYDW3qqlPHOxCQ+Kua+q8VEj7JRvWKd9f84Qu9gRKjpbmPDffHGXyuLq93SohtUxEi5M
         F7olJChj4kLqOlqnAYrahHM/WaBw9xcXGCTMVn1utUdqbJWZ+r0a4Pc1u3M4cozR36qV
         x1Tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231029; x=1768835829;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1D9db5ZF7CUAugaxRjyt1cjNq5FVgArrQKhmT1F8+jQ=;
        b=gX6jbZjD1aHDAB1hvngKZG2WifqUugzthS0efiEQZUdAykl1UHIQTBiMXjriJOE22u
         Pc/HlASs6AFkJ0DhHoRpZ1giVI0fPcVgrRvSDH5zJhCiPrljs6HG1AByA18LkqntuZOe
         LBikGL6lNVr/58tr5WekErawaVAeJLF9fAibRapq4FS7+xugy/ezOnOeIYZVgP0W3EMH
         WuQ5slBm0JVw8fci+uDy7CfwIwXMwTE2UN4eViotsDjgBn/09xDFgnKUp8vn0QuH5NU3
         kJtbMCHDryN4BOefgAnAdTzHz3cPxGP+5vMS3XpFhpbMeTfm+apjzA29M2RQOMjpP3uP
         hirw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV62JMQPNdJm2D4GzK/scHMDnpylyBOzs4/ySbp0euVqn+0GKipasULR+fVkhiOg+YEOkT63w==@lfdr.de
X-Gm-Message-State: AOJu0Yx8hRSCpIMB9KbMnca0AFAQ0hP8AjgyOWugipymtNNGVaoRDBMA
	vVZ/k5bCY2olhHKX2QG/82UDF71AVwI/R+wr159IznH1GciwiOIJZ3dx
X-Google-Smtp-Source: AGHT+IGm/HlJzmVOx3qkzdGz18J9Zzs1lxwsRoIaDIzE+rN4vmr9Kn37wsNKPodJ3M09EDpgxUli+w==
X-Received: by 2002:a17:907:6090:b0:b87:2d79:61c with SMTP id a640c23a62f3a-b872d7908a9mr135738066b.8.1768231029400;
        Mon, 12 Jan 2026 07:17:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fcm8oQrlYCv48/iC8k2lTGFfMXl7/wD5nqTuRnimPlcw=="
Received: by 2002:a05:6402:4610:20b0:649:784c:cac1 with SMTP id
 4fb4d7f45d1cf-650748ec41bls2095260a12.2.-pod-prod-09-eu; Mon, 12 Jan 2026
 07:17:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUbTN6wMjmnq2LbDlVC5LwJSXGS4+9XSZ92vN+Y0gYVuHPFYfJ2fUcHE3ffcaHpIcTV9gczkgzCyzo=@googlegroups.com
X-Received: by 2002:a17:906:7954:b0:b87:2579:b6cf with SMTP id a640c23a62f3a-b872579ba1bmr230991866b.41.1768231027244;
        Mon, 12 Jan 2026 07:17:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231027; cv=none;
        d=google.com; s=arc-20240605;
        b=TC9cHZHzHUEJ0WvZk7p9Dfml1og7RdyAs/BcjrXeRaqLxum7cGBq6cVkAreP/g5E7j
         ZIr7M1lwT2DjYimwlalIKT7V9tZ82kkkG2dhhxKVI4FyX4IdXUAeRkDeYxfT5CrFCJTM
         cWqch6TdApw6FeJxR0eodusU3ZEg44O1XmfnXdsgtrdeAgFaQvHKZQFWPGRgt3moy1KM
         p2+BDFMD/JPttU5tBn/jBkjzWAJds1So57W7db4uZXezwAxXP2cWxeMyUOEIo/Pf5ais
         vZX/ddaR64ZPPnOPmUlTycvXZDa/fM0gCS/fm93CV72ug89QPQijVUz4XhR7ZNp9rP2O
         JNYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=v6cRCZ2uht5FrarNg/yCMPHI/FNHADk8HmE9kFOaEj8=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=OUd9yGATzlXb2HCKtZ37Q7b0uAmSEAyRB32t4IBI454r8mFt8XOSP3wqGfEuGBocw2
         s/7nxG8RhR3hVBBgF6Vkct6wEKAcn+7SKdA9TefwoQQKR08NnbS0mkQbVtyx5eSfqYIU
         WnoXu+GMb/W2gS3KbRFq1SNkcdIno9x4tfo7TfDbCvkipbfGoR1aK4LJhtrRe0efaTRq
         ObwVsUxP/tM4P4Ww1V2k648zK79R1bm8NDXjOPfoqCUCColN8QKQGjNk/fJehcAJA8J5
         rqlv5L807cwj3QNpAWaK5diG5W5l8mLVhGNGLlzsH3T7s4UlaXZXT40pZYP5Md9f+Bb+
         6nPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b870d104efdsi8320666b.4.2026.01.12.07.17.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:07 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 361813368C;
	Mon, 12 Jan 2026 15:16:58 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 167FB3EA63;
	Mon, 12 Jan 2026 15:16:58 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id CE42BWoQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:58 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:17:01 +0100
Subject: [PATCH RFC v2 07/20] slab: handle kmalloc sheaves bootstrap
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-7-98225cfb50cf@suse.cz>
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
X-Rspamd-Queue-Id: 361813368C
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Level: 
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Spam-Flag: NO
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

Enable sheaves for kmalloc caches. For other types than KMALLOC_NORMAL,
we can simply allow them in calculate_sizes() as they are created later
than KMALLOC_NORMAL caches and can allocate sheaves and barns from
those.

For KMALLOC_NORMAL caches we perform additional step after first
creating them without sheaves. Then bootstrap_cache_sheaves() simply
allocates and initializes barns and sheaves and finally sets
s->sheaf_capacity to make them actually used.

Afterwards the only caches left without sheaves (unless SLUB_TINY or
debugging is enabled) are kmem_cache and kmem_cache_node. These are only
used when creating or destroying other kmem_caches. Thus they are not
performance critical and we can simply leave it that way.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 88 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++---
 1 file changed, 84 insertions(+), 4 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 0177a654a06a..f2de44f8bda4 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2593,7 +2593,8 @@ static void *setup_object(struct kmem_cache *s, void *object)
 	return object;
 }
 
-static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
+static struct slab_sheaf *__alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp,
+					      unsigned int capacity)
 {
 	struct slab_sheaf *sheaf;
 	size_t sheaf_size;
@@ -2611,7 +2612,7 @@ static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
 	if (s->flags & SLAB_KMALLOC)
 		gfp |= __GFP_NO_OBJ_EXT;
 
-	sheaf_size = struct_size(sheaf, objects, s->sheaf_capacity);
+	sheaf_size = struct_size(sheaf, objects, capacity);
 	sheaf = kzalloc(sheaf_size, gfp);
 
 	if (unlikely(!sheaf))
@@ -2624,6 +2625,12 @@ static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
 	return sheaf;
 }
 
+static inline struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s,
+						   gfp_t gfp)
+{
+	return __alloc_empty_sheaf(s, gfp, s->sheaf_capacity);
+}
+
 static void free_empty_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf)
 {
 	kfree(sheaf);
@@ -8117,8 +8124,11 @@ static int calculate_sizes(struct kmem_cache_args *args, struct kmem_cache *s)
 	if (s->flags & SLAB_RECLAIM_ACCOUNT)
 		s->allocflags |= __GFP_RECLAIMABLE;
 
-	/* kmalloc caches need extra care to support sheaves */
-	if (!is_kmalloc_cache(s))
+	/*
+	 * For KMALLOC_NORMAL caches we enable sheaves later by
+	 * bootstrap_kmalloc_sheaves() to avoid recursion
+	 */
+	if (!is_kmalloc_normal(s))
 		s->sheaf_capacity = calculate_sheaf_capacity(s, args);
 
 	/*
@@ -8613,6 +8623,74 @@ static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
 	return s;
 }
 
+/*
+ * Finish the sheaves initialization done normally by init_percpu_sheaves() and
+ * init_kmem_cache_nodes(). For normal kmalloc caches we have to bootstrap it
+ * since sheaves and barns are allocated by kmalloc.
+ */
+static void __init bootstrap_cache_sheaves(struct kmem_cache *s)
+{
+	struct kmem_cache_args empty_args = {};
+	unsigned int capacity;
+	bool failed = false;
+	int node, cpu;
+
+	capacity = calculate_sheaf_capacity(s, &empty_args);
+
+	/* capacity can be 0 due to debugging or SLUB_TINY */
+	if (!capacity)
+		return;
+
+	for_each_node_mask(node, slab_nodes) {
+		struct node_barn *barn;
+
+		barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, node);
+
+		if (!barn) {
+			failed = true;
+			goto out;
+		}
+
+		barn_init(barn);
+		get_node(s, node)->barn = barn;
+	}
+
+	for_each_possible_cpu(cpu) {
+		struct slub_percpu_sheaves *pcs;
+
+		pcs = per_cpu_ptr(s->cpu_sheaves, cpu);
+
+		pcs->main = __alloc_empty_sheaf(s, GFP_KERNEL, capacity);
+
+		if (!pcs->main) {
+			failed = true;
+			break;
+		}
+	}
+
+out:
+	/*
+	 * It's still early in boot so treat this like same as a failure to
+	 * create the kmalloc cache in the first place
+	 */
+	if (failed)
+		panic("Out of memory when creating kmem_cache %s\n", s->name);
+
+	s->sheaf_capacity = capacity;
+}
+
+static void __init bootstrap_kmalloc_sheaves(void)
+{
+	enum kmalloc_cache_type type;
+
+	for (type = KMALLOC_NORMAL; type <= KMALLOC_RANDOM_END; type++) {
+		for (int idx = 0; idx < KMALLOC_SHIFT_HIGH + 1; idx++) {
+			if (kmalloc_caches[type][idx])
+				bootstrap_cache_sheaves(kmalloc_caches[type][idx]);
+		}
+	}
+}
+
 void __init kmem_cache_init(void)
 {
 	static __initdata struct kmem_cache boot_kmem_cache,
@@ -8656,6 +8734,8 @@ void __init kmem_cache_init(void)
 	setup_kmalloc_cache_index_table();
 	create_kmalloc_caches();
 
+	bootstrap_kmalloc_sheaves();
+
 	/* Setup random freelists for each cache */
 	init_freelist_randomization();
 

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-7-98225cfb50cf%40suse.cz.

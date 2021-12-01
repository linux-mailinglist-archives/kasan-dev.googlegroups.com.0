Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBOXXT2GQMGQEVCCUYXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 06A954654EF
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Dec 2021 19:15:23 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id c15-20020a05651200cf00b0040524451deesf9836948lfp.20
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Dec 2021 10:15:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638382522; cv=pass;
        d=google.com; s=arc-20160816;
        b=saOI4d8Q7wgMdAb6Jnujyllamivm8wpcXaJgqPFSHfTqgbvoByrPuFL+3C5iJpfcFI
         VL/Oj4PXI6K1qIvWmYvQYWlgFToL5PB/X1rE2jSxgE0NyUVwj5y2Rfuh4iPnyv6E8n1n
         OIdF3cTVJsRexCyeBCvfVM7p5IR+O5k7o/m9FPoutE85BurKn62Fy5Dq2ZhEq5Uu56M1
         24ccBKls6hFPC7ZHZNa3Nkn160y+apNXjumaNQ7vh9DV32jFUpF9cjHUVcJ8clOiVRcR
         We9NlOMOWq+f2qqOHlxRtyW4vfqE+yUhzLOdwilHlFxVjP6ChJziZh7iGeZxqDWRLeWg
         C4Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=G0isFOpCHziWD+S3JqsGVKkucptacRcnjEF1QGuqHCg=;
        b=lEDyJKyi2M2nv6TLEq7uTvzHdPE3lr4/AKMioC1Do/+2EniZik1sG/yO+umGTCaKCb
         /Ctp8NT3sTFqPNYn5w8uP460uPwMJd82THiiozDPEqsY6UTzblORl/Gg0nT2RuU8E/m2
         u9cNbwtnwYLieyt/AP+IfltL+w9Lt2PLmKwM9T++0vHCQc07qJuusmPMapZduZbVbvZJ
         43lD+NItaMe392LPCpfz0k/QZj5qXMakeskNe1H7K09NWzqK+a4EYaFPOvaqI/R7xSbO
         8dmQdOyjCMeAuNxWYRByAkJFTozutIqLphqv5WaB6bZjlaHxfvpGwiv8exdLTN3vSupX
         qOXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=tFIyyHyX;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G0isFOpCHziWD+S3JqsGVKkucptacRcnjEF1QGuqHCg=;
        b=XTgHa/fZIaitPJwQ6SiNIZRgHU0QkV5EkgIZZ57LEsNfR/rHZIb5cjNpmhHr56zaEs
         FzftxeA3YHPL2ntiJLo0IXm0NgM1I3Jf2VqvnA7bZNAeWu893KRjTkCMzcrfh3kao+oi
         hycPt3GbXXhO/FQFSAh5YWn0MAoJXwjgPfy8dgxAXjS2GnYykiNZbELYcZsGUzXb9M1d
         ZM7HT/KX0HOHZFDACQoneUeg6O35OfeeQ4sKNgDYYGuM9CD913chbEhMLRbr/Nzei3pO
         Z4rdJc+SYYLbFdyLHSIach/57Hl1ekRMcx31Sx67//+5ieMM4Tz9QBCHNInd+rs7oQoW
         Zxzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G0isFOpCHziWD+S3JqsGVKkucptacRcnjEF1QGuqHCg=;
        b=t2DX0JHsr5Q5/mvpyaxCHbZOAsOdiD0MRsBvRZdHSg5UwmN+If85IHAvIOPxu0pHm4
         7v6E8FmomL8bpvVLfHIi63/a0sCO3nZVyQWsliirqu+BVmKSHcdHwvU/TpME6yGcbzt5
         x+BNTe9FY9R4LvQjenuJHeC7Y2INcz56RdsJoBhIZqXovUPPmsSn4fFSab6b/esjeuw2
         ez/k4rwTR0aC8WqJS15qUZvHHIOgkqNHLqJny4tJtdieVqr6j5arAwfhivCmWiOKaFRq
         X4kRRLAC72n6KofaFtqPH70gNDDsZciRjMtTinw8si9ep9t3yvNrOr9/XzSf4r+4j19Y
         copA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533SJnEJOtZhtvDh8zAstWyVaPNz2lj+UJvwhFN9KbO/RRFvEPpf
	/gb9xCZKdj1aLUVilzahhtY=
X-Google-Smtp-Source: ABdhPJzXKrJyiOBvHv3witMM42tkuMhSFOJCTjpVZW8S6O1lyrEQ9b2jV+DVFVg2yTVPcPWt/VO7tA==
X-Received: by 2002:a2e:a7cb:: with SMTP id x11mr7312539ljp.308.1638382522618;
        Wed, 01 Dec 2021 10:15:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e10:: with SMTP id i16ls1374668lfv.3.gmail; Wed,
 01 Dec 2021 10:15:21 -0800 (PST)
X-Received: by 2002:a05:6512:3ca4:: with SMTP id h36mr7350300lfv.411.1638382521558;
        Wed, 01 Dec 2021 10:15:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638382521; cv=none;
        d=google.com; s=arc-20160816;
        b=jU+4pSYbVVyYovbKo8JU8/eHI2Tv6LOWwrjnyfPcte6t8mkMclecpKF9usdgWTuc0+
         99q+iKBHCu8D2Jl/o2D8bbtM7rBJz6kMNEeMqBH2mC/JbfbkqWNWRjrghTCmwH80shx9
         VG2uap2oim2i7lcI5lq/HuxNuuKe5sD79i6zSwmTlq+vPGTJGMLv4YKCE1POnHngATg7
         Mw1AMGShe/lWWtM94XGBhrqqzox5uNKUpLxpDIE+LrfRXVZEraJFPP0FMQWoSbcTOvgh
         haHnvd2IgzuatKaUnEODjjL004nBwbbLecJLp+NeVdrXTrFCkLCdBM4Fn3FiD2izmwO5
         ROlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=XZjPNTGeYgeJU7BzAGxIgYnoqBmAt3jbNWLNHSCHwj8=;
        b=0nncUNhIQA4jkycyRAv9FJ2GPAMVL/+BJAQFe7LFnLnJnkU6mRsuOXXQbmS/5pVsxV
         ef7jezibiaoK35pqoSL4jqaHQmXoL+W1qyQgxWoTQPhEAZIqOFVjNOrLJoWnvfpbfyRx
         8XGyHASHzAxNNOOzQSA3wwch13jw7kgQKX0t1E4vykvi6BzZ9qtMGtzU1AdjX3syHbiq
         STuKEDICmXlu+gcLWDHk6Xd/B0VLOP3Nl9CHsCJB6vjDtGNw6FJvZZqRp2txZ9lzfiUq
         EzdxSxDeIhfuI7flabbIE3fmg6klrgZ7QBpUhpHEv0yR7YawdJefMhOfWQxlZaZdBve+
         Gfbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=tFIyyHyX;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id j13si46389lfu.5.2021.12.01.10.15.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Dec 2021 10:15:21 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id EE5B51FE00;
	Wed,  1 Dec 2021 18:15:20 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id BAE1214050;
	Wed,  1 Dec 2021 18:15:20 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id ILcZLbi7p2HPSAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 01 Dec 2021 18:15:20 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Matthew Wilcox <willy@infradead.org>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>
Cc: linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>,
	patches@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH v2 31/33] mm/sl*b: Differentiate struct slab fields by sl*b implementations
Date: Wed,  1 Dec 2021 19:15:08 +0100
Message-Id: <20211201181510.18784-32-vbabka@suse.cz>
X-Mailer: git-send-email 2.33.1
In-Reply-To: <20211201181510.18784-1-vbabka@suse.cz>
References: <20211201181510.18784-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=4577; h=from:subject; bh=VqBKrlF8E1KP8dUW3jPbmTVnQ1WbeBkExRZte4OfzrU=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBhp7unZdUzLs0RNxbE/xmUdWJ810YKUGhGeSZfPW6o 7rs8ZZ2JATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYae7pwAKCRDgIcpz8YmpEIPsB/ 9/DvPvnX4saooYE2CjNL/WpfwKE9KVeMTAfr2tSHpcIbRGXVO4R5UjvNOGzrOfs15j2/BgmZ2zBqrM FcwzelfEE+fyPKRmfzCLhfNbrCGQY+1wP/p07yHmAuV/Qco3xyynOf0epe0HDPhXa2AljhKEflo+U/ lef6W9BycDdK1D8Bjka9VgpPbrTJsSiSn72/qpX2KPmYBvGM8xbw5LeiY1y4WuiLWJQQfaNwUAyURt zDpxfztinl2aDcm0yetB/cGl3RcXxYBwRbWiW4hUbo6bESX32RnCR297fo35LbADHhEuA9bVcOs2t5 jo1r/oPaVD5EClfgWhqm5bor1t37SQ
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=tFIyyHyX;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
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

With a struct slab definition separate from struct page, we can go further and
define only fields that the chosen sl*b implementation uses. This means
everything between __page_flags and __page_refcount placeholders now depends on
the chosen CONFIG_SL*B. Some fields exist in all implementations (slab_list)
but can be part of a union in some, so it's simpler to repeat them than
complicate the definition with ifdefs even more.

The patch doesn't change physical offsets of the fields, although it could be
done later - for example it's now clear that tighter packing in SLOB could be
possible.

This should also prevent accidental use of fields that don't exist in given
implementation. Before this patch virt_to_cache() and and cache_from_obj() was
visible for SLOB (albeit not used), although it relies on the slab_cache field
that isn't set by SLOB. With this patch it's now a compile error, so these
functions are now hidden behind #ifndef CONFIG_SLOB.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
Tested-by: Marco Elver <elver@google.com> # kfence
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: <kasan-dev@googlegroups.com>
---
 mm/kfence/core.c |  9 +++++----
 mm/slab.h        | 46 ++++++++++++++++++++++++++++++++++++----------
 2 files changed, 41 insertions(+), 14 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 4eb60cf5ff8b..46103a7628a6 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -427,10 +427,11 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	/* Set required slab fields. */
 	slab = virt_to_slab((void *)meta->addr);
 	slab->slab_cache = cache;
-	if (IS_ENABLED(CONFIG_SLUB))
-		slab->objects = 1;
-	if (IS_ENABLED(CONFIG_SLAB))
-		slab->s_mem = addr;
+#if defined(CONFIG_SLUB)
+	slab->objects = 1;
+#elif defined (CONFIG_SLAB)
+	slab->s_mem = addr;
+#endif
 
 	/* Memory initialization. */
 	for_each_canary(meta, set_canary_byte);
diff --git a/mm/slab.h b/mm/slab.h
index 2d50c099a222..8c5a8c005896 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -8,9 +8,24 @@
 /* Reuses the bits in struct page */
 struct slab {
 	unsigned long __page_flags;
+
+#if defined(CONFIG_SLAB)
+
+	union {
+		struct list_head slab_list;
+		struct rcu_head rcu_head;
+	};
+	struct kmem_cache *slab_cache;
+	void *freelist;	/* array of free object indexes */
+	void * s_mem;	/* first object */
+	unsigned int active;
+
+#elif defined(CONFIG_SLUB)
+
 	union {
 		struct list_head slab_list;
-		struct {	/* Partial pages */
+		struct rcu_head rcu_head;
+		struct {
 			struct slab *next;
 #ifdef CONFIG_64BIT
 			int slabs;	/* Nr of slabs left */
@@ -18,25 +33,32 @@ struct slab {
 			short int slabs;
 #endif
 		};
-		struct rcu_head rcu_head;
 	};
-	struct kmem_cache *slab_cache; /* not slob */
+	struct kmem_cache *slab_cache;
 	/* Double-word boundary */
 	void *freelist;		/* first free object */
 	union {
-		void *s_mem;	/* slab: first object */
-		unsigned long counters;		/* SLUB */
-		struct {			/* SLUB */
+		unsigned long counters;
+		struct {
 			unsigned inuse:16;
 			unsigned objects:15;
 			unsigned frozen:1;
 		};
 	};
+	unsigned int __unused;
+
+#elif defined(CONFIG_SLOB)
+
+	struct list_head slab_list;
+	void * __unused_1;
+	void *freelist;		/* first free block */
+	void * __unused_2;
+	int units;
+
+#else
+#error "Unexpected slab allocator configured"
+#endif
 
-	union {
-		unsigned int active;		/* SLAB */
-		int units;			/* SLOB */
-	};
 	atomic_t __page_refcount;
 #ifdef CONFIG_MEMCG
 	unsigned long memcg_data;
@@ -47,7 +69,9 @@ struct slab {
 	static_assert(offsetof(struct page, pg) == offsetof(struct slab, sl))
 SLAB_MATCH(flags, __page_flags);
 SLAB_MATCH(compound_head, slab_list);	/* Ensure bit 0 is clear */
+#ifndef CONFIG_SLOB
 SLAB_MATCH(rcu_head, rcu_head);
+#endif
 SLAB_MATCH(_refcount, __page_refcount);
 #ifdef CONFIG_MEMCG
 SLAB_MATCH(memcg_data, memcg_data);
@@ -623,6 +647,7 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s,
 }
 #endif /* CONFIG_MEMCG_KMEM */
 
+#ifndef CONFIG_SLOB
 static inline struct kmem_cache *virt_to_cache(const void *obj)
 {
 	struct slab *slab;
@@ -669,6 +694,7 @@ static inline struct kmem_cache *cache_from_obj(struct kmem_cache *s, void *x)
 		print_tracking(cachep, x);
 	return cachep;
 }
+#endif /* CONFIG_SLOB */
 
 static inline size_t slab_ksize(const struct kmem_cache *s)
 {
-- 
2.33.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211201181510.18784-32-vbabka%40suse.cz.

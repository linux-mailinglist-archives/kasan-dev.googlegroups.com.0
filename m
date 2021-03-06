Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSMTROBAMGQEP47IT3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B5AC132F728
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 01:16:09 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id d3sf1381075lfc.18
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 16:16:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614989769; cv=pass;
        d=google.com; s=arc-20160816;
        b=RZt2Zd0mWI7e6S5ZUh3cgVzpEQhI+j35YXcGrtSmVFAyEGytGXxdFNOwu4gTkQyqva
         Whec2eotjhEBOMcAJZNIMkkod3cjDfA85DtHb5dGalvac/C12xgRlZQ4cZwtVy1XIQ9K
         b8h36c1u42RvcMJ+8VDJ1swJ/xiJKI1BexLbkd6vV3iXMnViRWijGoJwF3ybK0x5zYC3
         UJfx56+fwKN4fn9kE3qFr+l+Z1cgjq7muYCnxoe4ozsbhjokXz/e2oJRJOrUHqyADlx2
         690o+HGWXgAEKSE81WViNcnbpm8WVc6Xc+rNFAkkZR41Igr6O7dmnH4Dqqn9hkW9Cwtd
         nRmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=LrQw4BS9e6g6E07ulecP7XomYiYyFbp8e6KBVgVfXyE=;
        b=JuVu3lGHmvVjQQMzh1KYmoGuwKPmwThYSsNdHjXB+uobxhDZuG6YJ9e5o4TJZ03EqA
         r0F4jBY96t9z18ueIaT5amAeUtKXjumlVB1ESzpShwJHCm1SLoJCDyAT615SkGrPB2lR
         +1N8YaOFUAMDnoUlHIQuGoySWbqd4pEhfqws4hyuJ8QUgOHgTRkxNbO436thWpGffr+d
         mxu5nrDjrg2Tf9UnrwWC18b9/2WRPVEn6VbB8VNv/OUECnAt7Bt9eQturWS9CpSyNpDk
         TZURnRWhU4e0fVAzQwu7D9HfawU8A4ZF0MrLmYxweXZ2S1LkxfQxmkiTA5beRH2ytvzR
         f93Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YdUPNXd1;
       spf=pass (google.com: domain of 3x8lcyaokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3x8lCYAoKCW4MZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LrQw4BS9e6g6E07ulecP7XomYiYyFbp8e6KBVgVfXyE=;
        b=QMpv767SWgL5N6N4ClCbJ2Y4cIAOhMezLeDn2SMMsfCFXmnuPvDtOl64e3iyODD/V2
         EO8+++x80oS/jmnwwPbKy6jSKCGGdjUlpsKDhHBExV2fsUTadBFeIv5jjVe52WkaUHdq
         z5aDhXaX4A3u28eYZ4S2jDUfMxqLZWUuYvMPLsM6gt9dZblNX+nktXnrQPXksoSY8pG4
         AXTSKTaKlEUTuzxriyy3x2Ik6Ri6t6xu9E7/iFCGvuP5/QPm34zO1vtDGRNFG62j6Ev/
         wHdPgq9i7kSrUlwfMD3rEQ8Gz93rRfDd18rB7gbodKbJN9boGrKR7Z8yx6mb7BTulg5R
         eSpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LrQw4BS9e6g6E07ulecP7XomYiYyFbp8e6KBVgVfXyE=;
        b=kqlDzJssKuHlxob8ikKxWII5LH8SohIoQi/xrYVNiulbiFzOlBP0C03g/cdf5n9c5d
         nXJ9JUxGh8yqg1emAICPbrUZ1QHgTuulLFUAnD4+i1pnQ9ddcbDP6LKcB8uRexrPikQb
         PXNflVoUj0nEbLdo4YUzfktEeTKPDserJyLXfj7ECtVBL4quV98FYLfs9TozZ+Yf4tu/
         /kiqL0p79o4kMoXfOlgnlnENncEiBcHFy2liCle15/bR5Kx1eR877m0uiGXlBDYrxjKj
         um90fUIQWdgjBuNAuIKyttCht+ngrTppHi8//N6XdYU2jZZ/RpaqCWIEzhAASFSDeyT5
         0Z8g==
X-Gm-Message-State: AOAM530vb4k2D+MNDYuH3ELyOi/31Xon4IoaXiWk09/YwFenFT7lmC1F
	aBTaNJYPwz/ODCjf3oX0Tgk=
X-Google-Smtp-Source: ABdhPJzza1bmim12MxCUQDUc2BtE6P5mjOsRgklauH0u2srzKEjDgNltVT6xCxCwFUInj4CMkdsduA==
X-Received: by 2002:a2e:7614:: with SMTP id r20mr6843725ljc.80.1614989769314;
        Fri, 05 Mar 2021 16:16:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9a48:: with SMTP id k8ls2292442ljj.10.gmail; Fri, 05 Mar
 2021 16:16:08 -0800 (PST)
X-Received: by 2002:a2e:3a17:: with SMTP id h23mr6401989lja.158.1614989768326;
        Fri, 05 Mar 2021 16:16:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614989768; cv=none;
        d=google.com; s=arc-20160816;
        b=ZJ1+cuIChTyCyUPDfTdiMbJ3gBw+fTTjEcsYmJ0jhpPP0GmORafRPHrQkKXvaQ9Bjh
         FuTxXXieN55GOzXz4nP01Xn3OoQIZQZsW/1dfa7TGkpYgOefCOv0wt7PXv1c5ooORKi9
         LqpJTL4P97U/ewnInxcr15lJ+CuS0O/URQJRkxPaXk6ClpFsHnMu1XZO64/s3R9hVz8u
         kVvvYqmRfFRfBXC8HmVImDgQ60Pht2ynxjvQg6LLecTbdhhKtunYn3MBZwNgzmgPhY8/
         ZmObr1t2bW9vnXU3nBUswf+z6Iv86emfsbVjXOPLINoBVei/W55DdWAcbtZ/30QIA/UB
         ptxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=LxzF2AGWcMrRhep0n4A0P/U22pMClYyggQ6qHhFXe4g=;
        b=adae/4Pv9/BvbQKDWyyqexEQ7ULhS3eZiJtVM5PvO5GBC7UVemGrAAbT0rEHfayuky
         gNMpGIXzePsq9yR8X3Yhm+BIzJwETtOTlfc4CXWwTVui3IlJ3StO2DzuEU+PXUeSwsQq
         Qb1pmDvsEWaP6gLED7FKYO+vsAFZTS8NtO16HKlTofOV6DAvvpF1mrtNZ37tbRzo0CkA
         1S1bJiGEqYPXWiu+cN00ko45DkZkibdgjPTJMCi6vo7UfH4/kndo2rfVZBm3k1pugJ6L
         1iQUQEFyMRKtVEnvBJDS+kXYbxoppD9fBG4XXy3tX4+9S+DBYIec9meWdin6kdubl8vv
         XC5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YdUPNXd1;
       spf=pass (google.com: domain of 3x8lcyaokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3x8lCYAoKCW4MZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id j12si163896lfg.8.2021.03.05.16.16.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 16:16:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 3x8lcyaokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id h21so1751756wrc.19
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 16:16:08 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:953b:d7cf:2b01:f178])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c308:: with SMTP id
 k8mr11022960wmj.54.1614989767705; Fri, 05 Mar 2021 16:16:07 -0800 (PST)
Date: Sat,  6 Mar 2021 01:15:53 +0100
In-Reply-To: <cover.1614989433.git.andreyknvl@google.com>
Message-Id: <b8cc85d5cc9818b72e543d8034ce38acce0c0300.1614989433.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1614989433.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH 4/5] kasan, mm: integrate slab init_on_alloc with HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YdUPNXd1;       spf=pass
 (google.com: domain of 3x8lcyaokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3x8lCYAoKCW4MZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This change uses the previously added memory initialization feature
of HW_TAGS KASAN routines for slab memory when init_on_alloc is enabled.

With this change, memory initialization memset() is no longer called
when both HW_TAGS KASAN and init_on_alloc are enabled. Instead, memory
is initialized in KASAN runtime.

The memory initialization memset() is moved into slab_post_alloc_hook()
that currently directly follows the initialization loop. A new argument
is added to slab_post_alloc_hook() that indicates whether to initialize
the memory or not.

To avoid discrepancies with which memory gets initialized that can be
caused by future changes, both KASAN hook and initialization memset()
are put together and a warning comment is added.

Combining setting allocation tags with memory initialization improves
HW_TAGS KASAN performance when init_on_alloc is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  8 ++++----
 mm/kasan/common.c     |  4 ++--
 mm/slab.c             | 28 +++++++++++++---------------
 mm/slab.h             | 17 +++++++++++++----
 mm/slub.c             | 27 +++++++++++----------------
 5 files changed, 43 insertions(+), 41 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 4c0f414a893b..bb756f6c73b5 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -216,12 +216,12 @@ static __always_inline void kasan_slab_free_mempool(void *ptr)
 }
 
 void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
-				       void *object, gfp_t flags);
+				       void *object, gfp_t flags, bool init);
 static __always_inline void * __must_check kasan_slab_alloc(
-				struct kmem_cache *s, void *object, gfp_t flags)
+		struct kmem_cache *s, void *object, gfp_t flags, bool init)
 {
 	if (kasan_enabled())
-		return __kasan_slab_alloc(s, object, flags);
+		return __kasan_slab_alloc(s, object, flags, init);
 	return object;
 }
 
@@ -306,7 +306,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object)
 static inline void kasan_kfree_large(void *ptr) {}
 static inline void kasan_slab_free_mempool(void *ptr) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
-				   gfp_t flags)
+				   gfp_t flags, bool init)
 {
 	return object;
 }
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6107c795611f..7ea747b18c26 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -428,7 +428,7 @@ static void set_alloc_info(struct kmem_cache *cache, void *object,
 }
 
 void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
-					void *object, gfp_t flags)
+					void *object, gfp_t flags, bool init)
 {
 	u8 tag;
 	void *tagged_object;
@@ -453,7 +453,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 	 * Unpoison the whole object.
 	 * For kmalloc() allocations, kasan_kmalloc() will do precise poisoning.
 	 */
-	kasan_unpoison(tagged_object, cache->object_size, false);
+	kasan_unpoison(tagged_object, cache->object_size, init);
 
 	/* Save alloc info (if possible) for non-kmalloc() allocations. */
 	if (kasan_stack_collection_enabled())
diff --git a/mm/slab.c b/mm/slab.c
index 51fd424e0d6d..936dd686dec9 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3216,6 +3216,7 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid, size_t orig_
 	void *ptr;
 	int slab_node = numa_mem_id();
 	struct obj_cgroup *objcg = NULL;
+	bool init = false;
 
 	flags &= gfp_allowed_mask;
 	cachep = slab_pre_alloc_hook(cachep, &objcg, 1, flags);
@@ -3254,12 +3255,10 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid, size_t orig_
   out:
 	local_irq_restore(save_flags);
 	ptr = cache_alloc_debugcheck_after(cachep, flags, ptr, caller);
-
-	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && ptr)
-		memset(ptr, 0, cachep->object_size);
+	init = slab_want_init_on_alloc(flags, cachep);
 
 out_hooks:
-	slab_post_alloc_hook(cachep, objcg, flags, 1, &ptr);
+	slab_post_alloc_hook(cachep, objcg, flags, 1, &ptr, init);
 	return ptr;
 }
 
@@ -3301,6 +3300,7 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, size_t orig_size, unsigned lo
 	unsigned long save_flags;
 	void *objp;
 	struct obj_cgroup *objcg = NULL;
+	bool init = false;
 
 	flags &= gfp_allowed_mask;
 	cachep = slab_pre_alloc_hook(cachep, &objcg, 1, flags);
@@ -3317,12 +3317,10 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, size_t orig_size, unsigned lo
 	local_irq_restore(save_flags);
 	objp = cache_alloc_debugcheck_after(cachep, flags, objp, caller);
 	prefetchw(objp);
-
-	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && objp)
-		memset(objp, 0, cachep->object_size);
+	init = slab_want_init_on_alloc(flags, cachep);
 
 out:
-	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp);
+	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
 	return objp;
 }
 
@@ -3542,18 +3540,18 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 
 	cache_alloc_debugcheck_after_bulk(s, flags, size, p, _RET_IP_);
 
-	/* Clear memory outside IRQ disabled section */
-	if (unlikely(slab_want_init_on_alloc(flags, s)))
-		for (i = 0; i < size; i++)
-			memset(p[i], 0, s->object_size);
-
-	slab_post_alloc_hook(s, objcg, flags, size, p);
+	/*
+	 * memcg and kmem_cache debug support and memory initialization.
+	 * Done outside of the IRQ disabled section.
+	 */
+	slab_post_alloc_hook(s, objcg, flags, size, p,
+				slab_want_init_on_alloc(flags, s));
 	/* FIXME: Trace call missing. Christoph would like a bulk variant */
 	return size;
 error:
 	local_irq_enable();
 	cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
-	slab_post_alloc_hook(s, objcg, flags, i, p);
+	slab_post_alloc_hook(s, objcg, flags, i, p, false);
 	__kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
diff --git a/mm/slab.h b/mm/slab.h
index 076582f58f68..0116a314cd21 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -506,15 +506,24 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
 }
 
 static inline void slab_post_alloc_hook(struct kmem_cache *s,
-					struct obj_cgroup *objcg,
-					gfp_t flags, size_t size, void **p)
+					struct obj_cgroup *objcg, gfp_t flags,
+					size_t size, void **p, bool init)
 {
 	size_t i;
 
 	flags &= gfp_allowed_mask;
+
+	/*
+	 * As memory initialization is integrated with hardware tag-based
+	 * KASAN, kasan_slab_alloc and initialization memset must be
+	 * kept together to avoid discrepancies in behavior.
+	 *
+	 * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
+	 */
 	for (i = 0; i < size; i++) {
-		p[i] = kasan_slab_alloc(s, p[i], flags);
-		/* As p[i] might get tagged, call kmemleak hook after KASAN. */
+		p[i] = kasan_slab_alloc(s, p[i], flags, init);
+		if (p[i] && init && !IS_ENABLED(CONFIG_KASAN_HW_TAGS))
+			memset(p[i], 0, s->object_size);
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, flags);
 	}
diff --git a/mm/slub.c b/mm/slub.c
index e26c274b4657..f53df23760e3 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2822,6 +2822,7 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 	struct page *page;
 	unsigned long tid;
 	struct obj_cgroup *objcg = NULL;
+	bool init = false;
 
 	s = slab_pre_alloc_hook(s, &objcg, 1, gfpflags);
 	if (!s)
@@ -2899,12 +2900,10 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 	}
 
 	maybe_wipe_obj_freeptr(s, object);
-
-	if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
-		memset(kasan_reset_tag(object), 0, s->object_size);
+	init = slab_want_init_on_alloc(gfpflags, s);
 
 out:
-	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object);
+	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init);
 
 	return object;
 }
@@ -3356,20 +3355,16 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	c->tid = next_tid(c->tid);
 	local_irq_enable();
 
-	/* Clear memory outside IRQ disabled fastpath loop */
-	if (unlikely(slab_want_init_on_alloc(flags, s))) {
-		int j;
-
-		for (j = 0; j < i; j++)
-			memset(kasan_reset_tag(p[j]), 0, s->object_size);
-	}
-
-	/* memcg and kmem_cache debug support */
-	slab_post_alloc_hook(s, objcg, flags, size, p);
+	/*
+	 * memcg and kmem_cache debug support and memory initialization.
+	 * Done outside of the IRQ disabled fastpath loop.
+	 */
+	slab_post_alloc_hook(s, objcg, flags, size, p,
+				slab_want_init_on_alloc(flags, s));
 	return i;
 error:
 	local_irq_enable();
-	slab_post_alloc_hook(s, objcg, flags, i, p);
+	slab_post_alloc_hook(s, objcg, flags, i, p, false);
 	__kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
@@ -3579,7 +3574,7 @@ static void early_kmem_cache_node_alloc(int node)
 	init_object(kmem_cache_node, n, SLUB_RED_ACTIVE);
 	init_tracking(kmem_cache_node, n);
 #endif
-	n = kasan_slab_alloc(kmem_cache_node, n, GFP_KERNEL);
+	n = kasan_slab_alloc(kmem_cache_node, n, GFP_KERNEL, false);
 	page->freelist = get_freepointer(kmem_cache_node, n);
 	page->inuse = 1;
 	page->frozen = 0;
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b8cc85d5cc9818b72e543d8034ce38acce0c0300.1614989433.git.andreyknvl%40google.com.

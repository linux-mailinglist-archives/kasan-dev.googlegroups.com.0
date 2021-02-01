Return-Path: <kasan-dev+bncBDX4HWEMTEBRB35T4GAAMGQEFYE2B2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id DDC1D30B098
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 20:43:43 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id h18sf11077847wrr.5
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 11:43:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612208623; cv=pass;
        d=google.com; s=arc-20160816;
        b=xDchhv4AcxjAkwU5bdt99udl9uOrDmdNm2tIZ/gokci1FI1jXXDQcyboHcQ5VagyL2
         Zhzy2skEEUcII8024bwEqikQeD3k8ePxD9d6FnPBuBvz8oPFy2KjNVQnM+RnsZaUFnfu
         G0GX/kZqh9v3a7vkXRJO5/d2YmGAOqnCMJehlI5WPHXeyKKAQmHqn/kiTIZS9E7RD0uh
         raEKoVR3t5R/GZ8ljg6mnDZO0/1Oqci4vYDCnHJXcvbmcvhuy/dqFlQjsXIEMhimhqq3
         mCmQrJrNo/AnmozTAw/2KC05NpSr+rrmmIyy8SZgte0cMpN94eQIXmmr7Pq+tgeUgvZl
         LzZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=qFKDCbF9edluvK5tZ3ZbQ+sZ+T+eSLyK4IDLGJLKAv8=;
        b=A3p5TqF1TOHDZXrqydPPf4TMC8qszYOSneGloqWHBh+mPWfuHHsuV1ZT6nITD97Smc
         L9G69AuZ9iQ+/6R3hKdBMbm1dZnZ7x/fWh8HkQAMeIIeenFeYGtJKyVZqimqm5Zj1VWQ
         I+Ds1pfC5yjYNhnPvjQlbHwaJlhDmxuMM6yRjD2Nt9rJf/Tg1KK+64rZ43b7fxiDiuAE
         4gz3YGxb/NfKEEjnKu6lwlr0clJFzL5lXz9H7UPLbKq9qNLrlwnFKZ3ir4jZDSa8wObv
         SjIYg2I1Jvft9yxjnqOp+Kuao2zlLoAGx7501jPcB8CKpVjhryrDScoIgtqPGJBlpsyA
         qcJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e176a67f;
       spf=pass (google.com: domain of 37lkyyaokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=37lkYYAoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qFKDCbF9edluvK5tZ3ZbQ+sZ+T+eSLyK4IDLGJLKAv8=;
        b=WUmZoed+/KUQRZDtIqDYCuJGLb37WuX/wS9FnL9T4TUsJSQ82uT2EcrE0O41Pw1X7u
         sb6QIUtvJO1aSnVMFTgX1KG1iRKauLZmMt2f/CWQUKs/eTiO8VNuT14IWwck0kMAssFR
         /SYda1c62KpBfP9/POZHG+VTe5/DgsC2IExVG5lwGq5uashlc1NVq4wGtitP7Xu4Xmuv
         zTNcnV0P8O8aXBK4ltZv6R7kTfVrvCFzMXdJ7EGGfCEASncoqyFiMRlwrX3Hf06j2Z/S
         gfuvLj9os9vSkjgSRnvs/Bz7ulMFUYvljfuiStK21pgiGUnqoH4PIPyUyUNsR3OhCoz8
         Yq8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qFKDCbF9edluvK5tZ3ZbQ+sZ+T+eSLyK4IDLGJLKAv8=;
        b=hlSj4SS2KI2HMfzf4XRbcYvLfq+Cee6R3xLYnGprn3pGnPg7xx+zh0MeBzVdZoshNq
         NEjwNsYO7CWfLGjgEdeh8ugUrHdKM5ejNHg90q/uDKdTHGt85zatofD4i1hB2mVIQxaj
         5lFCAI6AuXow1jbQCBCtHIDs6IpTeJR4fihvnWI0+oxORlKR1RZ1mcByjSfCTUf0s2qj
         pxTK+V+zI1kus9ldzUQ0fyGarMaaafzayzvYbKykh17PyC54eyCJhRN5X7tUWRWjG+25
         K5056eZkUxQI2PA4IMZLIW3ctdcGIVpwucvtCOll1lTkg3f6Qqn5sM2Cserw1kM96Qkh
         eFRA==
X-Gm-Message-State: AOAM531WFZx7enYdtL3GHetwRyC2Rz4GAwtm5aP01WDuQfvOEGYr8wGM
	nu8L/efZJlACSv1LoqcU3v8=
X-Google-Smtp-Source: ABdhPJwpx4OUkR01sZpwAmvJLtKueSj4sEXsAD/QtVvsPQ/6yvCBQYLbBLSibKK5lQpvOZPdXJNbXg==
X-Received: by 2002:adf:cf04:: with SMTP id o4mr19897586wrj.412.1612208623739;
        Mon, 01 Feb 2021 11:43:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4485:: with SMTP id j5ls10461750wrq.1.gmail; Mon, 01 Feb
 2021 11:43:43 -0800 (PST)
X-Received: by 2002:adf:ffcd:: with SMTP id x13mr20164784wrs.149.1612208622996;
        Mon, 01 Feb 2021 11:43:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612208622; cv=none;
        d=google.com; s=arc-20160816;
        b=bIZ9jAii1v+sMkKRM9sfnhkGOrBklL5F1PZn63hlUrjyt/eDJN52v7ZbhndqziFaH2
         OklG1o9XdaRgvBOETrd9WK0Ae3MLhk+Rn/B+aZAjyxnnRYOrAWS06Efx9GOywxMJsYb1
         MVSiuidw6XVAZrji8MGmXh9NHh74Cbr+7KMAyvBmExX8HjytHqZC4ahyJDyhx1C9VwGf
         Hw7QqEuNcDgFrianjIWX/gO+3Bep8qG6WcQ5KsPSwdo5/C/AW0q34l0LKMWZKJ14iZC6
         Hq4ODKB1EFMmuIJaWwE3QsSZ0xqzQJIz/jJJTdPHssMd4oJLRvvYxW+UWbSa1yf+2Bz7
         53Ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=xUtTTHPe7DRCgRtwSi+4scq+pNy2/ibyykEGsvZRuk0=;
        b=YtnSBmjzG4nBa9enpnNG4J7PIlybD5X31nQM96AGsbqtRd7GZ18SfQyhxJ4KoXtHfp
         IJjkSqgNwmXjcusZtEws2eyL3ni7UPF+wd55Beu7v4firbbZ74mUlzt1I1SqcsCbSjDT
         M8InOy3Fu+rLc5xXKbGhFufGf+JuTnhyw/Si7nklwfw4zu5GdtR8zXthBExd3E5PwdeS
         2DvGx1MNxylSIlusDc4zuZ/YbZAMxfmo/wgg0lGMYx2WL/rHghTcusY8vuak/ICgzIQv
         fblxKst99YVieEBJJ8pb1DK5O4I1vfm4EQ7qeuE6nS1JFglyMN+loeNWW4RQFuWyGrtf
         RS2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e176a67f;
       spf=pass (google.com: domain of 37lkyyaokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=37lkYYAoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id t16si53325wmi.3.2021.02.01.11.43.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 11:43:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 37lkyyaokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id t13so177504wmq.7
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 11:43:42 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:8109:: with SMTP id
 c9mr380514wmd.137.1612208622386; Mon, 01 Feb 2021 11:43:42 -0800 (PST)
Date: Mon,  1 Feb 2021 20:43:25 +0100
In-Reply-To: <cover.1612208222.git.andreyknvl@google.com>
Message-Id: <c153f78b173df7537c9be6f2f3a888ddf0b42a3b.1612208222.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH 01/12] kasan, mm: don't save alloc stacks twice
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=e176a67f;       spf=pass
 (google.com: domain of 37lkyyaokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=37lkYYAoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
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

Currently KASAN saves allocation stacks in both kasan_slab_alloc() and
kasan_kmalloc() annotations. This patch changes KASAN to save allocation
stacks for slab objects from kmalloc caches in kasan_kmalloc() only,
and stacks for other slab objects in kasan_slab_alloc() only.

This change requires ____kasan_kmalloc() knowing whether the object
belongs to a kmalloc cache. This is implemented by adding a flag field
to the kasan_info structure. That flag is only set for kmalloc caches
via a new kasan_cache_create_kmalloc() annotation.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  9 +++++++++
 mm/kasan/common.c     | 18 ++++++++++++++----
 mm/slab_common.c      |  1 +
 3 files changed, 24 insertions(+), 4 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 6d8f3227c264..2d5de4092185 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -83,6 +83,7 @@ static inline void kasan_disable_current(void) {}
 struct kasan_cache {
 	int alloc_meta_offset;
 	int free_meta_offset;
+	bool is_kmalloc;
 };
 
 #ifdef CONFIG_KASAN_HW_TAGS
@@ -143,6 +144,13 @@ static __always_inline void kasan_cache_create(struct kmem_cache *cache,
 		__kasan_cache_create(cache, size, flags);
 }
 
+void __kasan_cache_create_kmalloc(struct kmem_cache *cache);
+static __always_inline void kasan_cache_create_kmalloc(struct kmem_cache *cache)
+{
+	if (kasan_enabled())
+		__kasan_cache_create_kmalloc(cache);
+}
+
 size_t __kasan_metadata_size(struct kmem_cache *cache);
 static __always_inline size_t kasan_metadata_size(struct kmem_cache *cache)
 {
@@ -278,6 +286,7 @@ static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
 				      slab_flags_t *flags) {}
+static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 static inline void kasan_poison_slab(struct page *page) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index fe852f3cfa42..374049564ea3 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -210,6 +210,11 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 		*size = optimal_size;
 }
 
+void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
+{
+	cache->kasan_info.is_kmalloc = true;
+}
+
 size_t __kasan_metadata_size(struct kmem_cache *cache)
 {
 	if (!kasan_stack_collection_enabled())
@@ -394,17 +399,22 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 	}
 }
 
-static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
+static void set_alloc_info(struct kmem_cache *cache, void *object,
+				gfp_t flags, bool kmalloc)
 {
 	struct kasan_alloc_meta *alloc_meta;
 
+	/* Don't save alloc info for kmalloc caches in kasan_slab_alloc(). */
+	if (cache->kasan_info.is_kmalloc && !kmalloc)
+		return;
+
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	if (alloc_meta)
 		kasan_set_track(&alloc_meta->alloc_track, flags);
 }
 
 static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
-				size_t size, gfp_t flags, bool keep_tag)
+				size_t size, gfp_t flags, bool kmalloc)
 {
 	unsigned long redzone_start;
 	unsigned long redzone_end;
@@ -423,7 +433,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				KASAN_GRANULE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
 				KASAN_GRANULE_SIZE);
-	tag = assign_tag(cache, object, false, keep_tag);
+	tag = assign_tag(cache, object, false, kmalloc);
 
 	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
 	kasan_unpoison(set_tag(object, tag), size);
@@ -431,7 +441,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 			   KASAN_KMALLOC_REDZONE);
 
 	if (kasan_stack_collection_enabled())
-		set_alloc_info(cache, (void *)object, flags);
+		set_alloc_info(cache, (void *)object, flags, kmalloc);
 
 	return set_tag(object, tag);
 }
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 9aa3d2fe4c55..39d1a8ff9bb8 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -647,6 +647,7 @@ struct kmem_cache *__init create_kmalloc_cache(const char *name,
 		panic("Out of memory when creating slab %s\n", name);
 
 	create_boot_cache(s, name, size, flags, useroffset, usersize);
+	kasan_cache_create_kmalloc(s);
 	list_add(&s->list, &slab_caches);
 	s->refcount = 1;
 	return s;
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c153f78b173df7537c9be6f2f3a888ddf0b42a3b.1612208222.git.andreyknvl%40google.com.

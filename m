Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPMNXT6QKGQEB6NLWZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 14FF22B2843
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:46 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id t3sf4397160lfk.21
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306045; cv=pass;
        d=google.com; s=arc-20160816;
        b=pOI7D1YBDRncbVbQi47T53v37L0NKPQcEtHCo91uLyAhauwFODqgSjwnqPz/Srie0J
         EkRTVtYiwMntJS57EHmMgFZrciLD4wlEyT96Krl2WfA4255pxLS0JqAm2lA/iKEcmZiw
         tDoNpEymzBA0cuDJ2OLkhDqHksL411V6x1j7X2vrt6jH1NAUsx6wfn/piSjURUIBxAc8
         EfsX6MOLIjjiYHmLtnEmTEwgDPnvEg9GRCRhwNLd6C+4J8b2LIH9htRqgD659+n0t+Hh
         NNpOIHqj6AKwqC7RdJW7zU1u+7dNzN9S+dktmjXi3bKqe08nYN1Fy+4vjM0EZromRWia
         1oIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=nvnHE3Zv0/6i04ztLoGBsnXY2Yn3K5/jUzc+9/hBUVc=;
        b=Bkc1Qa82lVUNkYsI+Lk2APN9N8Aslrnce7TPnAzfb+23hgfZtoowqRW4QdhSsMDtYX
         bED73h9GARAwBepYSztay/UCpCS1Elhs4v3ZCfERvqk2kUhJUgCbDa/Em8Vcj69GuQvE
         uTffLStLaIE1nxOtGpPz/D/Ogde0bpoApzgeUhuk+RjqAYNsu07hA23WbOL46hGGfv2+
         xH4si62hUMDnm82H2aVlRZP3SA0uBPcICBmju3veIOjRksXaFcE0vy+j5uy9TI2bd5In
         iarXQvvruLmMnS1ovITqy2nUl0kn2vWB2vgw/G2gdXq4vHFDBOeTXnAtkNp4OOB65qeg
         GcRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pmVSO2bc;
       spf=pass (google.com: domain of 3uwavxwokcygmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3uwavXwoKCYgmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nvnHE3Zv0/6i04ztLoGBsnXY2Yn3K5/jUzc+9/hBUVc=;
        b=jiM2r/tXyboNVSPC20g9CbDNzbSW0lAADowlCs344Mq4+l1ERWKKpYAQReA0E5D5Ft
         TU8oNSIAhgDBUQWVz4cucHtq2VxGzUmCOXzdg+5r9JtnMThB/pLaZEMtnDySJnqaVUqD
         0ni4/8NJA4l4vnO+FRGBhDnR4n41HH9Z6PeA3TCjcnuzbnMktRjhiaSTedUhXBZaSmmX
         fkgzPTvpmI9aiwT50FTSoZyPEzGiFqailpwJcuZc+NGIDPjoUq3TqhavsHj7tOfKAdbA
         yYEHacQTMNA2Argo/8qtdMgdqpsYpeKwU1vdkVP2LvAYMdxtumu5sihdpC7CF2hIwHbJ
         +5EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nvnHE3Zv0/6i04ztLoGBsnXY2Yn3K5/jUzc+9/hBUVc=;
        b=Xutvk4SajSP50j3G5cwQxyFFW0WLN2WiwJrV1Pu3+5+KG9z8d3n+2f8nqgC/D5pNF9
         LKSiEd9v2dArbxLNAEJFJxIItyeGzXGEzfKdUoRrILocTuYx6b9m10rInimDQUBqBytW
         PJvkWn5bCDiIWxGeFEj9rIFB0ghZLYWJ9LDh1/ibSGaQE/eHQNfCJhSCA7qB4qCUehC2
         4jv7AHwtoZOK4kcbcan4oWbmiYqlKTIPiMqHGb5sWG76R29eq78hmFtVSVKqUqFwCwRP
         A6FrQbpoGLUo78o/VSRReYieglrWbassu4bBpBJmmMkVhWauFxC0YlGuBHYH98veoj+a
         Debg==
X-Gm-Message-State: AOAM532vOX8EhGbpbvzULcmAcH/zpEG6+vvL0ojZifGiba7Gd6m/Iaq8
	iFXlTYgeLxw+JSbIewI45gQ=
X-Google-Smtp-Source: ABdhPJwuBT7I5aCjbjq+RrW8PZ4as6JC4MEUQCoXKaA5tBIFaYLDRzN7cdAnp3M8EV8T/xVyh2U0dA==
X-Received: by 2002:a2e:894e:: with SMTP id b14mr2071626ljk.370.1605306045677;
        Fri, 13 Nov 2020 14:20:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:480e:: with SMTP id v14ls4572860lfa.2.gmail; Fri, 13 Nov
 2020 14:20:44 -0800 (PST)
X-Received: by 2002:a19:952:: with SMTP id 79mr1927526lfj.559.1605306044612;
        Fri, 13 Nov 2020 14:20:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306044; cv=none;
        d=google.com; s=arc-20160816;
        b=GwzUrVMX6VJCkZLoNYMg1zLNCHBxgWUT10u+/c0SJMMiEb6bOvdAt1Gh2DT9v1eBuq
         qnicrS8gZfccUNV+GfsFDRrDj/S2iwqVaETRycYBYFt4AhP6nRdZfuJfluusCUCrGfWv
         TjzjIE2jQNtF0HNL8CRBK2B3hfB7UTwuUIaq0u4eFS9SHk01gltkkaNbgq6EfIHlmEmO
         QPpp7921xFL0xfx7NlJO1b/lrTBzpdQwpnLwsqCfOL3ofOhe4g+zqgPsGLiE/DQJFeGo
         E/iouq/ogPYW8qep+0QEX62i+RmVDHPSP1nIHsPufkfx0u/TSou4r51asOhFf/TQGrc3
         yKMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=BSF3Q9byE1BU2/WI2HEHM9hwbewwBwz05B55UYa5pyQ=;
        b=tEJktpV8MjZzKcH0OQdTrl3wRT8/ikATUNcowD9INl1A0Yv6JWDdp97UieQCAzhYZH
         /eaHFmfnWsX7vGd+bRrDRZg1Sqi2Sy/QfkZaeuY8RVwKCzA2HLxzTj3NxRuzmC0bw1rs
         /kokCQl4ZH4HwyfPY1PuoZaSsy2iKhh38Way3g3H54KJrPQHnRBZHHanzqC24stZZ0E0
         xG9alhFJGXfmCnnKalk2L5I/LafeDMxeFteJFnGVuWAbtE2ZP9vUuWnbc+2VvBLkzE+6
         62C9afX0EXxcDJbOrnmKZDJti6EY843sX/OPy7ubgp6GCU/mgCUo0G4PJFwxCaKxEcSG
         qQGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pmVSO2bc;
       spf=pass (google.com: domain of 3uwavxwokcygmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3uwavXwoKCYgmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id i67si238939lfi.2.2020.11.13.14.20.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uwavxwokcygmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id n25so5550858edr.20
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:44 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:1a0b:: with SMTP id
 i11mr4339374ejf.404.1605306043965; Fri, 13 Nov 2020 14:20:43 -0800 (PST)
Date: Fri, 13 Nov 2020 23:20:02 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <68b9e818c971a28c4b8082d6dbac52967553bd73.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 12/19] kasan, mm: check kasan_enabled in annotations
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Vincenzo Frascino <Vincenzo.Frascino@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pmVSO2bc;       spf=pass
 (google.com: domain of 3uwavxwokcygmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3uwavXwoKCYgmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
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

Declare the kasan_enabled static key in include/linux/kasan.h and in
include/linux/mm.h and check it in all kasan annotations. This allows to
avoid any slowdown caused by function calls when kasan_enabled is
disabled.

Co-developed-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
Signed-off-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I2589451d3c96c97abbcbf714baabe6161c6f153e
---
 include/linux/kasan.h | 213 ++++++++++++++++++++++++++++++++----------
 include/linux/mm.h    |  22 +++--
 mm/kasan/common.c     |  56 +++++------
 3 files changed, 210 insertions(+), 81 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 872bf145ddde..6bd95243a583 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -2,6 +2,7 @@
 #ifndef _LINUX_KASAN_H
 #define _LINUX_KASAN_H
 
+#include <linux/static_key.h>
 #include <linux/types.h>
 
 struct kmem_cache;
@@ -74,54 +75,176 @@ static inline void kasan_disable_current(void) {}
 
 #ifdef CONFIG_KASAN
 
-void kasan_unpoison_range(const void *address, size_t size);
+struct kasan_cache {
+	int alloc_meta_offset;
+	int free_meta_offset;
+};
 
-void kasan_alloc_pages(struct page *page, unsigned int order);
-void kasan_free_pages(struct page *page, unsigned int order);
+#ifdef CONFIG_KASAN_HW_TAGS
+DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
+static __always_inline bool kasan_enabled(void)
+{
+	return static_branch_likely(&kasan_flag_enabled);
+}
+#else
+static inline bool kasan_enabled(void)
+{
+	return true;
+}
+#endif
 
-void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
-			slab_flags_t *flags);
+void __kasan_unpoison_range(const void *addr, size_t size);
+static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_range(addr, size);
+}
 
-void kasan_poison_slab(struct page *page);
-void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
-void kasan_poison_object_data(struct kmem_cache *cache, void *object);
-void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
-					const void *object);
+void __kasan_alloc_pages(struct page *page, unsigned int order);
+static __always_inline void kasan_alloc_pages(struct page *page,
+						unsigned int order)
+{
+	if (kasan_enabled())
+		__kasan_alloc_pages(page, order);
+}
 
-void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
-						gfp_t flags);
-void kasan_kfree_large(void *ptr, unsigned long ip);
-void kasan_poison_kfree(void *ptr, unsigned long ip);
-void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
-					size_t size, gfp_t flags);
-void * __must_check kasan_krealloc(const void *object, size_t new_size,
-					gfp_t flags);
+void __kasan_free_pages(struct page *page, unsigned int order);
+static __always_inline void kasan_free_pages(struct page *page,
+						unsigned int order)
+{
+	if (kasan_enabled())
+		__kasan_free_pages(page, order);
+}
 
-void * __must_check kasan_slab_alloc(struct kmem_cache *s, void *object,
-					gfp_t flags);
-bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
+void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
+				slab_flags_t *flags);
+static __always_inline void kasan_cache_create(struct kmem_cache *cache,
+				unsigned int *size, slab_flags_t *flags)
+{
+	if (kasan_enabled())
+		__kasan_cache_create(cache, size, flags);
+}
 
-struct kasan_cache {
-	int alloc_meta_offset;
-	int free_meta_offset;
-};
+size_t __kasan_metadata_size(struct kmem_cache *cache);
+static __always_inline size_t kasan_metadata_size(struct kmem_cache *cache)
+{
+	if (kasan_enabled())
+		return __kasan_metadata_size(cache);
+	return 0;
+}
+
+void __kasan_poison_slab(struct page *page);
+static __always_inline void kasan_poison_slab(struct page *page)
+{
+	if (kasan_enabled())
+		return __kasan_poison_slab(page);
+}
+
+void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
+static __always_inline void kasan_unpoison_object_data(struct kmem_cache *cache,
+							void *object)
+{
+	if (kasan_enabled())
+		return __kasan_unpoison_object_data(cache, object);
+}
+
+void __kasan_poison_object_data(struct kmem_cache *cache, void *object);
+static __always_inline void kasan_poison_object_data(struct kmem_cache *cache,
+							void *object)
+{
+	if (kasan_enabled())
+		__kasan_poison_object_data(cache, object);
+}
+
+void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
+					  const void *object);
+static __always_inline void * __must_check kasan_init_slab_obj(
+				struct kmem_cache *cache, const void *object)
+{
+	if (kasan_enabled())
+		return __kasan_init_slab_obj(cache, object);
+	return (void *)object;
+}
+
+bool __kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
+static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object,
+						unsigned long ip)
+{
+	if (kasan_enabled())
+		return __kasan_slab_free(s, object, ip);
+	return false;
+}
+
+void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
+				       void *object, gfp_t flags);
+static __always_inline void * __must_check kasan_slab_alloc(
+				struct kmem_cache *s, void *object, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_slab_alloc(s, object, flags);
+	return object;
+}
+
+void * __must_check __kasan_kmalloc(struct kmem_cache *s, const void *object,
+				    size_t size, gfp_t flags);
+static __always_inline void * __must_check kasan_kmalloc(struct kmem_cache *s,
+				const void *object, size_t size, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_kmalloc(s, object, size, flags);
+	return (void *)object;
+}
 
-size_t kasan_metadata_size(struct kmem_cache *cache);
+void * __must_check __kasan_kmalloc_large(const void *ptr,
+					  size_t size, gfp_t flags);
+static __always_inline void * __must_check kasan_kmalloc_large(const void *ptr,
+						      size_t size, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_kmalloc_large(ptr, size, flags);
+	return (void *)ptr;
+}
+
+void * __must_check __kasan_krealloc(const void *object,
+				     size_t new_size, gfp_t flags);
+static __always_inline void * __must_check kasan_krealloc(const void *object,
+						 size_t new_size, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_krealloc(object, new_size, flags);
+	return (void *)object;
+}
+
+void __kasan_poison_kfree(void *ptr, unsigned long ip);
+static __always_inline void kasan_poison_kfree(void *ptr, unsigned long ip)
+{
+	if (kasan_enabled())
+		__kasan_poison_kfree(ptr, ip);
+}
+
+void __kasan_kfree_large(void *ptr, unsigned long ip);
+static __always_inline void kasan_kfree_large(void *ptr, unsigned long ip)
+{
+	if (kasan_enabled())
+		__kasan_kfree_large(ptr, ip);
+}
 
 bool kasan_save_enable_multi_shot(void);
 void kasan_restore_multi_shot(bool enabled);
 
 #else /* CONFIG_KASAN */
 
+static inline bool kasan_enabled(void)
+{
+	return false;
+}
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
-
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
-
 static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
 				      slab_flags_t *flags) {}
-
+static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 static inline void kasan_poison_slab(struct page *page) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
 					void *object) {}
@@ -132,36 +255,32 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
 {
 	return (void *)object;
 }
-
-static inline void *kasan_kmalloc_large(void *ptr, size_t size, gfp_t flags)
+static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
+				   unsigned long ip)
 {
-	return ptr;
+	return false;
+}
+static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
+				   gfp_t flags)
+{
+	return object;
 }
-static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
-static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
 static inline void *kasan_kmalloc(struct kmem_cache *s, const void *object,
 				size_t size, gfp_t flags)
 {
 	return (void *)object;
 }
+static inline void *kasan_kmalloc_large(const void *ptr, size_t size, gfp_t flags)
+{
+	return (void *)ptr;
+}
 static inline void *kasan_krealloc(const void *object, size_t new_size,
 				 gfp_t flags)
 {
 	return (void *)object;
 }
-
-static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
-				   gfp_t flags)
-{
-	return object;
-}
-static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
-				   unsigned long ip)
-{
-	return false;
-}
-
-static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
+static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
+static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
 
 #endif /* CONFIG_KASAN */
 
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 947f4f1a6536..24f47e140a4c 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -31,6 +31,7 @@
 #include <linux/sizes.h>
 #include <linux/sched.h>
 #include <linux/pgtable.h>
+#include <linux/kasan.h>
 
 struct mempolicy;
 struct anon_vma;
@@ -1415,22 +1416,30 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
 #endif /* CONFIG_NUMA_BALANCING */
 
 #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+
 static inline u8 page_kasan_tag(const struct page *page)
 {
-	return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
+	if (kasan_enabled())
+		return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
+	return 0xff;
 }
 
 static inline void page_kasan_tag_set(struct page *page, u8 tag)
 {
-	page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
-	page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
+	if (kasan_enabled()) {
+		page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
+		page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
+	}
 }
 
 static inline void page_kasan_tag_reset(struct page *page)
 {
-	page_kasan_tag_set(page, 0xff);
+	if (kasan_enabled())
+		page_kasan_tag_set(page, 0xff);
 }
-#else
+
+#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
+
 static inline u8 page_kasan_tag(const struct page *page)
 {
 	return 0xff;
@@ -1438,7 +1447,8 @@ static inline u8 page_kasan_tag(const struct page *page)
 
 static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
 static inline void page_kasan_tag_reset(struct page *page) { }
-#endif
+
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline struct zone *page_zone(const struct page *page)
 {
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a11e3e75eb08..17918bd20ed9 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -59,7 +59,7 @@ void kasan_disable_current(void)
 }
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
-void kasan_unpoison_range(const void *address, size_t size)
+void __kasan_unpoison_range(const void *address, size_t size)
 {
 	unpoison_range(address, size);
 }
@@ -87,7 +87,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 }
 #endif /* CONFIG_KASAN_STACK */
 
-void kasan_alloc_pages(struct page *page, unsigned int order)
+void __kasan_alloc_pages(struct page *page, unsigned int order)
 {
 	u8 tag;
 	unsigned long i;
@@ -101,7 +101,7 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
 	unpoison_range(page_address(page), PAGE_SIZE << order);
 }
 
-void kasan_free_pages(struct page *page, unsigned int order)
+void __kasan_free_pages(struct page *page, unsigned int order)
 {
 	if (likely(!PageHighMem(page)))
 		poison_range(page_address(page),
@@ -128,8 +128,8 @@ static inline unsigned int optimal_redzone(unsigned int object_size)
 		object_size <= (1 << 16) - 1024 ? 1024 : 2048;
 }
 
-void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
-			slab_flags_t *flags)
+void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
+			  slab_flags_t *flags)
 {
 	unsigned int orig_size = *size;
 	unsigned int redzone_size;
@@ -174,7 +174,7 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	*flags |= SLAB_KASAN;
 }
 
-size_t kasan_metadata_size(struct kmem_cache *cache)
+size_t __kasan_metadata_size(struct kmem_cache *cache)
 {
 	if (!kasan_stack_collection_enabled())
 		return 0;
@@ -197,7 +197,7 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 	return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
 }
 
-void kasan_poison_slab(struct page *page)
+void __kasan_poison_slab(struct page *page)
 {
 	unsigned long i;
 
@@ -207,12 +207,12 @@ void kasan_poison_slab(struct page *page)
 		     KASAN_KMALLOC_REDZONE);
 }
 
-void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
+void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 {
 	unpoison_range(object, cache->object_size);
 }
 
-void kasan_poison_object_data(struct kmem_cache *cache, void *object)
+void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
 	poison_range(object,
 			round_up(cache->object_size, KASAN_GRANULE_SIZE),
@@ -265,7 +265,7 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
 #endif
 }
 
-void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
+void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 						const void *object)
 {
 	struct kasan_alloc_meta *alloc_meta;
@@ -284,7 +284,7 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
+static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 			      unsigned long ip, bool quarantine)
 {
 	u8 tag;
@@ -330,9 +330,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	return IS_ENABLED(CONFIG_KASAN_GENERIC);
 }
 
-bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
+bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 {
-	return __kasan_slab_free(cache, object, ip, true);
+	return ____kasan_slab_free(cache, object, ip, true);
 }
 
 static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
@@ -340,7 +340,7 @@ static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
 }
 
-static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
+static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				size_t size, gfp_t flags, bool keep_tag)
 {
 	unsigned long redzone_start;
@@ -375,20 +375,20 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	return set_tag(object, tag);
 }
 
-void * __must_check kasan_slab_alloc(struct kmem_cache *cache, void *object,
-					gfp_t flags)
+void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
+					void *object, gfp_t flags)
 {
-	return __kasan_kmalloc(cache, object, cache->object_size, flags, false);
+	return ____kasan_kmalloc(cache, object, cache->object_size, flags, false);
 }
 
-void * __must_check kasan_kmalloc(struct kmem_cache *cache, const void *object,
-				size_t size, gfp_t flags)
+void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object,
+					size_t size, gfp_t flags)
 {
-	return __kasan_kmalloc(cache, object, size, flags, true);
+	return ____kasan_kmalloc(cache, object, size, flags, true);
 }
-EXPORT_SYMBOL(kasan_kmalloc);
+EXPORT_SYMBOL(__kasan_kmalloc);
 
-void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
+void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 						gfp_t flags)
 {
 	struct page *page;
@@ -413,7 +413,7 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
 	return (void *)ptr;
 }
 
-void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
+void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
 {
 	struct page *page;
 
@@ -423,13 +423,13 @@ void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
 	page = virt_to_head_page(object);
 
 	if (unlikely(!PageSlab(page)))
-		return kasan_kmalloc_large(object, size, flags);
+		return __kasan_kmalloc_large(object, size, flags);
 	else
-		return __kasan_kmalloc(page->slab_cache, object, size,
+		return ____kasan_kmalloc(page->slab_cache, object, size,
 						flags, true);
 }
 
-void kasan_poison_kfree(void *ptr, unsigned long ip)
+void __kasan_poison_kfree(void *ptr, unsigned long ip)
 {
 	struct page *page;
 
@@ -442,11 +442,11 @@ void kasan_poison_kfree(void *ptr, unsigned long ip)
 		}
 		poison_range(ptr, page_size(page), KASAN_FREE_PAGE);
 	} else {
-		__kasan_slab_free(page->slab_cache, ptr, ip, false);
+		____kasan_slab_free(page->slab_cache, ptr, ip, false);
 	}
 }
 
-void kasan_kfree_large(void *ptr, unsigned long ip)
+void __kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr)))
 		kasan_report_invalid_free(ptr, ip);
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/68b9e818c971a28c4b8082d6dbac52967553bd73.1605305978.git.andreyknvl%40google.com.

Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOMCRX6QKGQEPXU6M7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E0F3A2A737E
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:03:05 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id n207sf136389lfa.23
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:03:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534585; cv=pass;
        d=google.com; s=arc-20160816;
        b=PCvPycHpJ2lIu+Bo1dUTwjVDdHG5ycydWc4C4T+47x1liM7eHxUMZ55UiY9vBJ3FVf
         O18FU20MZ9YJKFvkqXqcXGYbR5b1/HkMPMAEtZs736Ten6q8zhRR/9zCkwPe/T4qmISU
         HGYqDfr4Wh8f4hToHt3RAO4aBLdJl9dQzpL//MUIYPv+oBdkbyDLnBtyk9c4WdHlOhIu
         Pj2NJv7dSX+cXfw07AKN0QQuxaP6n3aJm87L20h0vBakbfTss1QIlSNaxfprB9P96P+8
         tWiooDRB+emC21AKI7LbzWzE8hmklHcUKjtJihoRUAPsAkp+yHNcLBtwCZdJ7m/V2kdA
         3h1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=VG6oFgWtcZRzFH8CSO/jGFNdYLI2JWmAW2hjmT4IpFk=;
        b=YeL42dsujImGItCX7fPCFymnU7IEjVsEnWVOQa1EkRuTY6NSqnAI4r/lGSXWiGfmMV
         bQTBiQHPUwRHXAXqSWyCKopCvu+CsJ8vmsZ0Zp0eKRJuxLIiIK/2UDtLGOEDq2BiZ9ki
         CndKBWRI9k/Fg9pdPTcOeHQm0cYLFEGPoRxDvphQqQII/u2pbktsR+5zoB14lizBt/0E
         aocN8ciW8vbTYb9c94UagJFOHcf/dM3sTiCmgsQx4MNEuMAXL2DYmIQ+WUdvY6zO3Yd2
         YPOO40VRW7WHAYayu32I/s2dlGdcrzfm2PlsaB04PcONiDCj5qHS1/Ur1WGzqvBw9aLK
         kwvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YYO+EYSi;
       spf=pass (google.com: domain of 3n0gjxwokcuomzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3N0GjXwoKCUomzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VG6oFgWtcZRzFH8CSO/jGFNdYLI2JWmAW2hjmT4IpFk=;
        b=T1zuPT/D1SCAkca8/5ugvFQ1Ioc/+s/ZENtWW2r6kp7uh7Tyl6J0rFYjarIfcT3iau
         yhnUPSaJOZsdT9E/NK/7vl+HMvItdMk/i2oR4qOzRC2XGKZZvFrgRzBeHHbvU957S5i3
         48eKC7Z2Sg3CaWzl7iEUjs5eI3G8ySOwdcMRFMzllIAlqUtqjSOhfAqQz7Dfk7wn2fKi
         eYqBt75Sdr7/7k4FHpfVb9EYvn+l0i4MVU8sTySII/wYl6t0lcAGV5XF6gp4velJtvR4
         7dE3FSlg7t9wtK4Jdw4nOr0ZFZvHTEBLHaTT3iGSW0joSwsIGYFM4GnpUmrqrrzhh6P3
         a82g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VG6oFgWtcZRzFH8CSO/jGFNdYLI2JWmAW2hjmT4IpFk=;
        b=IGDcvY/U375xqdpNzL77lPDto3cWH53owdkxj/AhXwbc6siEcUEzfJQK1DkA7TvoGZ
         t2WA3e9b9Z169o5UShDn2oWDVDID9QNFrB+qJ5nrIWR3e/0Yluo6KcmcRxr/MABM4rPc
         dXFPiTrtHd9UXd+eb9BzVtV2+4YE1Pyfs7qY0YUCkO1HXONlBBQb0RzmhAka2iSSSiG0
         4cxFNtEFX02Gl5fOccl3gwbdpML12dRIgM+FrfQ2OdJiNGo7yLp4+1tye/RxQQ9XdP9g
         DVjpX1SIMiKWPf/6Dd5KvePVCWMtikIFhXuKoqKlpUv02lrRAWFS5jEfOGImEcQPUuQ1
         OfBQ==
X-Gm-Message-State: AOAM5314xqU2yNssjil4In81BjAbqKNfXgjAr17GjSBOCfVChyFKlO7q
	cRtLzexAYL5ioiBmMlz+5ik=
X-Google-Smtp-Source: ABdhPJwWAovNQG+DgNKJ/ToMNeGpu+MsB0IBXzUrApJ9ds7khaDdodLlrqH/YJWcQ677G9IvGSavVQ==
X-Received: by 2002:a2e:5016:: with SMTP id e22mr157138ljb.301.1604534585477;
        Wed, 04 Nov 2020 16:03:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2023:: with SMTP id s3ls2306156lfs.0.gmail; Wed, 04
 Nov 2020 16:03:04 -0800 (PST)
X-Received: by 2002:ac2:59d1:: with SMTP id x17mr78459lfn.142.1604534584597;
        Wed, 04 Nov 2020 16:03:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534584; cv=none;
        d=google.com; s=arc-20160816;
        b=B6SuMwndhhuJKlXnN6d51kVPDXzVYokGfNvMACinOZc83wVVKF7ILkfxTNhSlaNkyv
         dYDnRqPbAVd4fupIQcobAjdEp+LAhBHk/8vpvIaJgLePmIEz3+iz5nEgDyldlCJ9lONg
         LFfAsYvzF5zopQv8OE9viM9u18OTGIIvbfY8sJuo8vMoWCmU44OoUZc56By5fWKcqaI1
         9zj21dNGKPDjg6EPcXu/uzUm6y0TEwBtiDLnOuu023bRT0zF5kEBHgA1KVUqHNWuTuDp
         Oqs62tLUKMIwlv0zWn26w9l5+T3C+B0pHcb/aFhbufc8vtYVk+Lh6fNBdS/s85uyW2tK
         vheA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=DKUUdpjKzvhCcD6WgylaP6PBqV8CAT8cUIeT7JoiXzA=;
        b=ztO/Hb5Jbi2f5oUV9DmNTbnbNhju7ZiFROxmcihzLZKHyKQWe37ejWoZHOs7Wrp97G
         JPmDBxDCF6NKaTs07K6pNmVX9ZiX32O2Nw3RCeVALByOS8FcV4XQJFu8ARi+n4/s7AEl
         iB2hBiNofDf6OSrTlGWSpWsvt9qKzQ0uFtNzM7iBMTJ5I7zS8JzPVUi98NcrcChUovCg
         Vlj3BwVbeEDFVApSnUatJgdYwO8oyD0v0VNleo9kD9G46VUIodfVkL/7to5V3cZ3jiz4
         roToS2ab4pTl96C6USGGtQJ4eaWLFKcHTIUC+BRCEvpJ2d78CbtDurlfOdGOplBm1WTY
         ONNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YYO+EYSi;
       spf=pass (google.com: domain of 3n0gjxwokcuomzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3N0GjXwoKCUomzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id y11si111234lfg.7.2020.11.04.16.03.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:03:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3n0gjxwokcuomzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id n16so37836edw.19
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:03:04 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6402:14cf:: with SMTP id
 f15mr356123edx.18.1604534583946; Wed, 04 Nov 2020 16:03:03 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:22 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <f44efbb38afe1a1bc2bba2b4b6698e16cb216bbd.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 12/20] kasan, mm: check kasan_enabled in annotations
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YYO+EYSi;       spf=pass
 (google.com: domain of 3n0gjxwokcuomzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3N0GjXwoKCUomzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I2589451d3c96c97abbcbf714baabe6161c6f153e
---
 include/linux/kasan.h | 220 ++++++++++++++++++++++++++++++++----------
 include/linux/mm.h    |  22 +++--
 mm/kasan/common.c     |  60 ++++++------
 3 files changed, 216 insertions(+), 86 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 34236f134472..ae1046fc74e5 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -2,6 +2,7 @@
 #ifndef _LINUX_KASAN_H
 #define _LINUX_KASAN_H
 
+#include <linux/jump_label.h>
 #include <linux/types.h>
 
 struct kmem_cache;
@@ -72,56 +73,179 @@ static inline void kasan_disable_current(void) {}
 
 #ifdef CONFIG_KASAN
 
-void kasan_alloc_pages(struct page *page, unsigned int order);
-void kasan_free_pages(struct page *page, unsigned int order);
+struct kasan_cache {
+	int alloc_meta_offset;
+	int free_meta_offset;
+};
 
-void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
-			slab_flags_t *flags);
+#ifdef CONFIG_KASAN_HW_TAGS
+DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
+static inline kasan_enabled(void)
+{
+	return static_branch_likely(&kasan_flag_enabled);
+}
+#else
+static inline kasan_enabled(void)
+{
+	return true;
+}
+#endif
 
-void kasan_unpoison_data(const void *address, size_t size);
-void kasan_unpoison_slab(const void *ptr);
+void __kasan_alloc_pages(struct page *page, unsigned int order);
+static inline void kasan_alloc_pages(struct page *page, unsigned int order)
+{
+	if (kasan_enabled())
+		__kasan_alloc_pages(page, order);
+}
 
-void kasan_poison_slab(struct page *page);
-void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
-void kasan_poison_object_data(struct kmem_cache *cache, void *object);
-void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
-					const void *object);
+void __kasan_free_pages(struct page *page, unsigned int order);
+static inline void kasan_free_pages(struct page *page, unsigned int order)
+{
+	if (kasan_enabled())
+		__kasan_free_pages(page, order);
+}
 
-void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
-						gfp_t flags);
-void kasan_kfree_large(void *ptr, unsigned long ip);
-void kasan_poison_kfree(void *ptr, unsigned long ip);
-void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
-					size_t size, gfp_t flags);
-void * __must_check kasan_krealloc(const void *object, size_t new_size,
-					gfp_t flags);
+void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
+				slab_flags_t *flags);
+static inline void kasan_cache_create(struct kmem_cache *cache,
+			unsigned int *size, slab_flags_t *flags)
+{
+	if (kasan_enabled())
+		__kasan_cache_create(cache, size, flags);
+}
 
-void * __must_check kasan_slab_alloc(struct kmem_cache *s, void *object,
-					gfp_t flags);
-bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
+size_t __kasan_metadata_size(struct kmem_cache *cache);
+static inline size_t kasan_metadata_size(struct kmem_cache *cache)
+{
+	if (kasan_enabled())
+		return __kasan_metadata_size(cache);
+	return 0;
+}
 
-struct kasan_cache {
-	int alloc_meta_offset;
-	int free_meta_offset;
-};
+void __kasan_unpoison_data(const void *addr, size_t size);
+static inline void kasan_unpoison_data(const void *addr, size_t size)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_data(addr, size);
+}
+
+void __kasan_unpoison_slab(const void *ptr);
+static inline void kasan_unpoison_slab(const void *ptr)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_slab(ptr);
+}
+
+void __kasan_poison_slab(struct page *page);
+static inline void kasan_poison_slab(struct page *page)
+{
+	if (kasan_enabled())
+		return __kasan_poison_slab(page);
+}
+
+void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
+static inline void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
+{
+	if (kasan_enabled())
+		return __kasan_unpoison_object_data(cache, object);
+}
+
+void __kasan_poison_object_data(struct kmem_cache *cache, void *object);
+static inline void kasan_poison_object_data(struct kmem_cache *cache, void *object)
+{
+	if (kasan_enabled())
+		__kasan_poison_object_data(cache, object);
+}
+
+void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
+					  const void *object);
+static inline void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
+						      const void *object)
+{
+	if (kasan_enabled())
+		return __kasan_init_slab_obj(cache, object);
+	return (void *)object;
+}
+
+bool __kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
+static inline bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip)
+{
+	if (kasan_enabled())
+		return __kasan_slab_free(s, object, ip);
+	return false;
+}
+
+void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
+				       void *object, gfp_t flags);
+static inline void * __must_check kasan_slab_alloc(struct kmem_cache *s,
+						   void *object, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_slab_alloc(s, object, flags);
+	return object;
+}
 
-size_t kasan_metadata_size(struct kmem_cache *cache);
+void * __must_check __kasan_kmalloc(struct kmem_cache *s, const void *object,
+				    size_t size, gfp_t flags);
+static inline void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
+						size_t size, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_kmalloc(s, object, size, flags);
+	return (void *)object;
+}
+
+void * __must_check __kasan_kmalloc_large(const void *ptr,
+					  size_t size, gfp_t flags);
+static inline void * __must_check kasan_kmalloc_large(const void *ptr,
+						      size_t size, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_kmalloc_large(ptr, size, flags);
+	return (void *)ptr;
+}
+
+void * __must_check __kasan_krealloc(const void *object,
+				     size_t new_size, gfp_t flags);
+static inline void * __must_check kasan_krealloc(const void *object,
+						 size_t new_size, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_krealloc(object, new_size, flags);
+	return (void *)object;
+}
+
+void __kasan_poison_kfree(void *ptr, unsigned long ip);
+static inline void kasan_poison_kfree(void *ptr, unsigned long ip)
+{
+	if (kasan_enabled())
+		__kasan_poison_kfree(ptr, ip);
+}
+
+void __kasan_kfree_large(void *ptr, unsigned long ip);
+static inline void kasan_kfree_large(void *ptr, unsigned long ip)
+{
+	if (kasan_enabled())
+		__kasan_kfree_large(ptr, ip);
+}
 
 bool kasan_save_enable_multi_shot(void);
 void kasan_restore_multi_shot(bool enabled);
 
 #else /* CONFIG_KASAN */
 
+static inline kasan_enabled(void)
+{
+	return false;
+}
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
-
 static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
 				      slab_flags_t *flags) {}
-
-static inline void kasan_unpoison_data(const void *address, size_t size) { }
-static inline void kasan_unpoison_slab(const void *ptr) { }
-
+static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
+static inline void kasan_unpoison_data(const void *address, size_t size) {}
+static inline void kasan_unpoison_slab(const void *ptr) {}
 static inline void kasan_poison_slab(struct page *page) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
 					void *object) {}
@@ -132,36 +256,32 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
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
index 0793d03a4183..8d84a6b2fa3c 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -31,6 +31,7 @@
 #include <linux/sizes.h>
 #include <linux/sched.h>
 #include <linux/pgtable.h>
+#include <linux/kasan.h>
 
 struct mempolicy;
 struct anon_vma;
@@ -1414,22 +1415,30 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
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
@@ -1437,7 +1446,8 @@ static inline u8 page_kasan_tag(const struct page *page)
 
 static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
 static inline void page_kasan_tag_reset(struct page *page) { }
-#endif
+
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline struct zone *page_zone(const struct page *page)
 {
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index efad5ed6a3bd..385863eaec2c 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -81,7 +81,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 }
 #endif /* CONFIG_KASAN_STACK */
 
-void kasan_alloc_pages(struct page *page, unsigned int order)
+void __kasan_alloc_pages(struct page *page, unsigned int order)
 {
 	u8 tag;
 	unsigned long i;
@@ -95,7 +95,7 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
 	kasan_unpoison_memory(page_address(page), PAGE_SIZE << order);
 }
 
-void kasan_free_pages(struct page *page, unsigned int order)
+void __kasan_free_pages(struct page *page, unsigned int order)
 {
 	if (likely(!PageHighMem(page)))
 		kasan_poison_memory(page_address(page),
@@ -122,8 +122,8 @@ static inline unsigned int optimal_redzone(unsigned int object_size)
 		object_size <= (1 << 16) - 1024 ? 1024 : 2048;
 }
 
-void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
-			slab_flags_t *flags)
+void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
+			  slab_flags_t *flags)
 {
 	unsigned int orig_size = *size;
 	unsigned int redzone_size;
@@ -168,7 +168,7 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	*flags |= SLAB_KASAN;
 }
 
-size_t kasan_metadata_size(struct kmem_cache *cache)
+size_t __kasan_metadata_size(struct kmem_cache *cache)
 {
 	if (!kasan_stack_collection_enabled())
 		return 0;
@@ -191,17 +191,17 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 	return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
 }
 
-void kasan_unpoison_data(const void *address, size_t size)
+void __kasan_unpoison_data(const void *addr, size_t size)
 {
-	kasan_unpoison_memory(address, size);
+	kasan_unpoison_memory(addr, size);
 }
 
-void kasan_unpoison_slab(const void *ptr)
+void __kasan_unpoison_slab(const void *ptr)
 {
 	kasan_unpoison_memory(ptr, __ksize(ptr));
 }
 
-void kasan_poison_slab(struct page *page)
+void __kasan_poison_slab(struct page *page)
 {
 	unsigned long i;
 
@@ -211,12 +211,12 @@ void kasan_poison_slab(struct page *page)
 			KASAN_KMALLOC_REDZONE);
 }
 
-void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
+void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 {
 	kasan_unpoison_memory(object, cache->object_size);
 }
 
-void kasan_poison_object_data(struct kmem_cache *cache, void *object)
+void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
 	kasan_poison_memory(object,
 			round_up(cache->object_size, KASAN_GRANULE_SIZE),
@@ -269,7 +269,7 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
 #endif
 }
 
-void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
+void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 						const void *object)
 {
 	struct kasan_alloc_meta *alloc_meta;
@@ -288,7 +288,7 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
+static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 			      unsigned long ip, bool quarantine)
 {
 	u8 tag;
@@ -331,9 +331,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	return IS_ENABLED(CONFIG_KASAN_GENERIC);
 }
 
-bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
+bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 {
-	return __kasan_slab_free(cache, object, ip, true);
+	return ____kasan_slab_free(cache, object, ip, true);
 }
 
 static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
@@ -341,7 +341,7 @@ static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
 }
 
-static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
+static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				size_t size, gfp_t flags, bool keep_tag)
 {
 	unsigned long redzone_start;
@@ -373,20 +373,20 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
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
@@ -411,7 +411,7 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
 	return (void *)ptr;
 }
 
-void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
+void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
 {
 	struct page *page;
 
@@ -421,13 +421,13 @@ void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
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
 
@@ -440,11 +440,11 @@ void kasan_poison_kfree(void *ptr, unsigned long ip)
 		}
 		kasan_poison_memory(ptr, page_size(page), KASAN_FREE_PAGE);
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f44efbb38afe1a1bc2bba2b4b6698e16cb216bbd.1604534322.git.andreyknvl%40google.com.

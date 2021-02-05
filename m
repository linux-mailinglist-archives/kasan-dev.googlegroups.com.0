Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPMD62AAMGQEPM3BCPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C82E310EBE
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:34:55 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id s4sf2547888oia.5
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:34:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546494; cv=pass;
        d=google.com; s=arc-20160816;
        b=nomTtBAvQZtX2okN3vKOnQFEfXsA/8OL5SjSzoKhPWAalbXWU6Lq8rdRK+e/sokNsI
         7WNuPysa05m20HvBUSwsLtff2bChX5EjTvrGMDaqJvFbE4BZWtoObDFdR0qgpu0jsshG
         s8nnSOh3foJ631SXA8oUecqWtDDxl0aKuJ3v798Y5N3cjZ75e8TGvKPdytQDtgUpzJ7h
         oule0JyjgmsZAU+uV0ptDPx9LFUA+ORE4Rr4B1FeSsqnGWd2fBYY1gmW2V9ZrP62ednk
         zcsD3XhnzHtRdfFPAJhXANw1Wub7cQhGU/wNZ1xsAm08dNJI6yveA9hZ8vWRsi82uE5d
         cHcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=EEOv8JN+r5EsO0WdjEMz630lqjO7UiFekwE+27kIFz0=;
        b=mvIPy5vsYbS6HlmrveRmPdcH2w4h67YZjgCMDNVxpLa+7OaeA2aUSbTz6m3KXATTQr
         8sbaq8Gni1Nz5mpcAhydIVnRRFJiHJB+0l1wOT448ywZShDyQe9J2B/VtQgyKXPwpcmm
         bbvstnBMRZ+OKVIU6Ln5q6EPcQ9TM71IuukmL7XVyCGskeJtT3KmQwH1a3sQ6aArT7Ks
         jfGHpLMWFvOs+uut4uwXt9Ie+d5SP0lc84MhgERY0sKKAaQBIu6apUNTaLVgfaVNa/d7
         oFJcqMZeP26pcax9XZ+EKOdqXf8F9d4YG2aXpFazo0O25tKUhQgZCWSy9xaDpTqUf2ry
         MlKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g23QkriS;
       spf=pass (google.com: domain of 3viedyaokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3vIEdYAoKCT0Zmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EEOv8JN+r5EsO0WdjEMz630lqjO7UiFekwE+27kIFz0=;
        b=RbcM5znX467oxkOD1QfFCrfaWKDaX3MIjCm9g0FFgDybe6vA2d2dCjQWX+voQexwqf
         MRRD4aLFahulGEjQSOEmMw0f6iUzwATCJnq3k/WUwpcdu9Il+Aq+VMaWeGZ2CvsuTcSF
         pDx3AVJD1ltvcOnMWJeLCo9kdb6IHvkZrDuAMHnE35KB86UIaTkXOTHENPgvFKB3oAW9
         2JdN9S3J+Z2OToQvvwY60Y4nHTbh+T0OxLQN9G4TIp4ynJk8OJZDFmP2M3R7i/h3E8QB
         1hl9Rbul7tI8VWAdvZ/QS2pK4T9Z+snax2/4q4V+v+nx2He2/vYGkGWeWRWBZDu1BDz7
         SfyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EEOv8JN+r5EsO0WdjEMz630lqjO7UiFekwE+27kIFz0=;
        b=Tm6XC7GjxXDJlIw3lFe8Dn4llgRBqKgzuC9yjH3TOYX5u5Mn9Z1UNCohhp7WlfJ3so
         L9lQW4IQjHzDyFM9i+vP8I78LuMx41P2iT4nA9HK/yPWcNruqIi872bfZILrZhIBGwo8
         l1quV756/kCUfopOW8c6Vo363cvUvbaSqPZgKCp+t4El8/NcKNY4mUnTxBPYpte5hVky
         oRBE/8SsY1YS1jgRrD0HQd5rUv00+CFNKKG6MgVQlv0uhjB0knfIqmBj//q4g8WxUn0j
         OzLzyecUSzy7bmaW2jtceqsHPolv971b2hu+BPPMLWEsuqjS0zdkviSMHnWxewZez3DF
         yGkw==
X-Gm-Message-State: AOAM5312Hxzp2/ABNrmEhoU4zOzxZPXfbgP6ICWztJBiHka0wCIRhoOV
	REYgi+tvDXEdiMcAz95lMZE=
X-Google-Smtp-Source: ABdhPJyxO8IfoHL22pKsWDQFxkC3K8g/yNHgC77m+GqBi6UTiI2odUA/fAVscstXU38sCoZ/cCF0Bw==
X-Received: by 2002:a9d:5d02:: with SMTP id b2mr4147008oti.148.1612546493974;
        Fri, 05 Feb 2021 09:34:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:14a:: with SMTP id j10ls2435130otp.4.gmail; Fri, 05
 Feb 2021 09:34:53 -0800 (PST)
X-Received: by 2002:a9d:674f:: with SMTP id w15mr4088083otm.88.1612546493591;
        Fri, 05 Feb 2021 09:34:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546493; cv=none;
        d=google.com; s=arc-20160816;
        b=nFnrBHwDTJCCn5/StzVTFwTU2wsk/pC6fT3mZ6kPZgv3Sm3cLsMNlWP9XXIkbEKEyd
         NdOBum82L1bzCO681+IoRRCkCY42iqAbOG1HarNV1hm25f3x4aT70WTwFzgnRHAdbXSp
         VPNIo9IZtrg5/FJR2d8xGSba80+VoFDfYgjmS4esMixAM7z+jacyOH080rMw1dwh7vbu
         H+XMdxx+T0WKIyIBPepaz3c+F6PkTe1J1qztEKaHCxhvdC89UI8kOS+yvsiyEQMnL4eB
         kgz/RBJGr+tH1WyznQHXvgKDJWPM45NnLLe7O8vYqq2at9c/4SkDISfQ+/YbBowvJsUq
         13wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=lqblrx40cOeXNR+PvBIbJ4346eed6vA2slz2Dc36rws=;
        b=Zv15NhblpTt4DUt48Mgp3HQEcP2aSTeDre4cnScHQqPs7kKKrQvUAyXV13M/IgTXJ+
         m7JRdKhs8/Lgh75VfUHVEwuQfWgXyadirqKSZtEPCP7wVtMe32cHSCZ86A27QVFLD90n
         zh4oBeZHiNxqskn0LgozwKHgPP4jobnAC53tELjAKwk6eUDTG4UTdTS/zO+TzNpT5Zky
         iRzSazyce//+QDKJ2Dm8nSNP82HR1OFnW2Btyi/VAd173dJOUcZx8Lhkn6I23TLfRPug
         8EsIirm5SQCGJt1/AP/KScTLYIZVuj0v2iFcmjWdVLqheq3GCfDXVKvQwRbjSXCHx53W
         c4EQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g23QkriS;
       spf=pass (google.com: domain of 3viedyaokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3vIEdYAoKCT0Zmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id r27si668131oth.2.2021.02.05.09.34.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:34:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3viedyaokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id z28so364907qva.15
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 09:34:53 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f143:: with SMTP id
 y3mr5496897qvl.62.1612546492642; Fri, 05 Feb 2021 09:34:52 -0800 (PST)
Date: Fri,  5 Feb 2021 18:34:35 +0100
In-Reply-To: <cover.1612546384.git.andreyknvl@google.com>
Message-Id: <7c673ebca8d00f40a7ad6f04ab9a2bddeeae2097.1612546384.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612546384.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v3 mm 01/13] kasan, mm: don't save alloc stacks twice
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g23QkriS;       spf=pass
 (google.com: domain of 3viedyaokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3vIEdYAoKCT0Zmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
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

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  9 +++++++++
 mm/kasan/common.c     | 18 ++++++++++++++----
 mm/slab_common.c      |  1 +
 3 files changed, 24 insertions(+), 4 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 1011e4f30284..e6ed969e74b3 100644
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
index fe852f3cfa42..bfdf5464f4ef 100644
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
+				gfp_t flags, bool is_kmalloc)
 {
 	struct kasan_alloc_meta *alloc_meta;
 
+	/* Don't save alloc info for kmalloc caches in kasan_slab_alloc(). */
+	if (cache->kasan_info.is_kmalloc && !is_kmalloc)
+		return;
+
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	if (alloc_meta)
 		kasan_set_track(&alloc_meta->alloc_track, flags);
 }
 
 static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
-				size_t size, gfp_t flags, bool keep_tag)
+				size_t size, gfp_t flags, bool is_kmalloc)
 {
 	unsigned long redzone_start;
 	unsigned long redzone_end;
@@ -423,7 +433,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				KASAN_GRANULE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
 				KASAN_GRANULE_SIZE);
-	tag = assign_tag(cache, object, false, keep_tag);
+	tag = assign_tag(cache, object, false, is_kmalloc);
 
 	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
 	kasan_unpoison(set_tag(object, tag), size);
@@ -431,7 +441,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 			   KASAN_KMALLOC_REDZONE);
 
 	if (kasan_stack_collection_enabled())
-		set_alloc_info(cache, (void *)object, flags);
+		set_alloc_info(cache, (void *)object, flags, is_kmalloc);
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7c673ebca8d00f40a7ad6f04ab9a2bddeeae2097.1612546384.git.andreyknvl%40google.com.

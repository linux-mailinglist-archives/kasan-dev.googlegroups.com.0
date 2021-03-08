Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4MRTGBAMGQE3K6BSPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 95C853312A2
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 16:55:30 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id s11sf1682530ois.12
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 07:55:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615218929; cv=pass;
        d=google.com; s=arc-20160816;
        b=XeMh7JgRLWTvpGLG0VA3zD+KEtg9BBM7gm8eGRLO3/n14R+0LhQat2MVUalMa5n/lC
         PDkJMgFfsFutoFtmDWVLP1SRkmdtAY+MwghBrj7JL2SuiwwmnqS7B1Unz4JLVlSFxTh8
         QLSAIlUUDONkL43utNAbGlCl0gUKMVfA9lNaHj49PpTUrhZGr2yGmAmkLtvJ1x3Wi2Wm
         VUoIgIwVhSj23etNBR5C+4Eq8d8LQ+JgFf4vbe69nCRBUCo2N5mDXwjQCpeJg1WtC74K
         AfkAnjNnpsq+BUYobbol5orrCtZYpjsJu+LrPxhvZw0lKrHv2Ja+ueHh9Zyf4uY7Oz6t
         Rsrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=0eR1yiITrd6KpjxlTeNXk9xioVW4EXuislQ787YRqE4=;
        b=yPw7qtaj1k+6Vc664FrwmiD15n6bFNsKskx+7rzXF4t6wRpKfaeszm5by9tvWpRjaa
         zmCbnubXmvZ8HqgBnsAxQGkAtWfRpal130/uujmwyXut7CSfk7a7NfAd3eBB83mBKsn6
         3qGwOquTXGF03IAXUT1i3g+oDlB+sJNha5/LfKsMR6FBQRcCrPRc9s3bctoQ5IUZuHpM
         8W78Ms0qVOqJ4dBHvQSUXlsUSpMFpOolZ1EeWFCWW4tXCv03oVuFksRW/DZdU21o+Mdk
         9nn5k4xRB87huJGewKBc6vmXHZaJLeapGarp6h/4FOCUJ/Q+Jc0EVajLl31qQ2Pia4eW
         8rJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YvuLJTYi;
       spf=pass (google.com: domain of 38ehgyaokcamdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=38EhGYAoKCaMDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0eR1yiITrd6KpjxlTeNXk9xioVW4EXuislQ787YRqE4=;
        b=lBqQtPZbQL5nZzWGTOsQctjQXPXsQUD/vIXlstI6TIw4QLR9Lusmj9DGPUzHunaqrA
         HnHYrPb/HqwgD5lOD1lAxsgPjD80/A6TLsGlUmTW5syzv+lUZijApCuPB2VT6yYH/LCW
         I6M1eC71X6mpqJNDYWu6L645VHm79k2Qwk6Xdl58g3qgYc90Jfdw6oyb14doB6rOw4nW
         gm+nqpdpP9bk0nrnDrSVZFjA/cP+RBricIpSpY8aYCqvfau1Bim8Z7UCe5jmclaQGhGp
         UAYrsLlo7al38lMaTevx0DK+gDzQaOCTn3Z7hKYzBY0ErcuMuVwTj5N1VYBk4Dt5+Iyo
         I/Dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0eR1yiITrd6KpjxlTeNXk9xioVW4EXuislQ787YRqE4=;
        b=ehZi5SagMbgc0Un5O/J+nwq4QZnP5+af3pakFir2/AYYJIYjyZQ9N2Js4Y8fHin7l7
         QVg6wqRRiP4tOMyH5J2LV6dnthQCA2fC5KmwKp1k84DxuEnGuxtBiqKsc6SkgBUw5MwM
         Gn33QFHkdnM9eqdSkWDMZXNqeEvYQzp32/FIZuVknO/dQYrP1/wH/GUp9UnMYcRhRJZF
         ua9Yp4ol2Shje0yOy2jFsHWtZgKN3Lop4T/i7hmAkcIkzrKNKK/FMziBmEs7HtPl6jnF
         uCtxQ9q3mzonuyzaIZsLFTk8SkzJChtzsBHJQMUshX3GaHYqliPZg+iDwtutrWWsJFRu
         IY3Q==
X-Gm-Message-State: AOAM530h3uptEbc5jSNoyi2ckWxUjE4cTEJALu7rEWOEta1jkBHumyjk
	YluAeSi8IgiIQA2ag+w4RoI=
X-Google-Smtp-Source: ABdhPJwxRkLrfm2vJaoZV5BnIS1MxWXE0rVned5Un4FJ69AUUEoosRBPdMHbHOhpRuc5bUPqY/y2FA==
X-Received: by 2002:aca:1818:: with SMTP id h24mr17221587oih.16.1615218929451;
        Mon, 08 Mar 2021 07:55:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:578a:: with SMTP id q10ls1062588oth.7.gmail; Mon, 08 Mar
 2021 07:55:29 -0800 (PST)
X-Received: by 2002:a9d:42c:: with SMTP id 41mr19437846otc.108.1615218929149;
        Mon, 08 Mar 2021 07:55:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615218929; cv=none;
        d=google.com; s=arc-20160816;
        b=EVETaGPnWjPusj8qSUoZ2ffuKbrEexG0PSXXhVDn+hiidTHaQ7KKoo8i1Pw4yg7B0Q
         5ufFw8vc5nUsPznHLpraHLD8lX8yLL/EOH5Xv9MDF7LraXPJed9/DBwilfYIAt7UFbfx
         p8f1DO3zEj4IMvsKwiW8fOjuMTdDRrgSp+3JcliXum4VfGpyVFRzRHvJLmq7jvSVm8J5
         M2IKqIcr5CvsLDawmkP6uFPy24ZUUxq7vYlplufaB5uHSRaKXk4SplkwrMR/iJjC1k2d
         SBxh9bdnEbDGaPKgYVBqSeEHm7iyw+rrXXtyZFfLanY3QnE3F+xhh0fQFV/jCRNi7EX/
         OOow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=zCBHdpjDvAH5HFKLaFFW9ex0bLksKjp4z0Uq53dM3gc=;
        b=x9i2dYMz7JZKqxfngK1KsIf583DVX7TjrzBkwe7/8wyABoa5AVu8KW/eZ7Z6xYVFWJ
         pYkc4rSQ0MnBKmXZ159rOD8WLg4vVVeOdFr+bh9rMO0Dj4QHx3rbrrQ/sRYoVLQkNHwY
         8Ip2NTaFAl4TIVcyAY0TlQm1PQxJRAvmsvDX4DkHh8IuUzpOykX6BFiSB85Z+1FwDXz/
         9QJI1VmkUpDwePNwDkZqOOUohjs7wdC9x0e4dffGtHDG9eZ8NHFhyq9o21UdHCw7zZaS
         Q62CzPr9Uc9iJyae4654L3IaveOIINupl67W6oOw+0g7/JuGz91RT69hE3cNFYpwZupz
         /ZMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YvuLJTYi;
       spf=pass (google.com: domain of 38ehgyaokcamdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=38EhGYAoKCaMDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id x143si852201oif.2.2021.03.08.07.55.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 07:55:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 38ehgyaokcamdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id u5so7573267qkj.10
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 07:55:29 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:85fb:aac9:69ed:e574])
 (user=andreyknvl job=sendgmr) by 2002:a0c:e788:: with SMTP id
 x8mr21917279qvn.48.1615218928607; Mon, 08 Mar 2021 07:55:28 -0800 (PST)
Date: Mon,  8 Mar 2021 16:55:16 +0100
In-Reply-To: <cover.1615218180.git.andreyknvl@google.com>
Message-Id: <731edf3341d50e863a658689c184eb16abda70e6.1615218180.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1615218180.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH v2 3/5] kasan, mm: integrate page_alloc init with HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YvuLJTYi;       spf=pass
 (google.com: domain of 38ehgyaokcamdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=38EhGYAoKCaMDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
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
of HW_TAGS KASAN routines for page_alloc memory when init_on_alloc/free
is enabled.

With this change, kernel_init_free_pages() is no longer called when
both HW_TAGS KASAN and init_on_alloc/free are enabled. Instead, memory
is initialized in KASAN runtime.

To avoid discrepancies with which memory gets initialized that can be
caused by future changes, both KASAN and kernel_init_free_pages() hooks
are put together and a warning comment is added.

This patch changes the order in which memory initialization and page
poisoning hooks are called. This doesn't lead to any side-effects, as
whenever page poisoning is enabled, memory initialization gets disabled.

Combining setting allocation tags with memory initialization improves
HW_TAGS KASAN performance when init_on_alloc/free is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 30 ++++++++++++++++++++++--------
 mm/kasan/common.c     |  8 ++++----
 mm/mempool.c          |  4 ++--
 mm/page_alloc.c       | 37 ++++++++++++++++++++++++++-----------
 4 files changed, 54 insertions(+), 25 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 1d89b8175027..c89613caa8cf 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -96,6 +96,11 @@ static __always_inline bool kasan_enabled(void)
 	return static_branch_likely(&kasan_flag_enabled);
 }
 
+static inline bool kasan_has_integrated_init(void)
+{
+	return kasan_enabled();
+}
+
 #else /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_enabled(void)
@@ -103,6 +108,11 @@ static inline bool kasan_enabled(void)
 	return true;
 }
 
+static inline bool kasan_has_integrated_init(void)
+{
+	return false;
+}
+
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 slab_flags_t __kasan_never_merge(void);
@@ -120,20 +130,20 @@ static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
 		__kasan_unpoison_range(addr, size);
 }
 
-void __kasan_alloc_pages(struct page *page, unsigned int order);
+void __kasan_alloc_pages(struct page *page, unsigned int order, bool init);
 static __always_inline void kasan_alloc_pages(struct page *page,
-						unsigned int order)
+						unsigned int order, bool init)
 {
 	if (kasan_enabled())
-		__kasan_alloc_pages(page, order);
+		__kasan_alloc_pages(page, order, init);
 }
 
-void __kasan_free_pages(struct page *page, unsigned int order);
+void __kasan_free_pages(struct page *page, unsigned int order, bool init);
 static __always_inline void kasan_free_pages(struct page *page,
-						unsigned int order)
+						unsigned int order, bool init)
 {
 	if (kasan_enabled())
-		__kasan_free_pages(page, order);
+		__kasan_free_pages(page, order, init);
 }
 
 void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
@@ -277,13 +287,17 @@ static inline bool kasan_enabled(void)
 {
 	return false;
 }
+static inline bool kasan_has_integrated_init(void)
+{
+	return false;
+}
 static inline slab_flags_t kasan_never_merge(void)
 {
 	return 0;
 }
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
-static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
-static inline void kasan_free_pages(struct page *page, unsigned int order) {}
+static inline void kasan_alloc_pages(struct page *page, unsigned int order, bool init) {}
+static inline void kasan_free_pages(struct page *page, unsigned int order, bool init) {}
 static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
 				      slab_flags_t *flags) {}
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 316f7f8cd8e6..6107c795611f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -97,7 +97,7 @@ slab_flags_t __kasan_never_merge(void)
 	return 0;
 }
 
-void __kasan_alloc_pages(struct page *page, unsigned int order)
+void __kasan_alloc_pages(struct page *page, unsigned int order, bool init)
 {
 	u8 tag;
 	unsigned long i;
@@ -108,14 +108,14 @@ void __kasan_alloc_pages(struct page *page, unsigned int order)
 	tag = kasan_random_tag();
 	for (i = 0; i < (1 << order); i++)
 		page_kasan_tag_set(page + i, tag);
-	kasan_unpoison(page_address(page), PAGE_SIZE << order, false);
+	kasan_unpoison(page_address(page), PAGE_SIZE << order, init);
 }
 
-void __kasan_free_pages(struct page *page, unsigned int order)
+void __kasan_free_pages(struct page *page, unsigned int order, bool init)
 {
 	if (likely(!PageHighMem(page)))
 		kasan_poison(page_address(page), PAGE_SIZE << order,
-			     KASAN_FREE_PAGE, false);
+			     KASAN_FREE_PAGE, init);
 }
 
 /*
diff --git a/mm/mempool.c b/mm/mempool.c
index 79959fac27d7..fe19d290a301 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -106,7 +106,7 @@ static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
 		kasan_slab_free_mempool(element);
 	else if (pool->alloc == mempool_alloc_pages)
-		kasan_free_pages(element, (unsigned long)pool->pool_data);
+		kasan_free_pages(element, (unsigned long)pool->pool_data, false);
 }
 
 static void kasan_unpoison_element(mempool_t *pool, void *element)
@@ -114,7 +114,7 @@ static void kasan_unpoison_element(mempool_t *pool, void *element)
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
 		kasan_unpoison_range(element, __ksize(element));
 	else if (pool->alloc == mempool_alloc_pages)
-		kasan_alloc_pages(element, (unsigned long)pool->pool_data);
+		kasan_alloc_pages(element, (unsigned long)pool->pool_data, false);
 }
 
 static __always_inline void add_element(mempool_t *pool, void *element)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 0efb07b5907c..aba9cd673eac 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -396,14 +396,14 @@ static DEFINE_STATIC_KEY_TRUE(deferred_pages);
  * initialization is done, but this is not likely to happen.
  */
 static inline void kasan_free_nondeferred_pages(struct page *page, int order,
-							fpi_t fpi_flags)
+						bool init, fpi_t fpi_flags)
 {
 	if (static_branch_unlikely(&deferred_pages))
 		return;
 	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
 			(fpi_flags & FPI_SKIP_KASAN_POISON))
 		return;
-	kasan_free_pages(page, order);
+	kasan_free_pages(page, order, init);
 }
 
 /* Returns true if the struct page for the pfn is uninitialised */
@@ -455,12 +455,12 @@ defer_init(int nid, unsigned long pfn, unsigned long end_pfn)
 }
 #else
 static inline void kasan_free_nondeferred_pages(struct page *page, int order,
-							fpi_t fpi_flags)
+						bool init, fpi_t fpi_flags)
 {
 	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
 			(fpi_flags & FPI_SKIP_KASAN_POISON))
 		return;
-	kasan_free_pages(page, order);
+	kasan_free_pages(page, order, init);
 }
 
 static inline bool early_page_uninitialised(unsigned long pfn)
@@ -1242,6 +1242,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 			unsigned int order, bool check_free, fpi_t fpi_flags)
 {
 	int bad = 0;
+	bool init;
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
 
@@ -1299,16 +1300,21 @@ static __always_inline bool free_pages_prepare(struct page *page,
 		debug_check_no_obj_freed(page_address(page),
 					   PAGE_SIZE << order);
 	}
-	if (want_init_on_free())
-		kernel_init_free_pages(page, 1 << order);
 
 	kernel_poison_pages(page, 1 << order);
 
 	/*
+	 * As memory initialization might be integrated into KASAN,
+	 * kasan_free_pages and kernel_init_free_pages must be
+	 * kept together to avoid discrepancies in behavior.
+	 *
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	kasan_free_nondeferred_pages(page, order, fpi_flags);
+	init = want_init_on_free();
+	if (init && !kasan_has_integrated_init())
+		kernel_init_free_pages(page, 1 << order);
+	kasan_free_nondeferred_pages(page, order, init, fpi_flags);
 
 	/*
 	 * arch_free_page() can make the page's contents inaccessible.  s390
@@ -2315,17 +2321,26 @@ static bool check_new_pages(struct page *page, unsigned int order)
 inline void post_alloc_hook(struct page *page, unsigned int order,
 				gfp_t gfp_flags)
 {
+	bool init;
+
 	set_page_private(page, 0);
 	set_page_refcounted(page);
 
 	arch_alloc_page(page, order);
 	debug_pagealloc_map_pages(page, 1 << order);
-	kasan_alloc_pages(page, order);
-	kernel_unpoison_pages(page, 1 << order);
-	set_page_owner(page, order, gfp_flags);
 
-	if (!want_init_on_free() && want_init_on_alloc(gfp_flags))
+	/*
+	 * As memory initialization might be integrated into KASAN,
+	 * kasan_alloc_pages and kernel_init_free_pages must be
+	 * kept together to avoid discrepancies in behavior.
+	 */
+	init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
+	kasan_alloc_pages(page, order, init);
+	if (init && !kasan_has_integrated_init())
 		kernel_init_free_pages(page, 1 << order);
+
+	kernel_unpoison_pages(page, 1 << order);
+	set_page_owner(page, order, gfp_flags);
 }
 
 static void prep_new_page(struct page *page, unsigned int order, gfp_t gfp_flags,
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/731edf3341d50e863a658689c184eb16abda70e6.1615218180.git.andreyknvl%40google.com.

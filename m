Return-Path: <kasan-dev+bncBAABB4H2QOHAMGQE6JDIUMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id BABCC47B5A5
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:02:24 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 28-20020ac24d5c000000b00425c507cfc0sf2350522lfp.20
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:02:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037744; cv=pass;
        d=google.com; s=arc-20160816;
        b=oFBTMOglNfNz3VTxLVFFR+CPCnIShHsuCEe7ZFczEvzKUFsbKndzPMpTK7SiHUTfIF
         L9QRrH/LU0ZO4eJsVyZuM2qSw3i62TXvOumUITEKe4G4W8F+1Hded274G6SA5F1GA5TE
         9iDuYjTVxkXKJ1VLKItWVuZFgZ3MOAm85hAcRZ9OPwLYsD8NYTDBJoFDmHSUZkLBE00e
         Rbs54LkTbv42dW9iRl/xNHgErJw/AY/B0kHeLEd6ms4VeEzAma0KGeTjARcMFirSq2Kl
         85Dju6c96w+LmrW/yZlSZLEF2DlxmmT6FUP6+meTBUqxeNRHEkLYZBydHIvTcJyrkQ4b
         U2RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JiD/lBmd2+osKhOirHfNLTSWNg+WMu/iiQnMpydgenA=;
        b=gqg11yxqfGPCRZEKUXb5tLdA9pD/bmlHrxnWT2tqwc1YGIPhoZhLDbLJm7yoqkQV07
         gYDFS1r9p3JGt/dRLYF4v+ivGO6Ur4DZFXzBIDAhLvumo5BJxwOhreVj29UO2uwF2c+8
         ElkqgaYXTgUSeoCtVJAc4J7rRb1YFJYdCaAdkBq2Oxk3yLrea977LnHuH4SRBnuzcL8d
         8BZji5T8xnnmBpBu95nZ7ygyW2mJ+pTfartDsL6oAGN3gepQQY1jfYAhdg2B5j3M2fvR
         LWCetwKWZcnHXsH6IVyw7bB2jJIQ78OSZ5PKsAZcOvDgbPfUJ1PDDxlOQwx8Po7g6uq5
         6/Vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JTq4w68K;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JiD/lBmd2+osKhOirHfNLTSWNg+WMu/iiQnMpydgenA=;
        b=oKebY7X+cwcXsHy4rJ4OoR6+g+vZ2/tikuFCFSHsB2r6EycJWZESbNaJJRkRBq81LQ
         xsokd1nZGLC0YAz9Iyc3zIc9Oj79HBFU0Xa6vL/eob5RHda71yeNNq2fTgFhNe9GrS4D
         yaKmqrw5KirXdhoz5kOEb19fvqM1IPei69jWvPtTz2qb5DCqb2NNrVLGiSxNMmNz1x2z
         E4Kd5/uAhgqPx6mkdwz/UUUYLlU8iSwknzILyWPL9Sx1eMkLEG7rYGvNmpR6vOB4+ToJ
         i8dghKjHEg2/F4TBxqS2ZoGGER710wT678L23pETuuEQQE+m+IlNF7f+jBqQapusGEkI
         xbqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JiD/lBmd2+osKhOirHfNLTSWNg+WMu/iiQnMpydgenA=;
        b=oCntGdqOZaRshugKAbceok6PINsGFwvmURxrKRRQl3Xoi//LabETPSG0asE0ekQGfa
         X7gcH95o6fDiBM1WB7MEK3BQ8etsGpPIqS0VNKY6jjuK3tFaVCN/mAxdXhXod19cQ96z
         2LbVPxvvtb9bybUxFlQbycVLv633HvB7PPfa18qZ5H+hL1HgqQbRk81f68Ko99IzhUnM
         OyEkWvdjlWx6/u5seZjTslOIrCJkZmjVKFfug3rP/cishsaCz6YEutXacn86+Jv9ZbXq
         jffzcJonl0aKVbU6XRQnEk7nQliyQsxz6Eew5OB5g6wVekZsXhQDhHE0SuFdzXTknRCo
         kwfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531d6nkk49+pnn6lXhxEf7Efm2Gsz+pd/TyyPI0zCYhc4CPfmRCN
	ubGqRPJMci8y5qEaq0ftw4g=
X-Google-Smtp-Source: ABdhPJwjVZXgcyibEGa/wlXICKRQxoA8uENd6iHt9rSNsZYVDbMmGJt+luZvI4AlNyO8Zv6QQgYZlQ==
X-Received: by 2002:ac2:5cb0:: with SMTP id e16mr171393lfq.180.1640037744352;
        Mon, 20 Dec 2021 14:02:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3389:: with SMTP id h9ls801404lfg.2.gmail; Mon, 20
 Dec 2021 14:02:23 -0800 (PST)
X-Received: by 2002:a05:6512:1024:: with SMTP id r4mr145309lfr.143.1640037743633;
        Mon, 20 Dec 2021 14:02:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037743; cv=none;
        d=google.com; s=arc-20160816;
        b=eC+rs404S1diMrxDL0BaHvA+LMaekXLTkOJRg91mJ9L+EhdXAsvqxtTuWNPJfoNNex
         WaSI33q1BAdxt0zAfN0MEjfVJi9hFI3koilQlM3tO4wV+C2x5cec1zLfIrG4ZuinupF8
         EZwUiSi1K3PrsmPwlV7h3twaFOPEz7XVLvlGJxMWItX0VhouBD14n+StTh7bsUW68r2L
         glnpyGlLQlK187FbgY/Ph0KBfq7z/Byeq0XqdL/P0rReB0TcMZTCovqczSItHX6QdGhu
         sJgBElv9AUmhMAy7m5dixYRQPSmo9fUOc9Y4ApdmM0qqJJpW5egw95J+R2bn7bybFpO5
         6p5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8Jvymxid2u56CueOBZOhNZWKtFNf8TY1yGqNucgB3Ks=;
        b=p4tBcyhV4PbqQD+NChdnUyrMy40JOZypGXZdWiRKU6DNDgmi1k9f1XWQQc9iCYoA27
         y2qBe8k2BPjgdSRJkegGF4V8laPTHl6NQxa77OUQj6SHV6JNp2ZrmtyuMkFW7Bt675fK
         PcBLSvOpfgnoUCkarIgWTd+Ro5LPJ9SE1b98WmwvajDzS8hne9dIfbMQ7HK3ndJPlJGh
         P+6YmEE2PxKCsiY1GGKBTT1W7SyVhihtsKNF0+kOKV3wiZZsr8jPHKXVLfAMzxiyLOyr
         kV7kod+1K1Iv94/3QfIAqlyatnySMXBmk4t7LYeDHXEWAE/itiUrBU2XVo6+Vs5a52QR
         kmJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JTq4w68K;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id z24si689087lfu.0.2021.12.20.14.02.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:02:23 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v4 30/39] kasan, vmalloc: add vmalloc tagging for HW_TAGS
Date: Mon, 20 Dec 2021 23:02:02 +0100
Message-Id: <97ccf915f6d8df414c9471931ad92780a1f47576.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=JTq4w68K;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Add vmalloc tagging support to HW_TAGS KASAN.

The key difference between HW_TAGS and the other two KASAN modes
when it comes to vmalloc: HW_TAGS KASAN can only assign tags to
physical memory. The other two modes have shadow memory covering
every mapped virtual memory region.

Make __kasan_unpoison_vmalloc() for HW_TAGS KASAN:

- Skip non-VM_ALLOC mappings as HW_TAGS KASAN can only tag a single
  mapping of normal physical memory; see the comment in the function.
- Generate a random tag, tag the returned pointer and the allocation,
  and initialize the allocation at the same time.
- Propagate the tag into the page stucts to allow accesses through
  page_address(vmalloc_to_page()).

The rest of vmalloc-related KASAN hooks are not needed:

- The shadow-related ones are fully skipped.
- __kasan_poison_vmalloc() is kept as a no-op with a comment.

Poisoning and zeroing of physical pages that are backing vmalloc()
allocations are skipped via __GFP_SKIP_KASAN_UNPOISON and
__GFP_SKIP_ZERO: __kasan_unpoison_vmalloc() does that instead.

Enabling CONFIG_KASAN_VMALLOC with HW_TAGS is not yet allowed.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

---

Changes v3->v4:
- Fix comment style in __kasan_unpoison_vmalloc().
- Set __GFP_SKIP_KASAN_UNPOISON and __GFP_SKIP_ZERO flags instead of
  resetting.
- Move setting KASAN GFP flags to __vmalloc_node_range() and do it
  only for normal non-executable mapping when HW_TAGS KASAN is enabled.

Changes v2->v3:
- Switch kasan_unpoison_vmalloc() to using a single flags argument.
- Update kasan_unpoison_vmalloc() arguments in kernel/scs.c.
- Move allowing enabling KASAN_VMALLOC with SW_TAGS into a separate
  patch.
- Minor comments fixes.
- Update patch description.

Changes v1->v2:
- Allow enabling CONFIG_KASAN_VMALLOC with HW_TAGS in this patch.
- Move memory init for page_alloc pages backing vmalloc() into
  kasan_unpoison_vmalloc().
---
 include/linux/kasan.h | 36 +++++++++++++++--
 kernel/scs.c          |  4 +-
 mm/kasan/hw_tags.c    | 92 +++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/shadow.c     | 10 ++++-
 mm/vmalloc.c          | 51 ++++++++++++++++++------
 5 files changed, 175 insertions(+), 18 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 92c5dfa29a35..499f1573dba4 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -25,6 +25,12 @@ struct kunit_kasan_expectation {
 
 #endif
 
+typedef unsigned int __bitwise kasan_vmalloc_flags_t;
+
+#define KASAN_VMALLOC_NONE	0x00u
+#define KASAN_VMALLOC_INIT	0x01u
+#define KASAN_VMALLOC_VM_ALLOC	0x02u
+
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 #include <linux/pgtable.h>
@@ -418,18 +424,39 @@ static inline void kasan_init_hw_tags(void) { }
 
 #ifdef CONFIG_KASAN_VMALLOC
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+
 void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
 int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
 void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void *__kasan_unpoison_vmalloc(const void *start, unsigned long size);
+#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+static inline void kasan_populate_early_vm_area_shadow(void *start,
+						       unsigned long size)
+{ }
+static inline int kasan_populate_vmalloc(unsigned long start,
+					unsigned long size)
+{
+	return 0;
+}
+static inline void kasan_release_vmalloc(unsigned long start,
+					 unsigned long end,
+					 unsigned long free_region_start,
+					 unsigned long free_region_end) { }
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
+			       kasan_vmalloc_flags_t flags);
 static __always_inline void *kasan_unpoison_vmalloc(const void *start,
-						    unsigned long size)
+						unsigned long size,
+						kasan_vmalloc_flags_t flags)
 {
 	if (kasan_enabled())
-		return __kasan_unpoison_vmalloc(start, size);
+		return __kasan_unpoison_vmalloc(start, size, flags);
 	return (void *)start;
 }
 
@@ -456,7 +483,8 @@ static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long free_region_end) { }
 
 static inline void *kasan_unpoison_vmalloc(const void *start,
-					   unsigned long size)
+					   unsigned long size,
+					   kasan_vmalloc_flags_t flags)
 {
 	return (void *)start;
 }
diff --git a/kernel/scs.c b/kernel/scs.c
index 579841be8864..b83bc9251f99 100644
--- a/kernel/scs.c
+++ b/kernel/scs.c
@@ -32,7 +32,7 @@ static void *__scs_alloc(int node)
 	for (i = 0; i < NR_CACHED_SCS; i++) {
 		s = this_cpu_xchg(scs_cache[i], NULL);
 		if (s) {
-			kasan_unpoison_vmalloc(s, SCS_SIZE);
+			kasan_unpoison_vmalloc(s, SCS_SIZE, KASAN_VMALLOC_NONE);
 			memset(s, 0, SCS_SIZE);
 			return s;
 		}
@@ -78,7 +78,7 @@ void scs_free(void *s)
 		if (this_cpu_cmpxchg(scs_cache[i], 0, s) == NULL)
 			return;
 
-	kasan_unpoison_vmalloc(s, SCS_SIZE);
+	kasan_unpoison_vmalloc(s, SCS_SIZE, KASAN_VMALLOC_NONE);
 	vfree_atomic(s);
 }
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 76cf2b6229c7..21104fd51872 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -192,6 +192,98 @@ void __init kasan_init_hw_tags(void)
 		kasan_stack_collection_enabled() ? "on" : "off");
 }
 
+#ifdef CONFIG_KASAN_VMALLOC
+
+static void unpoison_vmalloc_pages(const void *addr, u8 tag)
+{
+	struct vm_struct *area;
+	int i;
+
+	/*
+	 * As hardware tag-based KASAN only tags VM_ALLOC vmalloc allocations
+	 * (see the comment in __kasan_unpoison_vmalloc), all of the pages
+	 * should belong to a single area.
+	 */
+	area = find_vm_area((void *)addr);
+	if (WARN_ON(!area))
+		return;
+
+	for (i = 0; i < area->nr_pages; i++) {
+		struct page *page = area->pages[i];
+
+		page_kasan_tag_set(page, tag);
+	}
+}
+
+void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
+				kasan_vmalloc_flags_t flags)
+{
+	u8 tag;
+	unsigned long redzone_start, redzone_size;
+
+	if (!is_vmalloc_or_module_addr(start))
+		return (void *)start;
+
+	/*
+	 * Skip unpoisoning and assigning a pointer tag for non-VM_ALLOC
+	 * mappings as:
+	 *
+	 * 1. Unlike the software KASAN modes, hardware tag-based KASAN only
+	 *    supports tagging physical memory. Therefore, it can only tag a
+	 *    single mapping of normal physical pages.
+	 * 2. Hardware tag-based KASAN can only tag memory mapped with special
+	 *    mapping protection bits, see arch_vmalloc_pgprot_modify().
+	 *    As non-VM_ALLOC mappings can be mapped outside of vmalloc code,
+	 *    providing these bits would require tracking all non-VM_ALLOC
+	 *    mappers.
+	 *
+	 * Thus, for VM_ALLOC mappings, hardware tag-based KASAN only tags
+	 * the first virtual mapping, which is created by vmalloc().
+	 * Tagging the page_alloc memory backing that vmalloc() allocation is
+	 * skipped, see ___GFP_SKIP_KASAN_UNPOISON.
+	 *
+	 * For non-VM_ALLOC allocations, page_alloc memory is tagged as usual.
+	 */
+	if (!(flags & KASAN_VMALLOC_VM_ALLOC))
+		return (void *)start;
+
+	tag = kasan_random_tag();
+	start = set_tag(start, tag);
+
+	/* Unpoison and initialize memory up to size. */
+	kasan_unpoison(start, size, flags & KASAN_VMALLOC_INIT);
+
+	/*
+	 * Explicitly poison and initialize the in-page vmalloc() redzone.
+	 * Unlike software KASAN modes, hardware tag-based KASAN doesn't
+	 * unpoison memory when populating shadow for vmalloc() space.
+	 */
+	redzone_start = round_up((unsigned long)start + size,
+				 KASAN_GRANULE_SIZE);
+	redzone_size = round_up(redzone_start, PAGE_SIZE) - redzone_start;
+	kasan_poison((void *)redzone_start, redzone_size, KASAN_TAG_INVALID,
+		     flags & KASAN_VMALLOC_INIT);
+
+	/*
+	 * Set per-page tag flags to allow accessing physical memory for the
+	 * vmalloc() mapping through page_address(vmalloc_to_page()).
+	 */
+	unpoison_vmalloc_pages(start, tag);
+
+	return (void *)start;
+}
+
+void __kasan_poison_vmalloc(const void *start, unsigned long size)
+{
+	/*
+	 * No tagging here.
+	 * The physical pages backing the vmalloc() allocation are poisoned
+	 * through the usual page_alloc paths.
+	 */
+}
+
+#endif
+
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_enable_tagging_sync(void)
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 5a866f6663fc..b958babc8fed 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -475,8 +475,16 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
-void *__kasan_unpoison_vmalloc(const void *start, unsigned long size)
+void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
+			       kasan_vmalloc_flags_t flags)
 {
+	/*
+	 * Software KASAN modes unpoison both VM_ALLOC and non-VM_ALLOC
+	 * mappings, so the KASAN_VMALLOC_VM_ALLOC flag is ignored.
+	 * Software KASAN modes can't optimize zeroing memory by combining it
+	 * with setting memory tags, so the KASAN_VMALLOC_INIT flag is ignored.
+	 */
+
 	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
 
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index cc23e181b0ec..47f3de7a3396 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2215,8 +2215,12 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
 		return NULL;
 	}
 
-	/* Mark the pages as accessible, now that they are mapped. */
-	mem = kasan_unpoison_vmalloc(mem, size);
+	/*
+	 * Mark the pages as accessible, now that they are mapped.
+	 * With hardware tag-based KASAN, marking is skipped for
+	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
+	 */
+	mem = kasan_unpoison_vmalloc(mem, size, KASAN_VMALLOC_NONE);
 
 	return mem;
 }
@@ -2450,9 +2454,12 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 	 * best-effort approach, as they can be mapped outside of vmalloc code.
 	 * For VM_ALLOC mappings, the pages are marked as accessible after
 	 * getting mapped in __vmalloc_node_range().
+	 * With hardware tag-based KASAN, marking is skipped for
+	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
 	 */
 	if (!(flags & VM_ALLOC))
-		area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
+		area->addr = kasan_unpoison_vmalloc(area->addr, requested_size,
+							KASAN_VMALLOC_NONE);
 
 	return area;
 }
@@ -3058,6 +3065,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 {
 	struct vm_struct *area;
 	void *ret;
+	kasan_vmalloc_flags_t kasan_flags;
 	unsigned long real_size = size;
 	unsigned long real_align = align;
 	unsigned int shift = PAGE_SHIFT;
@@ -3110,21 +3118,39 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 		goto fail;
 	}
 
-	/*
-	 * Modify protection bits to allow tagging.
-	 * This must be done before mapping by __vmalloc_area_node().
-	 */
+	/* Prepare arguments for __vmalloc_area_node(). */
 	if (kasan_hw_tags_enabled() &&
-	    pgprot_val(prot) == pgprot_val(PAGE_KERNEL))
+	    pgprot_val(prot) == pgprot_val(PAGE_KERNEL)) {
+		/*
+		 * Modify protection bits to allow tagging.
+		 * This must be done before mapping in __vmalloc_area_node().
+		 */
 		prot = arch_vmap_pgprot_tagged(prot);
 
+		/*
+		 * Skip page_alloc poisoning and zeroing for physical pages
+		 * backing VM_ALLOC mapping. Memory is instead poisoned and
+		 * zeroed by kasan_unpoison_vmalloc().
+		 */
+		gfp_mask |= __GFP_SKIP_KASAN_UNPOISON | __GFP_SKIP_ZERO;
+	}
+
 	/* Allocate physical pages and map them into vmalloc space. */
 	ret = __vmalloc_area_node(area, gfp_mask, prot, shift, node);
 	if (!ret)
 		goto fail;
 
-	/* Mark the pages as accessible, now that they are mapped. */
-	area->addr = kasan_unpoison_vmalloc(area->addr, real_size);
+	/*
+	 * Mark the pages as accessible, now that they are mapped.
+	 * The init condition should match the one in post_alloc_hook()
+	 * (except for the should_skip_init() check) to make sure that memory
+	 * is initialized under the same conditions regardless of the enabled
+	 * KASAN mode.
+	 */
+	kasan_flags = KASAN_VMALLOC_VM_ALLOC;
+	if (!want_init_on_free() && want_init_on_alloc(gfp_mask))
+		kasan_flags |= KASAN_VMALLOC_INIT;
+	area->addr = kasan_unpoison_vmalloc(area->addr, real_size, kasan_flags);
 
 	/*
 	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
@@ -3832,10 +3858,13 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	/*
 	 * Mark allocated areas as accessible. Do it now as a best-effort
 	 * approach, as they can be mapped outside of vmalloc code.
+	 * With hardware tag-based KASAN, marking is skipped for
+	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
 	 */
 	for (area = 0; area < nr_vms; area++)
 		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
-							 vms[area]->size);
+							 vms[area]->size,
+							 KASAN_VMALLOC_NONE);
 
 	kfree(vas);
 	return vms;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/97ccf915f6d8df414c9471931ad92780a1f47576.1640036051.git.andreyknvl%40google.com.

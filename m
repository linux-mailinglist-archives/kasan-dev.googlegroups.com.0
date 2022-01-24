Return-Path: <kasan-dev+bncBAABBX6VXOHQMGQE7OG56OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 100974987CE
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:07:28 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id f7-20020a1cc907000000b0034b63f314ccsf283515wmb.6
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:07:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047647; cv=pass;
        d=google.com; s=arc-20160816;
        b=HaA47Ae4RN9usc12g5+DP/9xiW2o/x3ccp6yGi37QJMFwfpQOx2IL1LudNeKjZjk1B
         HcF4z0eJyFhsOu+jDEpm++v4s8sPHFtEuQxeOh4enpMOYkDDnDpWG9+ILA34nqhfkiYo
         ZgkQmy5wWZAbvndSpMtRfFymVKLa1AaMAXFl4Qcw19r13Wlr4rtx1+2KwbbZ7D5QfV+I
         wEPePBU+lkq0aO/WLXxFpA1+ADe5csE3w3Etn3bhw2k2qTTf6Y/dfOyQV9yPJjKfS7PS
         qhdzzAQlHjkbedwNQd0KOY+bqOshcabp2lFf8CVqWGPi0JQx4d3z2WzHbCzWAY+NorF4
         Bd2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pXcWOAnFn/HL96j1qS+kGKUuyA5I/aHuItZGly2qEjw=;
        b=LfpJtNwBKiW2N+OS81NdLyGQyr58M0FgyXQCrQ8GpFfO1tOE/gxNpv9o/xtdHuy51z
         tR8QbnihHmFJelyE2E9d3AbXMeQycTe9X/5AdhV1ymhD40eLNYHUW38dVKog756HN02K
         PzVGipHbunul3SBXmn2ClBbjAjqQ7LS68AgBY3C2m8O84+0RyRZ58sMRwMgRRD3Gi1Q6
         HKuLBribKdtpTk4HUjmow+V1O5RZZ8KkEQTVIYALknt1eFLjvcyOCqds10pMyqyr9psO
         ybvxZ1xZG/F1J7hN68xkXZED678V/kk45FFMAMOdqDg+72hY7l7G9Skv4hyIJQjfCiFK
         9hjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qtquelmQ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pXcWOAnFn/HL96j1qS+kGKUuyA5I/aHuItZGly2qEjw=;
        b=VjXh2nFHqBTsK1KD2w/xOSD62c6jcqusCnJ06lgYI/Za+5lotqjnVAjv7KEWcmKEuH
         a3S8bkiqGmzJ+kq3g1Sd59dvbzIPuGzVkLvevyiU3sWiKz5p4MWp5hr1t3NloS36YDwa
         KFQOIo2Lsx+mTC0Iz6VkGFg656NejYaoK2yh2AxslsE0OsKO0RVohyr6VDXrkdXZelN8
         lK33w2MkdQccY/NncuhqbWlPjHLkW+7Zd+463JQ7x0ud0yWr3G0vsqs83sBXoodCBoWE
         XyhI9n9CMLPWTa+nPlxUZYk4WiC//SWKuFRHsTRBJhwyLNp6Ew7tlGUt9jjVkvPNu0lj
         qu+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pXcWOAnFn/HL96j1qS+kGKUuyA5I/aHuItZGly2qEjw=;
        b=aZsQUG/HPA3d6ybZe+u+0OtqYoD2HwMLLN3dbmYpVlW04g48SgNRVxAkY4hDq8i97V
         uhs9dvsSN9mapzjhO76cSfop3pt+C363SH4Y2UtaPeY11P5CTsb3i4MYQRSSwPTg4Lz2
         6OKzZdTi9zcYr9lRqjW7EOkPh7UG0qNBnP9eprvFYwFgze/4z5gTwW0PBicw/xg4A/ju
         p6u+g51aICBnEIsNffC1pw4d85wueYVsjzkVeY7X+RM7AGN++Rs7J85dC0aSjv29MyWr
         gupWcYkzYhM6wKaGZPb+tKGDuBrHPAdmXi/voUCEoQeMyQEwZks9KJkmvQW6mJRB36y2
         NRjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OZEL1occVImFtKs0IOb1JSO02uA4txRxgx5d/8ytAgi2jNvvu
	jr1qxWdT6wxwq5Z6G9EXoIk=
X-Google-Smtp-Source: ABdhPJzli7M1Pj3rAx7Wxf4D+8cIoJ2ysTKH5/+uJCCsTxmqevzLX7fs2DRyaoSn667g/eDU/MaAsw==
X-Received: by 2002:adf:d1c6:: with SMTP id b6mr10976656wrd.88.1643047647654;
        Mon, 24 Jan 2022 10:07:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f80e:: with SMTP id s14ls303321wrp.2.gmail; Mon, 24 Jan
 2022 10:07:26 -0800 (PST)
X-Received: by 2002:a5d:4701:: with SMTP id y1mr5985147wrq.576.1643047646903;
        Mon, 24 Jan 2022 10:07:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047646; cv=none;
        d=google.com; s=arc-20160816;
        b=xa1GO03wHm8F3kB9Ly9X9pFQnIxSO9shUgPFrVxQkeEYBhZj3XY5BwoHlbMlEnbe+E
         Vma6zIp8hcSMeAph+RPqqmCppuTTs5Gb1ZBH1r+qP8Rpshx4hIYdYG616AG1Tt+XBFMR
         PQj5ZvBRwU+qW/h9S8bGzDPGFoBimQn6lZXEUxqFitEcg8+FFVGzTN1HGW2NWfxSaTmC
         kDfwRGP0fXR4drtQFXsIG/rQR2nJo9aH3WNCBGs01weV9rs+mQUnh0sdxPLU9PfFvI9J
         /xokqusnX7PIJaGAdm46KXMMQ3l/zkVzoMDpxl0VWL4GWsPPXXO5sPxMtAUbk3oruYtq
         vYRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=L2wQT1d/w3fGCiKjwOUJ2oVIDACQn/YNGLLlrS6LjTc=;
        b=fg28XjGZxSb2NiXGertXksDwD3j3fm7qa5XvniVjOrJdGPEzHKlQhPpYUHeSPYhwM3
         pLlOo829xpdEU9XE3jPayX+s1LR9RW+I1vFtYeI3XhgmbRBmJGPsDHbhOMPLXrDW+0fI
         2BRLl0jFXIqTCP61Buklt0NwWzMNWYrDrLY8sX3uDX6HuRxou6xoJvROLtsm5z7fMKyb
         dyNuAQuGv0FF0DUxwXPTUqKb1nipUprQ1KituZCG26aqWI4IKb+0yPVnMnh72GmMUGyp
         FK8BjJ6NQwirMgxTl/dFuqv6f1/iovqAFyWUa7q41BX/X7jWoS39cmgMs6Oo8hcN2tNL
         hguQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qtquelmQ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id h2si541008wrp.7.2022.01.24.10.07.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:07:26 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH v6 30/39] kasan, vmalloc: add vmalloc tagging for HW_TAGS
Date: Mon, 24 Jan 2022 19:05:04 +0100
Message-Id: <d19b2e9e59a9abc59d05b72dea8429dcaea739c6.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=qtquelmQ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index b65adac1cd80..6dcdf815576b 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2216,8 +2216,12 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
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
@@ -2451,9 +2455,12 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
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
@@ -3064,6 +3071,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 {
 	struct vm_struct *area;
 	void *ret;
+	kasan_vmalloc_flags_t kasan_flags;
 	unsigned long real_size = size;
 	unsigned long real_align = align;
 	unsigned int shift = PAGE_SHIFT;
@@ -3116,21 +3124,39 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
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
@@ -3830,10 +3856,13 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d19b2e9e59a9abc59d05b72dea8429dcaea739c6.1643047180.git.andreyknvl%40google.com.

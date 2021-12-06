Return-Path: <kasan-dev+bncBAABBRUJXKGQMGQEKVKLYKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 40DB546AAD4
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:46:47 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id z138-20020a1c7e90000000b003319c5f9164sf194012wmc.7
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:46:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827207; cv=pass;
        d=google.com; s=arc-20160816;
        b=X6Vlu/Y25XCCPZrcFHqSqnBNxv/acThr0cvduAlBW4IYE0mJEer8w+yvG0gAKLgiBS
         8Q4k/Z4INeZDhZZDGfRZ9X2a2I0QP/ogI+jIHznznnJ9+I0Y6lp5ZlbSiczvJ9mWgDdh
         3mNpoVoAFwpun/uTz/i2gD33cmQuula1fEVvHpiBcfqo5acgdhkd+/tHfp7jZGBhgL1Z
         evuSM9LwgXVQT+lbORx/BPmBUXUk04nYs2rTl+I0hkGnNhoLNr89y0aaPrzWWzcqHhv3
         bHYgoHjP3pmLv440TR9xzW+es5p9RJo/ZHR2ZmkDDp3ckLTfsMJI/yc343hk2ZSwtdC7
         xJ9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zODfJzocCxz07nHIOwSHlh5XxZVB+Q2R+EhOAgHwwCg=;
        b=0/hLrLb3AVTKbw5fhpXhapSTaU8olrHDFyKGrVemYZAEh5zGTJ5n11oKS4xBwgRZGD
         k8K/lXaqq72AIoGiXXQseQqMwsMD0vJu4BChCDoHIOWHBaC/mQ7/MUenhrFmjXGJxkVq
         md2BmJKSjTYdt/nDJO0ReXYcUFjIqmV6ouGJ322Dc0xbLcfa8lX4RY8VpI0Nr4GFbtP5
         mZXJVjNtDGpQnGEEqL4qpGAAqVgCTlovcX4yLet6NIfe32l6J6yTq4tJky8qqBA/oJ6e
         Y9pF8nSa6QJ9+kmFCWRx8dHa3QAJ7qtk02SS09gxj3wPi+frVB8474ECMGv/WbN1fPTp
         pBeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DPBuz+qZ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zODfJzocCxz07nHIOwSHlh5XxZVB+Q2R+EhOAgHwwCg=;
        b=t3DEJ620+d/CPKg7jlsxJ8rTpg/mbB5cJoxdGoJywO2Krkcyb+OKJvjSUiMMj/0EYK
         in+Y1C9tM5cdK4YH26Ck/X0XndKBvPcfg26LeLGEJSk1F/FN6y5F8xhCIM+zYF1V6/cq
         HHV9OYAc1WKHtbPScD6cYxZ7zc3wKeJ3W6h6xXmLhBk4/UnIpvTS68pq9XXspxR6LCCW
         1ZKUPpF0maRhN17URZgK4/02rAPl2JHwBM6TpFwQSmZhaAjYm2bCCe9FKuY9fayLMcDh
         qt0Cbwve7tBdahZP1Oc7wJi6KcLUHwhdimA0QlqgxfK1v+D9SPtlYhfVa82uir/LY47l
         8J8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zODfJzocCxz07nHIOwSHlh5XxZVB+Q2R+EhOAgHwwCg=;
        b=A9zVIv4DATW8tq2NPX6CUQUml9ILDxkT5M5VyRtqw+vBNclLAvwPsQQ3RB4988F5cX
         YxSpg2UYYrMES6WzW2FxBZujOEBj1+HMxvGdRBE0pz2DVAl0b/EREW5v77Vzys9Mzd7n
         kBTHFiYJ2L9IXmSQbwMruId4Ih5jY+qokc3hAZOBou5uKfaams16kfKBGjyP1FZNNiD4
         uCPukY7rLp9Bk324UAU4BVJ99Sfn6jGoMfWnTh5tFbpZhu/uqoNMDYRSliNgrtRY37hs
         DdielzcJPGjGUiW5EBrSVlfBMGIfho35seCDQqrT30OdXe9VRyPfsRp39bU+9cJtl8TW
         CrVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532UeLM2rrd1DCGjxRy05nLSNQ1s2gLFQ4bIb7aGAhYrwv7nY9m9
	+SqZReacUC9qovC4uRadIXo=
X-Google-Smtp-Source: ABdhPJw512xgaz4WEOwrNb91auh0pJaOu/FtQjU8bkEx4pqLgBUsVRv9APUP+L8NF04mGVyO7DSUcQ==
X-Received: by 2002:a5d:59ae:: with SMTP id p14mr45321437wrr.365.1638827206995;
        Mon, 06 Dec 2021 13:46:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:770f:: with SMTP id t15ls223816wmi.3.gmail; Mon, 06 Dec
 2021 13:46:46 -0800 (PST)
X-Received: by 2002:a05:600c:3510:: with SMTP id h16mr1521358wmq.144.1638827206315;
        Mon, 06 Dec 2021 13:46:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827206; cv=none;
        d=google.com; s=arc-20160816;
        b=b0fcFV3qW1rKezwcRUk8oTV4rmGbJS3OzAG7QjMP+i7efZTaMFtxgPHzpSPBjwo+ID
         Q6qc1i8wqQUIqCOfXSVbayrUhuVB1u15C0iXb7detIVy6u4jPd/Pjj5YG/xvFAw73Rmu
         AFw7Fs0EiMVCL2vi139xud4DmxgItDwzLD7nRDqqXWfzveJY8lCfqGUBol+PqPEPAZht
         y06traLSGsQQU0TqBGs0nwiugzkpU0YVHp3ZBx3q/wtH8LWuFk6z/JPNg/jCeL+JHUCC
         7NKEYORyZZl4Gerco1C1kHySLD2HovenKVpyc6VTNx2DNgnUTt2nUtG/sgSATAEOSHwd
         g38w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=74CNvwwh68OzFRGu8FIPa2yQlRoKG2WJZYC0+RUr6EA=;
        b=t3o9gL++u9I/2YfFt3rd8+L24tpSh0Xkl2zGZst4Fn0G/XiFycmcSumyADg6YO1fHx
         VdpXfS559LwJgEw/x4H+Ayvk3CcJS5LXYEZlG4JoXid7D4EpLjocHQSKxfn96i5Xg5Cy
         5TUQ+/TJWGRki4bgxQWKFleRnNGB2fTdtSstVOSd8CEIjCm2TU0WMmhZCcTbpS/5gvz1
         SwLZnEsscLDhRKypEff3sooO1EPfkBQPRLjBKTkvPCs/XUVX1BgZhJHwe2cx+w2TlN+I
         hf0B2s5SQf6ZqqYSUfW7vf/RPSEoFxbbO+pFEKwv1/FyduCkL1xUxHrvtiqTxKD4ikom
         i1zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DPBuz+qZ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id c2si105121wmq.2.2021.12.06.13.46.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:46:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 28/34] kasan, vmalloc: add vmalloc support to HW_TAGS
Date: Mon,  6 Dec 2021 22:44:05 +0100
Message-Id: <72a8a7aa09eb279d7eabf7ea1101556d13360950.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DPBuz+qZ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

This patch adds vmalloc tagging support to HW_TAGS KASAN.

The key difference between HW_TAGS and the other two KASAN modes
when it comes to vmalloc: HW_TAGS KASAN can only assign tags to
physical memory. The other two modes have shadow memory covering
every mapped virtual memory region.

This patch makes __kasan_unpoison_vmalloc() for HW_TAGS KASAN:

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

This patch allows enabling CONFIG_KASAN_VMALLOC with HW_TAGS
and adjusts CONFIG_KASAN_VMALLOC description:

- Mention HW_TAGS support.
- Remove unneeded internal details: they have no place in Kconfig
  description and are already explained in the documentation.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

---

Changes v1->v2:
- Allow enabling CONFIG_KASAN_VMALLOC with HW_TAGS in this patch.
- Move memory init for page_alloc pages backing vmalloc() into
  kasan_unpoison_vmalloc().
---
 include/linux/kasan.h | 30 +++++++++++++--
 lib/Kconfig.kasan     | 20 +++++-----
 mm/kasan/hw_tags.c    | 89 +++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/shadow.c     | 11 +++++-
 mm/vmalloc.c          | 32 +++++++++++++---
 5 files changed, 162 insertions(+), 20 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 6a2619759e93..0bdc2b824b9c 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -417,19 +417,40 @@ static inline void kasan_init_hw_tags(void) { }
 
 #ifdef CONFIG_KASAN_VMALLOC
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+
 void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
 int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
 void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
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
 void * __must_check __kasan_unpoison_vmalloc(const void *start,
-					     unsigned long size);
+					     unsigned long size,
+					     bool vm_alloc, bool init);
 static __always_inline void * __must_check kasan_unpoison_vmalloc(
-					const void *start, unsigned long size)
+					const void *start, unsigned long size,
+					bool vm_alloc, bool init)
 {
 	if (kasan_enabled())
-		return __kasan_unpoison_vmalloc(start, size);
+		return __kasan_unpoison_vmalloc(start, size, vm_alloc, init);
 	return (void *)start;
 }
 
@@ -456,7 +477,8 @@ static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long free_region_end) { }
 
 static inline void *kasan_unpoison_vmalloc(const void *start,
-					   unsigned long size, bool unique)
+					   unsigned long size,
+					   bool vm_alloc, bool init)
 {
 	return (void *)start;
 }
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 3f144a87f8a3..7834c35a7964 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -178,17 +178,17 @@ config KASAN_TAGS_IDENTIFY
 	  memory consumption.
 
 config KASAN_VMALLOC
-	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on (KASAN_GENERIC || KASAN_SW_TAGS) && HAVE_ARCH_KASAN_VMALLOC
+	bool "Check accesses to vmalloc allocations"
+	depends on HAVE_ARCH_KASAN_VMALLOC
 	help
-	  By default, the shadow region for vmalloc space is the read-only
-	  zero page. This means that KASAN cannot detect errors involving
-	  vmalloc space.
-
-	  Enabling this option will hook in to vmap/vmalloc and back those
-	  mappings with real shadow memory allocated on demand. This allows
-	  for KASAN to detect more sorts of errors (and to support vmapped
-	  stacks), but at the cost of higher memory usage.
+	  This mode makes KASAN check accesses to vmalloc allocations for
+	  validity.
+
+	  With software KASAN modes, checking is done for all types of vmalloc
+	  allocations. Enabling this option leads to higher memory usage.
+
+	  With hardware tag-based KASAN, only VM_ALLOC mappings are checked.
+	  There is no additional memory usage.
 
 config KASAN_KUNIT_TEST
 	tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 76cf2b6229c7..837c260beec6 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -192,6 +192,95 @@ void __init kasan_init_hw_tags(void)
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
+				bool vm_alloc, bool init)
+{
+	u8 tag;
+	unsigned long redzone_start, redzone_size;
+
+	if (!is_vmalloc_or_module_addr(start))
+		return (void *)start;
+
+	/* Unpoisoning and pointer tag assignment is skipped for non-VM_ALLOC
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
+	if (!vm_alloc)
+		return (void *)start;
+
+	tag = kasan_random_tag();
+	start = set_tag(start, tag);
+
+	/* Unpoison and initialize memory up to size. */
+	kasan_unpoison(start, size, init);
+
+	/*
+	 * Explicitly poison and initialize the in-page vmalloc() redzone.
+	 * Unlike software KASAN modes, hardware tag-based KASAN doesn't
+	 * unpoison memory when populating shadow for vmalloc() space.
+	 */
+	redzone_start = round_up((unsigned long)start + size, KASAN_GRANULE_SIZE);
+	redzone_size = round_up(redzone_start, PAGE_SIZE) - redzone_start;
+	kasan_poison((void *)redzone_start, redzone_size, KASAN_TAG_INVALID, init);
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
index 4ca280a96fbc..8600dd925f35 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -475,8 +475,17 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
-void *__kasan_unpoison_vmalloc(const void *start, unsigned long size)
+void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
+				bool vm_alloc, bool init)
 {
+	/*
+	 * Software tag-based KASAN tags both VM_ALLOC and non-VM_ALLOC
+	 * mappings, so the vm_alloc argument is ignored.
+	 * Software tag-based KASAN can't optimize zeroing memory by combining
+	 * it with setting memory tags, so the init argument is ignored;
+	 * vmalloc() memory is poisoned via page_alloc.
+	 */
+
 	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
 
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 82ef1e27e2e4..d48db7cc3358 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2214,8 +2214,12 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
 		return NULL;
 	}
 
-	/* Mark the pages as accessible after they were mapped in. */
-	mem = kasan_unpoison_vmalloc(mem, size);
+	/*
+	 * Mark the pages as accessible after they were mapped in.
+	 * With hardware tag-based KASAN, marking is skipped for
+	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
+	 */
+	mem = kasan_unpoison_vmalloc(mem, size, false, false);
 
 	return mem;
 }
@@ -2449,9 +2453,12 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 	 * accessible after they are mapped in.
 	 * Otherwise, as the pages can be mapped outside of vmalloc code,
 	 * mark them now as a best-effort approach.
+	 * With hardware tag-based KASAN, marking is skipped for
+	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
 	 */
 	if (!(flags & VM_ALLOC))
-		area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
+		area->addr = kasan_unpoison_vmalloc(area->addr, requested_size,
+							false, false);
 
 	return area;
 }
@@ -2849,6 +2856,12 @@ vm_area_alloc_pages(gfp_t gfp, int nid,
 	struct page *page;
 	int i;
 
+	/*
+	 * Skip page_alloc poisoning and zeroing for pages backing VM_ALLOC
+	 * mappings. Only effective in HW_TAGS mode.
+	 */
+	gfp &= __GFP_SKIP_KASAN_UNPOISON & __GFP_SKIP_ZERO;
+
 	/*
 	 * For order-0 pages we make use of bulk allocator, if
 	 * the page array is partly or not at all populated due
@@ -3027,6 +3040,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 {
 	struct vm_struct *area;
 	void *addr;
+	bool init;
 	unsigned long real_size = size;
 	unsigned long real_align = align;
 	unsigned int shift = PAGE_SHIFT;
@@ -3083,8 +3097,13 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	/*
 	 * Mark the pages for VM_ALLOC mappings as accessible after they were
 	 * mapped in.
+	 * The init condition should match the one in post_alloc_hook()
+	 * (except for the should_skip_init() check) to make sure that memory
+	 * is initialized under the same conditions regardless of the enabled
+	 * KASAN mode.
 	 */
-	addr = kasan_unpoison_vmalloc(addr, real_size);
+	init = !want_init_on_free() && want_init_on_alloc(gfp_mask);
+	addr = kasan_unpoison_vmalloc(addr, real_size, true, init);
 
 	/*
 	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
@@ -3784,10 +3803,13 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	 * Mark allocated areas as accessible.
 	 * As the pages are mapped outside of vmalloc code,
 	 * mark them now as a best-effort approach.
+	 * With hardware tag-based KASAN, marking is skipped for
+	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
 	 */
 	for (area = 0; area < nr_vms; area++)
 		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
-							 vms[area]->size);
+							 vms[area]->size,
+							 false, false);
 
 	kfree(vas);
 	return vms;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/72a8a7aa09eb279d7eabf7ea1101556d13360950.1638825394.git.andreyknvl%40google.com.

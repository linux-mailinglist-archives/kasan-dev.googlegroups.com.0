Return-Path: <kasan-dev+bncBAABBT6BTKGQMGQEDTA3SFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 55307464105
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:08:16 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id c40-20020a05651223a800b004018e2f2512sf8587535lfv.11
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:08:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310096; cv=pass;
        d=google.com; s=arc-20160816;
        b=IrvpztfufgiImQaXelCdQIDapjS+xUUNwG262GrwKcc3TMdQz/yan2Eg8u4AVmRjsG
         svd5AUsKKCzWRojCukav49xT4DEPtwILA+n+ox7LgdQWo1gBOwEAvXgqUkcKGEOghr6P
         JG5oxGPj7WhZSpbY9zLx3Pok5H69pKFEl6lEOdR56ZfUg2Ql8qElDZuEHwgtJesuTuci
         z+i0ErcOHvi48XcrV2WG3oIJvMdR+ZtUlndEjGkxneF8Pz7T6SXz3leMpiUH3M/xaeI2
         8UBboNY260HklkOJ6uAxl63IkRdS0/+vgociQ/2wLiLoCMQBwWNW4vt6tItpxg6f6ghp
         yvRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cqTwC+ryMa3OmYzNRUiQpPrt4jwFOzY/TcPCIVcYZEY=;
        b=fZ/r2dggihXTua8TTBcuCq72ry7Tro4P7CcPgI+rYTP+XqwqN0omnhAq9NCkb5RcDl
         U3KcFnDUGlffit0Ih0hMHxBW3ljBfgDq50fgIVzDk7aBvZinXyf5FmZWfVBO3cmkUeE6
         ySV7sliEjaIwXlvyHw4ThKom4RzghbSkGJh1n5prjNTXF93zSMtcqiNY9+AIesnMB+ai
         TQpZ05eGOfy7WtlKmwG0+I3W4pp1Rlu4ZLXss6u+fgjidaEKpX1lfhhN2xaC638Namk2
         B8eB0dde3/MzO6vvTwkchBFSbb5t3TrLwhe2R6CZkIfDJqy0H4GiKRN/2XlAxCLKXnOC
         qFTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=e5hYOgE6;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cqTwC+ryMa3OmYzNRUiQpPrt4jwFOzY/TcPCIVcYZEY=;
        b=QkkUQJdyMnZ19DCoPIXK9hHeK/ywxVslhPBtm0oqOkMOzUrW0NmhNW2btpSNucf00v
         ZK9mMn4VyTcNN5Ai0QQ9iXMPtEFGpMgFzxKNzmQwdVf0/MsG4dIkALj58+050+i/BBpj
         E7eGPh+K1EQvIE2iFBd061RwOzzZmYvly+SnODz6fKax25TBt773wO07AWfYIDt9KKZ6
         CCRsGKi+VT6dP+gFb1I8XNEqv6Jht7wPQY2AtjzC2w7GdvuU9htymktvrHGsG5EW5FTq
         njrVnT5URlkRdG4fgpK0XmTIV8dolgdKYgeyHfHY2Gaud6l2SvxtfXGS66lO3g4Ka27I
         SY/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cqTwC+ryMa3OmYzNRUiQpPrt4jwFOzY/TcPCIVcYZEY=;
        b=q+P1v/9HmH4wY4B9VrShM0CF9vkujeyJgkO9Js6oR4ZYlwzazpVpc8gWguvcZfG6Yj
         y6V65tugJVe3qQSezVGle8LFwQx/9nd5HrqYsQufi61U1FIc1mgph/ehBfebdDBWFLjb
         vitwtdqWUGEaicou+2A6XHVucI9c35vAGLaRwQpStlkLxDYjZa6mphgXxYEL4aXzM8oh
         OygFrgTl10SIjPIo6FRhn7FGBBr+z11v7KSM8Lc9YTi5I75u2RbOqcpKseAct6CuTWSl
         V6oUu/ezh1DtGUwyh/TrV+CAzPdu13I692su7EMs7sdfGp0VufvZhhr7M+l2NYM/P5N2
         25VA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5320CZrfA8OsQ0uDmQFG0IuQ6eZGAmVmERO/vFitnPQDXV4snb55
	jy2R/mP9bW5qbDPAz+ThGak=
X-Google-Smtp-Source: ABdhPJz95+M3qxEKGArEnCkWLHrTsK28RWSF4g52WBMZG+2Y++x8X4b3pa5RlIIhlQkwjsY8I7ngtA==
X-Received: by 2002:a2e:2a46:: with SMTP id q67mr1636309ljq.398.1638310095941;
        Tue, 30 Nov 2021 14:08:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a378:: with SMTP id i24ls14769ljn.3.gmail; Tue, 30 Nov
 2021 14:08:15 -0800 (PST)
X-Received: by 2002:a2e:7319:: with SMTP id o25mr1611507ljc.320.1638310095113;
        Tue, 30 Nov 2021 14:08:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310095; cv=none;
        d=google.com; s=arc-20160816;
        b=QdOsGjLOel4AL4c8ofY8I2PVRZgvziEr2gantbEu91wDCkO4pH0TQXEnFktvWS1FyQ
         ncKu3uPM0/Iis9LjzYBdKWkd9WCKGav5Tqy5qgciG4RjeltoKvJv0AlFOzeKlRvH1Idh
         K+KKTwBLNnJ8KHLrOpYXl+g9orTh+ku/C+VHJ0HCBwJWGmeKVxXGDZBjuCtfwNieHIrK
         Hm3ToyyLwKN2tNn/DFJqrHirB7/6sKxgoJ6FSbAIln6SAvuDQ8GC3bVbRxYriZLSlSfK
         7BFtqkTsh5GMLr/BYE2Wvg3dltM2d0zRZbNvA9kd4Nyh9nX+Y5Zud45bQwxzkBolzpZ8
         DP6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HNHQ9BiBKyIqAtWVImrJMYlD8BjFZxN/2CktLIPvhw0=;
        b=lH4MVi2nZIsktcSr7qe/laGm90nCh4fgCfQFlC4MeHaxB9Hv8duhDUJycBg8lK7n6E
         aTOuvfAYmgbUGlC6U1U7vQ8nj393JmmTeC5eckxtj/hYGL8GRB0K350dCb51qR33YMQ/
         RR50zguQ6fp1+CBoxXiw6nf/vrs47LeVLGb61bbmY4l+JBdh50H9NUuuPUMGOyoxC+Rl
         MYV45rgJ9nv4xIw4mDpGXQmJxhb2vfnOpSGf7LBR1BF1gIc7t1rivbjBZ6WT5E6uilBE
         cX1tutfq77/HTQNaFusDu58FJFILbw8TA7E0HFQbeUYAr/8ibyALR5V0u1LAL8FsEFFQ
         8eCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=e5hYOgE6;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id g21si1785138lfv.11.2021.11.30.14.08.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:08:15 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 27/31] kasan, vmalloc: add vmalloc support to HW_TAGS
Date: Tue, 30 Nov 2021 23:08:12 +0100
Message-Id: <aa90926d11b5977402af4ce6dccea89932006d36.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=e5hYOgE6;       spf=pass
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

This patch adds vmalloc tagging support to HW_TAGS KASAN.

The key difference between HW_TAGS and the other two KASAN modes
when it comes to vmalloc: HW_TAGS KASAN can only assign tags to
physical memory. The other two modes have shadow memory covering
every mapped virtual memory region.

This patch makes __kasan_unpoison_vmalloc() for HW_TAGS KASAN:

- Skip non-VM_ALLOC mappings as HW_TAGS KASAN can only tag a single
  mapping of normal physical memory; see the comment in the function.
- Generate a random tag, tag the returned pointer and the allocation.
- Propagate the tag into the page stucts to allow accesses through
  page_address(vmalloc_to_page()).

The rest of vmalloc-related KASAN hooks are not needed:

- The shadow-related ones are fully skipped.
- __kasan_poison_vmalloc() is kept as a no-op with a comment.

Poisoning of physical pages that are backing vmalloc() allocations
is skipped via __GFP_SKIP_KASAN_UNPOISON: __kasan_unpoison_vmalloc()
poisons them instead.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 include/linux/kasan.h | 27 +++++++++++--
 mm/kasan/hw_tags.c    | 92 +++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/shadow.c     |  8 +++-
 mm/vmalloc.c          | 25 +++++++++---
 4 files changed, 143 insertions(+), 9 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 6a2619759e93..df1a09fb7623 100644
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
+					     bool vm_alloc);
 static __always_inline void * __must_check kasan_unpoison_vmalloc(
-					const void *start, unsigned long size)
+					const void *start, unsigned long size,
+					bool vm_alloc)
 {
 	if (kasan_enabled())
-		return __kasan_unpoison_vmalloc(start, size);
+		return __kasan_unpoison_vmalloc(start, size, vm_alloc);
 	return (void *)start;
 }
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 76cf2b6229c7..fd3a93dfca42 100644
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
+				bool vm_alloc)
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
+	/*
+	 * Unpoison but don't initialize. The pages have already been
+	 * initialized by page_alloc.
+	 */
+	kasan_unpoison(start, size, false);
+
+	/*
+	 * Unlike software KASAN modes, hardware tag-based KASAN doesn't
+	 * unpoison memory when populating shadow for vmalloc() space.
+	 * Thus, it needs to explicitly poison the in-page vmalloc() redzone.
+	 */
+	redzone_start = round_up((unsigned long)start + size, KASAN_GRANULE_SIZE);
+	redzone_size = round_up(redzone_start, PAGE_SIZE) - redzone_start;
+	kasan_poison((void *)redzone_start, redzone_size, KASAN_TAG_INVALID, false);
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
index 4ca280a96fbc..f27d48c24166 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -475,8 +475,14 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
-void *__kasan_unpoison_vmalloc(const void *start, unsigned long size)
+void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
+				bool vm_alloc)
 {
+	/*
+	 * As software tag-based KASAN tags both VM_ALLOC and non-VM_ALLOC
+	 * mappings, the vm_alloc argument is ignored.
+	 */
+
 	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
 
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 82ef1e27e2e4..409a289dec81 100644
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
+	mem = kasan_unpoison_vmalloc(mem, size, false);
 
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
+							false);
 
 	return area;
 }
@@ -2849,6 +2856,12 @@ vm_area_alloc_pages(gfp_t gfp, int nid,
 	struct page *page;
 	int i;
 
+	/*
+	 * Skip page_alloc poisoning for pages backing VM_ALLOC mappings,
+	 * see __kasan_unpoison_vmalloc. Only effective in HW_TAGS mode.
+	 */
+	gfp &= __GFP_SKIP_KASAN_UNPOISON;
+
 	/*
 	 * For order-0 pages we make use of bulk allocator, if
 	 * the page array is partly or not at all populated due
@@ -3084,7 +3097,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	 * Mark the pages for VM_ALLOC mappings as accessible after they were
 	 * mapped in.
 	 */
-	addr = kasan_unpoison_vmalloc(addr, real_size);
+	addr = kasan_unpoison_vmalloc(addr, real_size, true);
 
 	/*
 	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
@@ -3784,10 +3797,12 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	 * Mark allocated areas as accessible.
 	 * As the pages are mapped outside of vmalloc code,
 	 * mark them now as a best-effort approach.
+	 * With hardware tag-based KASAN, marking is skipped for
+	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
 	 */
 	for (area = 0; area < nr_vms; area++)
 		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
-							 vms[area]->size);
+							 vms[area]->size, false);
 
 	kfree(vas);
 	return vms;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/aa90926d11b5977402af4ce6dccea89932006d36.1638308023.git.andreyknvl%40google.com.

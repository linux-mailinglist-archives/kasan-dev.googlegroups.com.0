Return-Path: <kasan-dev+bncBAABBMEC36GQMGQENQUJIUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C0704736F5
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:54:57 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id o4-20020adfca04000000b0018f07ad171asf4167951wrh.20
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:54:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432497; cv=pass;
        d=google.com; s=arc-20160816;
        b=R0SX4qShPTeuBvlVkhvD40LLO4Wp/dxXpxarVwKC6zYExhwsXAU/bPVN1QCRbt0KsM
         hldqoPL4chtvFbIbOavxxHxviR1eTioXaqy9gqH5tvMFIHtymXUafyYGPH8uIwXfGdVT
         o2MdaJkjkvV0roNT5fZ3saQPc+NpG3ZP1S7JyeHRP85C4xZlb943WDO5rKoraS4u8W8A
         SHTawCEUj8iQ3K+aRCAYWouDA9xcerK0AMeutLslJM2ikpbMF6lIkseURHxcoL/Fc7Sr
         JX4nowgk1l1LmXZylnYKNmOJ9yOWmi/7wZjaboTO287I2R9ofY/V2YKL6s6dUoA8TQsW
         lU/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WM0cSCXKqASLI0m9+n64Zb34n0yI2Zk1Vd06kv3zUEk=;
        b=EBDwVJCVkZQNMD8qUK8mAKOYok8qxuh1mH5HQUMtZZhg3Mvj+nYbYkraB9jOUY4xIY
         DWKfTB8VAhAY9jFNdsAntcyvFyOPmoqv6m2+a/XBRWn8h8PxIRtchWkdMGAj/+KazDBL
         iZyWPqXbWv7IyEB+3KEZcVAlc4lFLm/75WdIjKghvQRtGgilxmkbvk5I6HiyymalqJQt
         Mz6iJufF4Ks8cToMjzDdf03Cua+x+3o43aCLTJfvb61PXZaCUTJ9SijMYsu4Jj7vXnfC
         E9jhKHYdDMtJQI6XPA8GWnmmlMZR6VpJlZStUMOAHNESo2AtW6SfSdB9mHQBDxjOQp4Y
         l8ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=o4YA6eJp;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WM0cSCXKqASLI0m9+n64Zb34n0yI2Zk1Vd06kv3zUEk=;
        b=kVLtSu4+JfIlmD4cVm5WvaIVJVc3sRHxdLR/9moHwapUMKFxaHWawbj7I3thoZKy4L
         pdtltA6NJNOSFq1P1aCLcrEP01ZAdWiY+oTjfgI1IuOOx3sXYosxfk50iIhRVFpgbicP
         qLyWq1SK5+2XSor5dX0UNHHcHVlcEbUYNfGbIqX1MDnEQ+JO27zCsmxCKqr3LG+wD8+L
         Fek9+sXjOgqO+5zxPgj2DK7J3Zqe67tB0NaP/A161K5nh897ttdaoVQBCJLcjqHdgiZc
         1JO0MtM5kbhLlDtHZ5afRhDJaQL5fQ9BCPeXnqY/RpTa6EzCLOsTI3/LNka92lAE4LIJ
         C76A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WM0cSCXKqASLI0m9+n64Zb34n0yI2Zk1Vd06kv3zUEk=;
        b=drgKp9P4ryug/NDVRpf6h/uUfW+VyrgokgyKHgobEQcwyJ4kyN9YCDWPxUCrUJh3Bv
         O+HlODknRc+n3kiwnMqfwmJXy+V0zY15O9rYjXf39Y+AAq05Bu6C42HNd8LJ/DlWbXBg
         xDBRHMJlDoPa8iBJ0TzKh90j1nnMYyRn+u8eMQvwKQHU1+2feERvk2cUVUoo21msu9Jo
         JscDRASpAmSpWx8uowC9GAlwXVCnUHM1EVVMURWez4jNsk9qUDvlWUaqt+oqz0KVAZa1
         yYCM9nXde4BgMkqdPjQmULtzva7o3U58fSN64qMof6McLSGoNIvK1Oa8sxKmsRfyo41m
         Hrzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53175dqkWLBcU+F7ZS8MVNYUHp0n0P+jICz5tg39aKAlvn+N/3VP
	Qgk5BPyFcmswioEVkZntOPo=
X-Google-Smtp-Source: ABdhPJxj3Al6JWWpsckfxBdrMT0mXXi9q7Nv8WYdz2OKETUEhfwMkkOwqeMY3fV2baf5zdfxkWLumg==
X-Received: by 2002:a05:600c:6024:: with SMTP id az36mr39618703wmb.11.1639432497000;
        Mon, 13 Dec 2021 13:54:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls502219wrr.0.gmail; Mon, 13 Dec
 2021 13:54:56 -0800 (PST)
X-Received: by 2002:a5d:4448:: with SMTP id x8mr1320262wrr.508.1639432496321;
        Mon, 13 Dec 2021 13:54:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432496; cv=none;
        d=google.com; s=arc-20160816;
        b=jJFq7JtnMhLcIbZdiBY1t4LdFE58G7ksu2gZFL9NwF685HYSfGTGIO7h5T4TZTmkdz
         MQUpVWu3+AahVmleAY1UFlcqsswUv7PxihSRh8Ua3K68cIBmo9YscUda03M1o1dFcsow
         lAONZCM18i3WQxUqnzOcvzZa9qw2NRwBvBoXYoJW4h3jYajdNGB5qD1FdG+4icFFWP0n
         yiOuU6WlohJ/2Hdkf77TOBFqCRSESxyCy3HpUzoU8PKOIeT5uLetSUL7tnqwTDvs7K54
         Tt4+9JL2pSSz+D1yvpxxDN2V2rJcD+xO0l24Y290PHeEFQZRKsI+XoTxwBJGCBkfk5my
         GYuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CYiuCpANmF2hofVD+qkF0AskHe4DKzJGyvoujTMdBZA=;
        b=cA1vXxHinTYgrbY/D6/Viy2HEIlFyE2AXNTYXnieyGu0lWiMceODAMOoNCrKYjDTcC
         kW7s0enSEXxeQ0bS6uT4c38jThvF+SaX05pb8Pevzlu6g+B9iB7KL7k/qBkbaQnn3n3k
         llB+sA3RKFZhnrPq9Sz9rLAsXgjzYMmETzSzheBvNlg01fw4A2XeFjOktkpDB4sCDqE4
         5Zci3KUOsMEklDn1uCUcQyfj5NmRLH0bpAoWppLGuQOOEcjm1a+dUeuiI4OP6X2otT1X
         CZF4cu2WuLcdqW/pO1TdEku3/SN7giV9J4uWAE5oz3UkFrFMZCdbzzYu5m1JbWSZSWXV
         NuIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=o4YA6eJp;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id o17si45462wms.2.2021.12.13.13.54.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:54:56 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH mm v3 29/38] kasan, vmalloc: add vmalloc tagging for HW_TAGS
Date: Mon, 13 Dec 2021 22:54:25 +0100
Message-Id: <af3819749624603ed5cb0cbd869d5e4b3ed116b3.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=o4YA6eJp;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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
 mm/kasan/hw_tags.c    | 91 +++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/shadow.c     | 10 ++++-
 mm/vmalloc.c          | 34 +++++++++++++---
 5 files changed, 163 insertions(+), 12 deletions(-)

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
index 76cf2b6229c7..de564a6187e1 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -192,6 +192,97 @@ void __init kasan_init_hw_tags(void)
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
+	/* Skip unpoisoning and assigning a pointer tag for non-VM_ALLOC
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
index 9a6862e274df..4171778922cc 100644
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
+	mem = kasan_unpoison_vmalloc(mem, size, KASAN_VMALLOC_NONE);
 
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
+							KASAN_VMALLOC_NONE);
 
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
@@ -3054,6 +3067,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 {
 	struct vm_struct *area;
 	void *addr;
+	kasan_vmalloc_flags_t kasan_flags;
 	unsigned long real_size = size;
 	unsigned long real_align = align;
 	unsigned int shift = PAGE_SHIFT;
@@ -3115,8 +3129,15 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	/*
 	 * Mark the pages for VM_ALLOC mappings as accessible after they were
 	 * mapped in.
+	 * The init condition should match the one in post_alloc_hook()
+	 * (except for the should_skip_init() check) to make sure that memory
+	 * is initialized under the same conditions regardless of the enabled
+	 * KASAN mode.
 	 */
-	addr = kasan_unpoison_vmalloc(addr, real_size);
+	kasan_flags = KASAN_VMALLOC_VM_ALLOC;
+	if (!want_init_on_free() && want_init_on_alloc(gfp_mask))
+		kasan_flags |= KASAN_VMALLOC_INIT;
+	addr = kasan_unpoison_vmalloc(addr, real_size, kasan_flags);
 
 	/*
 	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
@@ -3817,10 +3838,13 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
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
+							 KASAN_VMALLOC_NONE);
 
 	kfree(vas);
 	return vms;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/af3819749624603ed5cb0cbd869d5e4b3ed116b3.1639432170.git.andreyknvl%40google.com.

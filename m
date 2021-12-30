Return-Path: <kasan-dev+bncBAABBZEKXCHAMGQEQ4ZJZLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DD69481FB1
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:15:49 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id p19-20020a19f113000000b00425930cf042sf5112927lfh.22
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:15:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891748; cv=pass;
        d=google.com; s=arc-20160816;
        b=UucknklujjEcLuhXrmPWz75DdZjgIb5/FyjoSRw4fwypnfQ2kCJf2BnbvZLuPGjcA+
         sayV4KTvkjCKxjSXd0Ew8cn98y4wHe3tTVn712yQ+YmPbmGyWnvchR7BK7Tf22WzlnzB
         3jguKTnV2n+frk7mmjHC1uYLDIUCy4zrCdpfj0SNRGIi8sJrxIRoh9vSNFtbMhfZNFrM
         9YpLrQxDSeYcTIba0RRGtZhccvlgXnaPsoT5s4M4goz8kg6LhSquvPSZkPusCgbPIj2v
         PMooE4YHNhL9O5nH3dnhSZ/nhMGOY4MTvc61vFTgcoz03iVhEw+NT7C5HeHdbMY/QKuN
         uL1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xL1BrAY/vWxs5l/SKbKB6kmWIR7GM9zRcU3ZT5yZJuM=;
        b=kmXlHZIn8HjlnXigk4ko5WKIbVD70Rsfb7+Nit7ktP+zpjr2PeT2hkb5cV7gU199MI
         VoNN/P534RPEr9Wl80f0wj0LEPvbMMxFzZkxThaOJ/5tcqXjhXdSan93FG0sJesQhZQM
         PwsN8eMiQ5FnoUY7RP0/NysvXz9ObdoIWMvJuEqLREIj90fnG9u2lBRIVfaruHw4YWla
         z/jEzk0NoxdfwdBpWD5kPb7OSm36l29yddiBNMWrE+5rc9brMQq/c9s6AqKvv1Q+BzGP
         HmgS2xRo98ZyHga8tU43TefvwYYD6C8TsYP2V7lLFIZSuuHT2y9LKliysc3Uy6v7n1CQ
         zx4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bkAQ7uG6;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xL1BrAY/vWxs5l/SKbKB6kmWIR7GM9zRcU3ZT5yZJuM=;
        b=JiGYQNTDa1Yeffl1kg97vVEBcBtT0miavQkHs7dGUvJ9Yq82PtBpw4K9tKngUwSW29
         nJJfLkuktrI7WoTPDQqiP6I45wyymyT3RRu/81q5NCmCsmfHRyFDkDzggrMLy2IbDYXV
         tOwgAsRvIewDRIoUjfWEWsSb7raHZxQsJxZPgEgixM2fJ6c3jNK3TkEwSXkFSVLy3bsa
         L+XbKhs49uUqMzAgf9RBZoZEEQz/IzIaKcwKTwl2ut7WvsXbMA/p9sYsA7Ekm5mmBjoK
         oikSX3h4tuzkL/zz9W+bpDZHteLNS1I9GHXDgyCKE4mvOTRqw3aSRHxpD0R5zAr1duhn
         veDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xL1BrAY/vWxs5l/SKbKB6kmWIR7GM9zRcU3ZT5yZJuM=;
        b=Xi4egKMSGbSAy1ToOck7tfboT0J5IyR3DMEtJ6S/kzEX7KwTHBAWrvgrAOuSgjNRF1
         ZE8z3H1PJJ65i2AfGghN/oG5Uk3PF65bw4mCIXvCNFPoiIu3Akqe0v0T1KWycdjLvg8G
         nAP/K9td50mUf2N38tHx6ZqqL+vRP2fsVfwWKyEQVUSjYtNpCNuDbFbbYCkCX6/dfhyq
         /aQn0+ql7KHPQg33vRWq06297j+BZbb6rt3tHYcxV/OO1qbHOz7f6AS5YDtTgQ4xTXy0
         CZ409q7XDbfTZcU4DGm6wlniGE/SeY/8+ltxyDPjzb9a7shsvWqEt//RVxG8wlUEdJGn
         kcBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5320A7fKTOSmG2gRmt7Q6Pu9bnXzKyOAv/qkEp9NY8w4NA90chw/
	i+ixBX5WdsmHL9/i/Hjpx78=
X-Google-Smtp-Source: ABdhPJxjjO3YtJBDe0hZJAJ8rsqXPEbu6NJSDzz7tOCXTM0/8zX6KwJ7nx4Bd8ad9QL+iEK5iPwJ7g==
X-Received: by 2002:a05:6512:a93:: with SMTP id m19mr29057686lfu.105.1640891748786;
        Thu, 30 Dec 2021 11:15:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:454:: with SMTP id g20ls1929539ljg.1.gmail; Thu, 30
 Dec 2021 11:15:48 -0800 (PST)
X-Received: by 2002:a2e:a452:: with SMTP id v18mr18247463ljn.239.1640891747948;
        Thu, 30 Dec 2021 11:15:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891747; cv=none;
        d=google.com; s=arc-20160816;
        b=Z5YBKdRfmwV4VMX/Bn0WO7utj9qWBao2/nSYUmJiKYeU4+FO0Id7rz0JQqg5IkPwmy
         qhMq0pVpv28xDe9zM87yIu+PxvsT6U5vr6901GxP3Fi10uPcXZCuE9xCngIp4D1SVeIY
         g0wFkrJBa6sR/INMAs5wGZnf9JYYMZITCiZ+4XBHZ8falKAOuYsVMEhISG89gpRsvE2k
         FKyev8JKgDKsr/N3ihj4jAhe53sh+vfmlRMqdzQc5C5RuQyJf1jPCKfmsF7kpTrfPZi3
         +Qb+8wxZemDqwDApCoqyFVGz1x7TEpwwqOpxYdnDJMxs5zzfxZvxFMCFtcUw+L9RT1k2
         DZQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=v4y/HrL/D3rpYHd0Cjbf19I+NSq4uVOBniVw3UkTjFU=;
        b=CnnlNYtTPB7UO3zS4Dg3q0csAqaEtPrdir8aGIIwGMdZi9ln3CaV2aJTV9I0538sgf
         64oW6UcXR/EMatiKkew02oCIl+LHrB7ZlaCH84pLHKB8yaaArT+3F8xym1+UUuzBrCmz
         QNcLnc0RtMw/ybaWflG4DQYP11rinQtYMa7y55jcz3z1hjv6gj0xDeGpcLeKa9GRmO9y
         V/h4LZdUuKwv+t4Bq4cGve98teYkOKcv+JQrqSxs2Q19rRJyXOcfPv3/9BUhhDtmHl4l
         y8VqPM/HpED+eyO311G2KZL962HVX4Kx4aA01K1MwdYzQuy6t2mAt9AySwxiDKPnLnRV
         ts2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bkAQ7uG6;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id j15si898369lfg.9.2021.12.30.11.15.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:15:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH mm v5 30/39] kasan, vmalloc: add vmalloc tagging for HW_TAGS
Date: Thu, 30 Dec 2021 20:14:55 +0100
Message-Id: <bfccd0f13932bb0c36443da74e5ef5bf5f7335a1.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=bkAQ7uG6;       spf=pass
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
index bcf973a54737..0f0c9a6a4b11 100644
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
@@ -3063,6 +3070,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 {
 	struct vm_struct *area;
 	void *ret;
+	kasan_vmalloc_flags_t kasan_flags;
 	unsigned long real_size = size;
 	unsigned long real_align = align;
 	unsigned int shift = PAGE_SHIFT;
@@ -3115,21 +3123,39 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
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
@@ -3837,10 +3863,13 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bfccd0f13932bb0c36443da74e5ef5bf5f7335a1.1640891329.git.andreyknvl%40google.com.

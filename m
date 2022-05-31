Return-Path: <kasan-dev+bncBAABBPHP3CKAMGQEA7SYIKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id AA4AF53942F
	for <lists+kasan-dev@lfdr.de>; Tue, 31 May 2022 17:43:57 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id bu3-20020a056512168300b0047791fb1d68sf6882001lfb.23
        for <lists+kasan-dev@lfdr.de>; Tue, 31 May 2022 08:43:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654011837; cv=pass;
        d=google.com; s=arc-20160816;
        b=QhIQl1n/at8M88cENaAXEBREZ74ecDrUccATR4toqsNBA8MZTQ1FBXH/XDHJPlQGWV
         i9TVTiOsbwBLJF0R6Y347uaoOVNNoq0f4XFygThWGsQgD0clwZ1bSSRLiNK7F4wT9WzK
         lS4+yA33BXM8Mk0Zy63dDF7l1iPrqWV9iSME0ZMKwValTidPoNjqva1nzFJ/Z1VPmUHJ
         EZvM/7c766sHe6b89sUicec8b66t7OqV3LqxhIRi0uhERJ6xWIE9LEKH3rkhySJ+zKa2
         qQzLxUU1iAUiedZPZs630ahzyqiLvKVGJF1GW6tXMUuYbMN/4CKK0pQxHkdURpJj16kA
         j39A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PT6K/12HnThObDvXv/++9WjDHBM8i45zqxUDzATtWEs=;
        b=IsI8P+pVrsovGephdBifPgW4LwcupM8EZy0FZzauUxJ5ze0mM8o34M6hZXbakmuxJN
         rM7JC1LD7CGO7Ge9knyoS3xhsjzHMwbxJDgNr934ZX+vegI2khXjRbXTH6iBfiqe2HYA
         pHlS6gfW5q0sd9RgQQbbhRHAnSmfAQSZpYMuX9jIbs/nIrTkkxmlRyud4VTC/eJJYcPp
         1SSAON2cgZigzdqiu1E+ekDUI+schOP99w+ogJRiGqQFTOKVhZ5/ocK0egBxKdCZKGt3
         oWYZ/Kn9L7fnHUXlXDbjUE2UCXGT+iPfIwsBd1PjYG3BOMp1k+F0yBc387c2qH2N0mv3
         Ej/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=c59EypVa;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PT6K/12HnThObDvXv/++9WjDHBM8i45zqxUDzATtWEs=;
        b=pbDInFOH8tKkCJiXw95VME7vUaM02X5mRZyTR2YzMugD/n6UcuLeJYTjRx+Ky+Aeji
         IFrAIS9oCG8KANtLqpF51E3H6YA87kkP5qmBlwclGUrmRsVNpgn/Zi87c3cf2ywRnQsx
         DEjRBnKSkdkRKjgsSqDRsgEL7u2eMZc6NIGRUmDK0nRwbWeproQ8020+mvEra3oDUgLu
         UZKlTOEnSc3phpVvzuuXDu1ubclGMCYtmvShaG3euYNIhypC7na99iIDvR8dHxPXw20F
         rK8n7aXcKSbRaNAIlpQYXJS5jp21cgt7qYC4y22Mt72bupC7Wqn9/IhFJVm++3OzQK3O
         9k1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PT6K/12HnThObDvXv/++9WjDHBM8i45zqxUDzATtWEs=;
        b=QVFLpXECcdzJ54qaX9JpyBQG7OZRlEpM4W3XHBTKd9LZSAxyC51iboZnfFD3yAK2jO
         ctyYBmAIX20ypB9hfxAwdSx/H9ntZvhjXZ1WKNnw/BjBDbRp+OLGX0n63vizJa46Ck2W
         r44b/srMtZ9PXiv0jRcP2nXtsJnzQhB2KTNeVZqA7uJ0Z1vZarq9aWFCG7rI6uFliOhm
         QM9jNrQOCbw7kl1w7gbH1mL4KLGSa1EG30ojBt23qnhSbMGaOgmrbHcxurJK4lajmbxA
         ZTXJMykuYT+G7iYqSZIlN7CGFfmtuz51Dm+PwsoHeahA0KG46wzcZQzp4x+HzRxb2Xau
         jFLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533G/qpKbSiyvqMTT4AlwR3PPwpup3P4A77xsgOjRrzGaFbYKK3N
	siLmW2QHiL8EHUVz3WILoI0=
X-Google-Smtp-Source: ABdhPJxhEld/3CSy+J4XhwrhEbwXtgZAREHbAuZbxEjjrwjbe2JVECGpf6w4m5H653Vnk4MKQouwyg==
X-Received: by 2002:a05:6512:110e:b0:477:cb5e:651c with SMTP id l14-20020a056512110e00b00477cb5e651cmr41214208lfg.180.1654011836880;
        Tue, 31 May 2022 08:43:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als207564lfa.2.gmail; Tue, 31 May 2022
 08:43:56 -0700 (PDT)
X-Received: by 2002:a05:6512:68c:b0:478:70ed:b701 with SMTP id t12-20020a056512068c00b0047870edb701mr32423176lfe.130.1654011836035;
        Tue, 31 May 2022 08:43:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654011836; cv=none;
        d=google.com; s=arc-20160816;
        b=wo16XMNtLgmVqCQAvKlz2X7EJf+lf/EUW/AHXlsPCOtjfBZaTEZdjO8DKbTCFt1p8n
         i5722i7MERvVo9LvtNtKOYe4ZGWDV/00C4mNalj99ej6q0NLTBAGks0aeCzKPOlQNwGA
         INCD+MvfIN/vlkpVLDwey7MKNcGpgK6EqqJoJ4MiiKX5V08Jfuda4a+K7eRQTvL3PbFu
         QDNiWREVqQcCfAR7FhX2K1xLPSNoyG5JVAiFvtauFVDQ4itCzN+EZhvfdv/gwN/TUtnb
         3rbFC7uN1X7ODTX+s1hbFq9IUvZfP4DJxWidJtta53R67JAMuTNczgouvNtJJENhunL2
         EaKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=aKpEOAmZCRxRoXVhww36jQag5lkjQ3WmgRmPB/KuwNI=;
        b=vFmqQeVVaz/ov5sxkonB4osAfVkX6rcHNsGkvvLhVyCoWkOGdV1fODN4dmqU1AByuP
         BNJfJzD3f9d1ch8RBq1I3gPwkr2WLSv+/LoClzIxaQmXxVlrufObTDEITG+eOKGoYdPe
         14tlxE1ddtTCoYuKpoOFrlP9DMcRlgkPMAj6mG05wW4fNI+m828c9FztwGSqQHsiblFv
         ++iwyoN1Yl0kHX2octVU8HtOeW4lxGpR+EemQJaiEuWAgfw0x6w4MuteAr7TtA3XnW/x
         u0ZsfN533aCLOf9IQnKyeGzU1YnH2yv5BMsFtq8BGKdfr648GOWWMVKFEtpMj7ECp3DP
         IOJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=c59EypVa;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id g7-20020a056512118700b00472587043edsi659296lfr.1.2022.05.31.08.43.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 31 May 2022 08:43:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 3/3] kasan: fix zeroing vmalloc memory with HW_TAGS
Date: Tue, 31 May 2022 17:43:50 +0200
Message-Id: <bbc30451228f670abeaf1b8aad678b9f6dda4ad3.1654011120.git.andreyknvl@google.com>
In-Reply-To: <4c76a95aff79723de76df146a10888a5a9196faf.1654011120.git.andreyknvl@google.com>
References: <4c76a95aff79723de76df146a10888a5a9196faf.1654011120.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=c59EypVa;       spf=pass
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

HW_TAGS KASAN skips zeroing page_alloc allocations backing vmalloc
mappings via __GFP_SKIP_ZERO. Instead, these pages are zeroed via
kasan_unpoison_vmalloc() by passing the KASAN_VMALLOC_INIT flag.

The problem is that __kasan_unpoison_vmalloc() does not zero pages
when either kasan_vmalloc_enabled() or is_vmalloc_or_module_addr() fail.

Thus:

1. Change __vmalloc_node_range() to only set KASAN_VMALLOC_INIT when
   __GFP_SKIP_ZERO is set.

2. Change __kasan_unpoison_vmalloc() to always zero pages when the
   KASAN_VMALLOC_INIT flag is set.

3. Add WARN_ON() asserts to check that KASAN_VMALLOC_INIT cannot be set
   in other early return paths of __kasan_unpoison_vmalloc().

Also clean up the comment in __kasan_unpoison_vmalloc.

Fixes: 23689e91fb22 ("kasan, vmalloc: add vmalloc tagging for HW_TAGS")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/hw_tags.c | 30 ++++++++++++++++++++++--------
 mm/vmalloc.c       | 10 +++++-----
 2 files changed, 27 insertions(+), 13 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9e1b6544bfa8..c0ec01eadf20 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -263,21 +263,31 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	u8 tag;
 	unsigned long redzone_start, redzone_size;
 
-	if (!kasan_vmalloc_enabled())
-		return (void *)start;
+	if (!kasan_vmalloc_enabled() || !is_vmalloc_or_module_addr(start)) {
+		struct page *page;
+		const void *addr;
+
+		/* Initialize memory if required. */
+
+		if (!(flags & KASAN_VMALLOC_INIT))
+			return (void *)start;
+
+		for (addr = start; addr < start + size; addr += PAGE_SIZE) {
+			page = virt_to_page(addr);
+			clear_highpage_tagged(page);
+		}
 
-	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
+	}
 
 	/*
-	 * Skip unpoisoning and assigning a pointer tag for non-VM_ALLOC
-	 * mappings as:
+	 * Don't tag non-VM_ALLOC mappings, as:
 	 *
 	 * 1. Unlike the software KASAN modes, hardware tag-based KASAN only
 	 *    supports tagging physical memory. Therefore, it can only tag a
 	 *    single mapping of normal physical pages.
 	 * 2. Hardware tag-based KASAN can only tag memory mapped with special
-	 *    mapping protection bits, see arch_vmalloc_pgprot_modify().
+	 *    mapping protection bits, see arch_vmap_pgprot_tagged().
 	 *    As non-VM_ALLOC mappings can be mapped outside of vmalloc code,
 	 *    providing these bits would require tracking all non-VM_ALLOC
 	 *    mappers.
@@ -289,15 +299,19 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	 *
 	 * For non-VM_ALLOC allocations, page_alloc memory is tagged as usual.
 	 */
-	if (!(flags & KASAN_VMALLOC_VM_ALLOC))
+	if (!(flags & KASAN_VMALLOC_VM_ALLOC)) {
+		WARN_ON(flags & KASAN_VMALLOC_INIT);
 		return (void *)start;
+	}
 
 	/*
 	 * Don't tag executable memory.
 	 * The kernel doesn't tolerate having the PC register tagged.
 	 */
-	if (!(flags & KASAN_VMALLOC_PROT_NORMAL))
+	if (!(flags & KASAN_VMALLOC_PROT_NORMAL)) {
+		WARN_ON(flags & KASAN_VMALLOC_INIT);
 		return (void *)start;
+	}
 
 	tag = kasan_random_tag();
 	start = set_tag(start, tag);
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 07db42455dd4..0adf4aa1514d 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3168,15 +3168,15 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 
 	/*
 	 * Mark the pages as accessible, now that they are mapped.
-	 * The init condition should match the one in post_alloc_hook()
-	 * (except for the should_skip_init() check) to make sure that memory
-	 * is initialized under the same conditions regardless of the enabled
-	 * KASAN mode.
+	 * The condition for setting KASAN_VMALLOC_INIT should complement the
+	 * one in post_alloc_hook() with regards to the __GFP_SKIP_ZERO check
+	 * to make sure that memory is initialized under the same conditions.
 	 * Tag-based KASAN modes only assign tags to normal non-executable
 	 * allocations, see __kasan_unpoison_vmalloc().
 	 */
 	kasan_flags |= KASAN_VMALLOC_VM_ALLOC;
-	if (!want_init_on_free() && want_init_on_alloc(gfp_mask))
+	if (!want_init_on_free() && want_init_on_alloc(gfp_mask) &&
+	    (gfp_mask & __GFP_SKIP_ZERO))
 		kasan_flags |= KASAN_VMALLOC_INIT;
 	/* KASAN_VMALLOC_PROT_NORMAL already set if required. */
 	area->addr = kasan_unpoison_vmalloc(area->addr, real_size, kasan_flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bbc30451228f670abeaf1b8aad678b9f6dda4ad3.1654011120.git.andreyknvl%40google.com.

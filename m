Return-Path: <kasan-dev+bncBAABBDHTRCKQMGQEMOOXFKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 26EC55453F6
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 20:18:53 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id ay28-20020a05600c1e1c00b0039c5cbe76c1sf37546wmb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 11:18:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654798732; cv=pass;
        d=google.com; s=arc-20160816;
        b=IYvv3VtwFrwLhjF1LQV5l7XgY6r3ZaWLp6TSO1vg85936CacwVQ3JLaHEPJVUjjdvv
         YyJ2c5hcCtkihHhTGjDNUanKfO2S0alNVpIdCXH29aYzxXS5p+L/Z4LV0Qkhey7aWE7Y
         LovYyroHvxDJW3CxtnnvtB/fHT+XzbYBHzlT6lq5YgK6PGxwFH1x0T0fpDgZSNug0Tqc
         LMdRtQ/bLuDVhRF9zSIL3FOYO7q7pbm4IBgm1nHZOe7/wnFgVWVS3SIJkrBSAWf2NTYv
         7OJG3QVELdhI+6ufyzmxR/6Ut/c/pqS3CSMWUyja5qY0HBxvcOAitmoaa9wKf9gtvEDT
         yffw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OOJovmzkvbqcbc1TAxj9eAJZebliUla3CBMDF65I/W4=;
        b=KPZVMzFtXvmXGBv1xGuf3YsPG9OTVPORcEgkYnzN59U9HG6wWpfeoFanX3U2Ho4dgp
         2dIP+48qMcNZQ3VTqPA4g24DCx0ZzKHi8NFd0Q0rbQxy8S4pQ0KKqin6nceaUwNZBW6K
         SJ9GvEqvbHoZXvA5ko2dfLrmk5hryYVNBgQExfEf6eg5mGVsfp4H66Fqbl42jgSUJu8k
         FOExDswGQJAZRGCfF9fi1lyfwvB26s28y2Hqb2AFLb7QqdNXqlKJjWXHzxPwmtUu3Ii4
         LV0D3oJOOumeK7pxnNiAf6tEk1MdMWNQVJRD7vk3+6XiIMRvc54+ZHpLWpVlTcJnQE8W
         R2Vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ubs0Oifr;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OOJovmzkvbqcbc1TAxj9eAJZebliUla3CBMDF65I/W4=;
        b=VsP9fvn4c8azdYrLITq6L+Rl5J9PhDBtC6VAeXr1aeTAYgqgDUZdv+yo5dL3YTG4U+
         WKOgnz0meCNo44JpnEPjTnRJLBg4R6QdSUOxkuWxA+V3wknPQbi1DckmyllpGANlBytM
         bvViPHo83MarDNTa2Mqy7q9kSVu1ZDyv3SqWcjXtz4tjtAS/IkwJx/0Gf/WTTGrhjNp3
         /vfZHSNgAO8/t3+B+3MblsyaXckfzRMe6wJEhERZNebzfTK2q9avxzTSyvgzuJJIzUdf
         A2GehgK/VOrcclPp4uZGPcBQRpy7qPcbTEkQDtRddEJ6sL3/wxPd2ZEdbBdY8iqkcYam
         bTEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OOJovmzkvbqcbc1TAxj9eAJZebliUla3CBMDF65I/W4=;
        b=vYRzVKQwKCuJ7TVGFDD5KgsZ1uTXpL1PgEAJfYQs07pEpBWQgpcuhjRBxYX451XInx
         tOdywfXS6uymyHWztEdG42X0st5wKAcKj9iFaLX1aFdVPUlTbMXBGHU/VSOQg7sboKGi
         +30E2YCrJQf0mdr54yud7X2Gy4w8D/RFdIfSPOf7sOouJwNlObrw58RUvRMABFl6uhgi
         Z1/Unyrv3KFbym9FK49417jOVHEFVOlQqcdkAgj29Z/o9WOCkBDl2H0nuJgkV14n/Wla
         PPGWOSRBwtc54TshF5nK4zDGbzMW7OkRkFigRxWUcwqQDsRjzcD/Mlj3IXrzLoEZHstG
         1Fig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530o91OBU3ZTqTn/uWUUTbj7i9QNKMl7bdDI8gtsM43xN4HaodrD
	0oabsccAAa+fWJC23M6Pc4k=
X-Google-Smtp-Source: ABdhPJzbwq7g77Mp/GCjBjrtx0VTyMvqriDjzJDLZXdCNjz0UCrbrgwpjL4nu5/7WMW/evg2ovDrdw==
X-Received: by 2002:a05:6000:1568:b0:219:af0c:48b0 with SMTP id 8-20020a056000156800b00219af0c48b0mr6325748wrz.140.1654798732650;
        Thu, 09 Jun 2022 11:18:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:648e:0:b0:217:c8b4:52e3 with SMTP id o14-20020a5d648e000000b00217c8b452e3ls2795562wri.1.gmail;
 Thu, 09 Jun 2022 11:18:51 -0700 (PDT)
X-Received: by 2002:a5d:4141:0:b0:210:3de0:359f with SMTP id c1-20020a5d4141000000b002103de0359fmr39348370wrq.441.1654798731927;
        Thu, 09 Jun 2022 11:18:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654798731; cv=none;
        d=google.com; s=arc-20160816;
        b=BjwcQSnZ74y+0kT+NencaMySZoTDvGP3d7XHfaj/JP1mwvNJQwnZL36J+f+xQ2ThHn
         xhKlZIk2o/NtQbTgLLfMEvIGozw5Jt8zd2OlGHpz76FmbhXkgOX9hAeGNlccFGi5Udq1
         VKAbSGCMUIfY0q7InV7WNXBcK97oomlFM+ug+qPy+0mEjyRLNMy+auJ02ug6AfvrZqNl
         f8tt0rlRtQDsUQw5nKZJM6QzACNm5GKqcpgxKq+JS/oSOOge15YOKqq54QEUu3OH9Jtr
         IQAIWvIVciNckrfq89Kxm+uBl2a0cZTJ7roIcZ8iXgLuPIBJxoPiVGQWswN9ClDbDych
         QYDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eJy0WE1RZ6sxBZ/XENlV0bykPV6S6KO6JYi7Cn8ktdA=;
        b=RatNWyuRFwfPtpdR+zXMrbMGq8oTLrK4tCXReA0qLXeR688vpDxrjbAEkgLriDC9XN
         CTwK3HjTom8O/mapuDA7ICPamrSrITMSHuNieIVwok5Vz730CM5e0lsgclZtCXwFvSxi
         WlnVo+vsnk1ySYRMBwKQvCIBgWQyJACy0BZf2LJrKl3St7PztdZd3Z8O2kSo+2kAEKlM
         GBNNLuBgXW4uA5XNoQNKZSU5tAY3JAorhqNUnDLYH8EmPpvxbqfLfuAKs0KGHVQtVBJp
         EV5P4DCgJfxBo9mellhhY6b2LE+flGpN1x9a0qbDntZ46d/mkkm6E/Qa0Kqz3JwC3vSk
         +1gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ubs0Oifr;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id n21-20020a05600c3b9500b0039c4d96e9efsi101520wms.1.2022.06.09.11.18.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 09 Jun 2022 11:18:51 -0700 (PDT)
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
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 3/3] kasan: fix zeroing vmalloc memory with HW_TAGS
Date: Thu,  9 Jun 2022 20:18:47 +0200
Message-Id: <4bc503537efdc539ffc3f461c1b70162eea31cf6.1654798516.git.andreyknvl@google.com>
In-Reply-To: <1ecaffc0a9c1404d4d7cf52efe0b2dc8a0c681d8.1654798516.git.andreyknvl@google.com>
References: <1ecaffc0a9c1404d4d7cf52efe0b2dc8a0c681d8.1654798516.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ubs0Oifr;       spf=pass
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

Changes v1->v2:
- Add init_vmalloc_pages() helper.
---
 mm/kasan/hw_tags.c | 32 +++++++++++++++++++++++---------
 mm/vmalloc.c       | 10 +++++-----
 2 files changed, 28 insertions(+), 14 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9e1b6544bfa8..9ad8eff71b28 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -257,27 +257,37 @@ static void unpoison_vmalloc_pages(const void *addr, u8 tag)
 	}
 }
 
+static void init_vmalloc_pages(const void *start, unsigned long size)
+{
+	const void *addr;
+
+	for (addr = start; addr < start + size; addr += PAGE_SIZE) {
+		struct page *page = virt_to_page(addr);
+
+		clear_highpage_kasan_tagged(page);
+	}
+}
+
 void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 				kasan_vmalloc_flags_t flags)
 {
 	u8 tag;
 	unsigned long redzone_start, redzone_size;
 
-	if (!kasan_vmalloc_enabled())
-		return (void *)start;
-
-	if (!is_vmalloc_or_module_addr(start))
+	if (!kasan_vmalloc_enabled() || !is_vmalloc_or_module_addr(start)) {
+		if (flags & KASAN_VMALLOC_INIT)
+			init_vmalloc_pages(start, size);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4bc503537efdc539ffc3f461c1b70162eea31cf6.1654798516.git.andreyknvl%40google.com.

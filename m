Return-Path: <kasan-dev+bncBAABBPMJXKGQMGQEJ5HNJAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id E0AAD46AACE
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:46:37 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id k10-20020ac2456a000000b0041bd7b22c6fsf2235978lfm.21
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:46:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827197; cv=pass;
        d=google.com; s=arc-20160816;
        b=HE2msx5UaA40Lzv05or8F5748kNe8lLM5nySyHpvo2wJu0+HGXh4RVD84LiUlCyjbO
         Ntpgy5PwFVrRyZAGRteN7B0F/7qDXHDubZGvmNb/Yz+nIY1+CtqA9tHLwHtzkbgVmPa7
         sju/+1wb7ztUIgRm/SpgV5DS2WOU65+S167dhWiiIgwW2ri7rn4yEa9paXbXf+tLYiqT
         RHtYLnY4IvRfFxqN+jUKgLnKrmcY3ym+EPNyiaH+vDcu7QZtzPt8Mbdx+KGXwcWPxhTX
         K2V/2Qu8q62NFsNUcLIGBiKgx1QNhVlDHPhr3H+buD/AotRMl6KTf0ipTDc6dLUU5qKa
         pXSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xiINgbcuqeGZjA3vpQbg9zZFs+rxgQV9Z/EgW45Doec=;
        b=TTehstAtqAnRNjxQ5qG6W/VvLJZq47nsYruYph3YmqC0BN/lJ+UKIBjL9fWsbaIB5K
         YsGMM7W63YNxu9qnnMRle0gWb5d/40P6YbeJ1xF/sXGDiqqwLqCkqaAPHHuNgSoUpsMo
         D1KAI5eks9gYfLNGHlPz3UdLGpLGW2R1h1N0Ftol+F6BF5eLmRGxELEZV7hDLKn8lj/Y
         6V3eK8R+VStbDqIN1D7Ler6i779PJk3QyyVMwrHRYOmFAlMT9hDWLVN8x+15KDSqTZ85
         d+x8RmWZondEdxff0x6hXCVGuSx5cHcMIroAzGIf0SEcZOZMPslij2CeUadeZf75+oB7
         SkWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=diPSXiCf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xiINgbcuqeGZjA3vpQbg9zZFs+rxgQV9Z/EgW45Doec=;
        b=TsA1F8rSigblz9T51DztQLEz6dpsQuuf+Xxt+CYRQJYMRml3+sRnosE0fcqnUm5xVp
         oyVEeqZ6GBreOAQwILxZtvtYzHeTKUrfFrpt3QZJokGeTC7vEsRvEnX797YBYb/rVVE6
         hdEgkAjo8rbhZS0CvJpt14wo7qVePakhLaUHwSVP5ccO+V7iGizaz02ekEMZQ/th5NCc
         QB8Or2XXEBzpdRcjGif+5kIDQWqawBA7tehLHb3uxW/jsdA0qLEcK/AhaeG+aLDY4251
         ViBtUBGrQ/m1MG9pUZj96gJV1z6XANIncwGdzN4Y10v17+z0q7Y5sHZPY5RZnxN2aANC
         Cdxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xiINgbcuqeGZjA3vpQbg9zZFs+rxgQV9Z/EgW45Doec=;
        b=mX42lPKwsvFw3Vcs1cxm43uooprmxbTymieZ752B8jfDpGJDuv1fTpvozqKrDd/klW
         1JTLs0wRj95puP57fraR0kmRFrb/FhJZvYuUHKH4Wzwe8yyg4ESb3gADWIgqNCWqSHkd
         ok98U8kzBy+zSAMUQc+KEV7+HFe29h43hUUMgNkZddTCcQZdOy+y3hU5jR0NU2bz/DaJ
         Ub5opvw76XmYuPqt78XNLCzM75KzKrCIhNcX/oKzYrF854+bIiEWvQ1LcAEWxYOfDDhw
         DTxRBzH0FAti+YBLAzyYgMQxuMMQifjkLYmmQDMgokXK2YlFqG7woV3pDw0tu6Odz2yD
         eEmg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531IkHAdjGEacRJyHEhvuDwNEJXjNjyPvNSwKlHf1lUnf80XZTQW
	j5TLhHy4yw8LZEA8PV3ZbME=
X-Google-Smtp-Source: ABdhPJxe3UIxSlGOctmkOQZpgHZ2te74Ybj8HpoXtuUbz3AXG25vkTdr4UXc5kTeVRjx7IY4vQIc6w==
X-Received: by 2002:a19:c797:: with SMTP id x145mr36126078lff.533.1638827197467;
        Mon, 06 Dec 2021 13:46:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls1927411lfv.1.gmail; Mon,
 06 Dec 2021 13:46:36 -0800 (PST)
X-Received: by 2002:a05:6512:3e20:: with SMTP id i32mr37972831lfv.673.1638827196749;
        Mon, 06 Dec 2021 13:46:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827196; cv=none;
        d=google.com; s=arc-20160816;
        b=QVyJJOVcr6IzS5dUBUfnPzjtVe81S37RR+jg0neeF3nhZ1a+HSYVwVyW1e9y7Kxzno
         NfleXpxDyjDi7Niq7BDPO8IGhk7s5xgZd65+09G1btA5BSjrL+gn381s52LYqQBY/5D8
         fkhzRhpWOi78dJovYZn9J8kQ7yP9+Drbryu2FPHgrWrdKvd/+HQG5zy6jbNcXfwfSbg3
         5c4XP5KSX0dmMBcycwX92B0fUl4Tl2vpBGCSA+l8HKysG85sSNMrm0jhX/LhcuVugLKC
         XF9o4vaXSbw74Yd7fVTMcheZ61WIRxOKTXXhmLX50NbPKGkFbQpkmLxg1hIONU7/JwxB
         t0TQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Psw3MnbE/X6is67FfglkhKemZX8bH5/LHATd5xYq6jA=;
        b=arJjHBCqRz+BHwgO3yIzhtQW5eB+WTMaLm5Qdlora9PJnGyBfyXtgfv/5URkAyOZX2
         VB4sLT4tQDF/9/4sPKv2X5J+vHvWcCtsbRRQv1EFhYtx30Em6CsCcruVTZLolK9e1U8c
         2EGsGf4gw/z+gzqpUgqpi5EquiygHmbfODkameiPjad+SBm6IccQVDuZ4/OstQj0gTG1
         lZC3kXP15ASitcXGKwBRohB6XOrNiXzOaCuJUdfbBmt9M/mwy7Sxfzj52ms7leImtSBb
         qtkmq6muxIbMlaKvKEYqnIgcmJWnFufaaovm5DbbvC8FsBh0xsHZfBJaQLjQjiXQOpnq
         iPaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=diPSXiCf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id d18si752966lfg.3.2021.12.06.13.46.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:46:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
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
Subject: [PATCH v2 26/34] kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
Date: Mon,  6 Dec 2021 22:44:03 +0100
Message-Id: <694654c29f4dddb3e927c264f71d032df6d906cd.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=diPSXiCf;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

This patch adds a new GFP flag __GFP_SKIP_KASAN_UNPOISON that allows
skipping KASAN poisoning for page_alloc allocations. The flag is only
effective with HW_TAGS KASAN.

This flag will be used by vmalloc code for page_alloc allocations
backing vmalloc() mappings in a following patch. The reason to skip
KASAN poisoning for these pages in page_alloc is because vmalloc code
will be poisoning them instead.

This patch also rewords the comment for __GFP_SKIP_KASAN_POISON.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/gfp.h | 18 +++++++++++-------
 mm/page_alloc.c     | 24 +++++++++++++++++-------
 2 files changed, 28 insertions(+), 14 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index dddd7597689f..8a3083d4cbbe 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -54,9 +54,10 @@ struct vm_area_struct;
 #define ___GFP_THISNODE		0x200000u
 #define ___GFP_ACCOUNT		0x400000u
 #define ___GFP_ZEROTAGS		0x800000u
-#define ___GFP_SKIP_KASAN_POISON	0x1000000u
+#define ___GFP_SKIP_KASAN_UNPOISON	0x1000000u
+#define ___GFP_SKIP_KASAN_POISON	0x2000000u
 #ifdef CONFIG_LOCKDEP
-#define ___GFP_NOLOCKDEP	0x2000000u
+#define ___GFP_NOLOCKDEP	0x4000000u
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
@@ -235,21 +236,24 @@ struct vm_area_struct;
  * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the memory itself
  * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
  *
- * %__GFP_SKIP_KASAN_POISON returns a page which does not need to be poisoned
- * on deallocation. Typically used for userspace pages. Currently only has an
- * effect in HW tags mode.
+ * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page allocation.
+ * Only effective in HW_TAGS mode.
+ *
+ * %__GFP_SKIP_KASAN_POISON makes KASAN skip poisoning on page deallocation.
+ * Typically, used for userspace pages. Only effective in HW_TAGS mode.
  */
 #define __GFP_NOWARN	((__force gfp_t)___GFP_NOWARN)
 #define __GFP_COMP	((__force gfp_t)___GFP_COMP)
 #define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)
 #define __GFP_ZEROTAGS	((__force gfp_t)___GFP_ZEROTAGS)
-#define __GFP_SKIP_KASAN_POISON	((__force gfp_t)___GFP_SKIP_KASAN_POISON)
+#define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
+#define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
 
 /* Disable lockdep for GFP context tracking */
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (25 + IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
 /**
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 73e6500c9767..7065d0e763e9 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2380,6 +2380,21 @@ static bool check_new_pages(struct page *page, unsigned int order)
 	return false;
 }
 
+static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
+{
+	/* Don't skip if a software KASAN mode is enabled. */
+	if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS))
+		return false;
+
+	/*
+	 * For hardware tag-based KASAN, skip if either:
+	 *
+	 * 1. Memory tags have already been cleared via tag_clear_highpage().
+	 * 2. Skipping has been requested via __GFP_SKIP_KASAN_UNPOISON.
+	 */
+	return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
+}
+
 inline void post_alloc_hook(struct page *page, unsigned int order,
 				gfp_t gfp_flags)
 {
@@ -2419,13 +2434,8 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		/* Note that memory is already initialized by the loop above. */
 		init = false;
 	}
-	/*
-	 * If either a software KASAN mode is enabled, or,
-	 * in the case of hardware tag-based KASAN,
-	 * if memory tags have not been cleared via tag_clear_highpage().
-	 */
-	if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS) || !init_tags) {
-		/* Mark shadow memory or set memory tags. */
+	if (!should_skip_kasan_unpoison(gfp_flags, init_tags)) {
+		/* Unpoison shadow memory or set memory tags. */
 		kasan_unpoison_pages(page, order, init);
 
 		/* Note that memory is already initialized by KASAN. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/694654c29f4dddb3e927c264f71d032df6d906cd.1638825394.git.andreyknvl%40google.com.

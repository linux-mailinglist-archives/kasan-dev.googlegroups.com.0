Return-Path: <kasan-dev+bncBCCMH5WKTMGRB6WUVLDAMGQEPZQJ74Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C2BBB7DB0F
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:32:59 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-62ed2de7ee8sf5973219a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:32:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758112379; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jh0MmF3mxZh8ILfpC/GavRCPY7Xv6iPlQqNYK2Rpd+XaywyrNhiuiLv0eyTM/HXFcK
         pWik9ZaLHoMUhzR69MFaqQGl4s42y7IPdhlEDIGG3G74/KXOMMM08ucGYGL+2mu5MXTB
         L8+3VuYr62xVGXxQV0jEOb2+NkqYt5fj6upZ3iliMpg/JjylRDX/Z0eKd7QHCFWTtSN5
         9riucqcDPzkbbE6IbgYC3oq5R3Vu2KHE6NBvplIiPXEiCGlenB50qXSm08RG8fzSJ9DI
         kzF7SUHI/VB+wfjMvoN+pYiiOJIYjoKFJowipmxcMGhys7uSfM4HlTYtszg5w7tVb0Rk
         11YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=SGQ/XKLb12QWNubJ1odI5zNO+qknl1aEancyG107+jo=;
        fh=b2J2zIPwlzSfD8XlIL4Ej5wQTwNJ9mYTClHCeXxzCK0=;
        b=JwNC4dW5Qtc9pjn2eDUEkWRpx9VV7zbM4bs4qcw2oXPYbcVUPJgeo/9sdE/Clv78VF
         IkyYh72Fu/U5lHZr8p4aSNOxN7Y4voTMsLSZ3mJT8CDnP3HHZrjMsjJTJRPWwTyGZQ0q
         mPRZPhl3Gv0sYIgsI9BPA9jLVZEE9TAfjFWc56KJbjA2LkWPtsUS4RdwBhfhC831vHke
         veXnjYNryp0CbaVnvSowR4tOL+cughFfyj6D7DMIlLKOhTYHtu1QKNHAarRXwv3gHysu
         XSXfUR8lOP6f/DdpKxz9tTMXQurw2rXHPbJRd153gFhnU6E3wvMymPsn/YD8exPA6+Fe
         l76Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=I6LkjGiB;
       spf=pass (google.com: domain of 3d6rkaaykcuqmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3d6rKaAYKCUQmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758112379; x=1758717179; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SGQ/XKLb12QWNubJ1odI5zNO+qknl1aEancyG107+jo=;
        b=gmIqILfIlxNDHaADcxQ9Z8kyFzG4oFrnBbeyBDIuKQvY+hPuKTMZBiI1FP6Xsqo0Cc
         xgK7/AADf+MjLVJhp8AFynJyHZTocX4aVKqkcj7mR4BYLBO0gguFj5lA8IKlH65HnK1o
         kqSlh1d+88t7hDjXjqPcm1NL7BB1QvIllJWfutVOWEulHLEmQh725r/Dd300B0t7jsX8
         QEKiw5FpLThjcDv2CNzVGvD0IYVZwr7i2K6cdrsuqZ97eD3uJwQK/Y7ms5dlSBcbrBni
         PqTK42FORXzr331kq+V0Sw1o0jVaRxLbemLivjEIzSMlVrTAwijgxnKqDtTXHT8D8aD3
         e2Yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758112379; x=1758717179;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SGQ/XKLb12QWNubJ1odI5zNO+qknl1aEancyG107+jo=;
        b=Ip577tPaAdOYnSFHXQ3xnqueG2w3lglPvi+uIjWEjuIM5k3PBH3+iqTRtaksCqnba6
         AMtc9BnzVD8YxmL5yOWEPLc45ilKTBT/3BEeKXJpH6o7+WXfYHPurXMTcLD5dw+/avsL
         1O9q5uqmhLNNWaBqv3uDDlcKu06SbA8LGAWz8m9+ZPAkB9MWMks2UXGm7JQn1Vfa6/U3
         riBYUxX8xoiCOeF5Tqbz/dy2XA/G0HvGjL60ddS8ZqBSjGVptWvfWuohFg52fB9eAFDK
         bDo0UDB5PLvArtb5LGdMaxWS4UizGKtxctfDZbnltWdyop9Hs9q2WGgoMbXhTqNb4bY9
         nfEg==
X-Forwarded-Encrypted: i=2; AJvYcCWERgsLsZvDwqVOujO4fZDg6vwGR7EogQIngUjONEARDq2gTcAwo+jY6VNgzI6ihMqgavr7nw==@lfdr.de
X-Gm-Message-State: AOJu0YwMA+Ev9UOoEwFV8Ov5PeBGDJ5DPCYOE6wx2EH4ZAGUIZCwchxd
	g3zvaUIfBCnWIJX22N4rq6BP46yDV0VdadiFTRcbHyZ070E9EkAKdONg
X-Google-Smtp-Source: AGHT+IFPFsTsXEeFJA+cHumjXBOfAGYuGceqLgiTQovP90EQll+zqcTXEy92gjHxqGh/DIzk7N9sgA==
X-Received: by 2002:a05:6402:21d3:b0:62f:26cb:8072 with SMTP id 4fb4d7f45d1cf-62f83c2db1emr2261519a12.13.1758112378820;
        Wed, 17 Sep 2025 05:32:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd64RD5TqTDwJnfvVpKM93sFRiUDcDbb4rNdInfJ4okSuQ==
Received: by 2002:aa7:cf07:0:b0:62f:9888:f350 with SMTP id 4fb4d7f45d1cf-62f9888fad8ls120373a12.1.-pod-prod-06-eu;
 Wed, 17 Sep 2025 05:32:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXLaKyuolKYLXVHQrnPlQVYpvCgW6p1x0h8l4aka3OiW1aaWsHhUgoQUH2C78rNEWZ4v++y4PUxbIg=@googlegroups.com
X-Received: by 2002:a05:6402:1d51:b0:62f:32c7:6c45 with SMTP id 4fb4d7f45d1cf-62f83a2a4f3mr2008075a12.9.1758112375792;
        Wed, 17 Sep 2025 05:32:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758112375; cv=none;
        d=google.com; s=arc-20240605;
        b=e3gI2NDr3BUUmHrkVW8GAUqEL0DY/WeCjp5Or2aaI9uzGNek0K/IB+GF/j+01fYV/C
         9M1QAM+MWMub2XaNHVI4HOicj2jDxgCYLftfh2n15SM3v3A5u/i3EenL/fOkxhbLtA0C
         PXcfP1nTkdzoXKDnulPQ3pKhMBM8uztzCA1GUISRJG0d4P7wCONaD0nszbvSYSO7S0Is
         i6VHGOXVAcvA0NB5jD26wbkjUOZQFJZ+6sGEOjtGkartwAh2ZSCuszhc4nWDg4W8Td91
         +BA34eFLI8HuiWWNz8aO2+89H19a4IceHsceLf1ycKClEF9P9QBUzaKvJbszv42b55vR
         9UIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=gGExNynnqYK/ZqCJ7ukjmzItbcXmGcwmJziwMXpS7pE=;
        fh=upbwDKASfbLheDjPysP/Pww0cKs9hUUIXknh3sHjWi8=;
        b=ZBVnsPbwM8Ze2+x6kPEwdELsfQP4GcEXShr6QeSnZOkAeNA2WTv3bF86Zq2+AN0US2
         vTKU43AWzmUlBHIe9TFUo4hvHFOsFbTsRz1ctdxO2dN+XneAyrOz3LBY6/QmSWn+iV+3
         uD/oF7xPBkGAwbjtqYhIkHLQT8EyYbOTuEywwn/qX1BtdNbUrJJp2fVqgfLs9sCB/AR+
         qpEbRHn2RsAquRPzVRmxwTYMruOsSHfbTNKN5LgqfkJa178o/kmQXvBLFcNVuuNI6DuW
         vFAt1DhYj7D7Re98o3NLPwBvcljo+CbgHHDVjCo9Ei3IybxStkPe4u8tqb6ntnK2aNGF
         k+ag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=I6LkjGiB;
       spf=pass (google.com: domain of 3d6rkaaykcuqmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3d6rKaAYKCUQmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-62ed9fcbb47si371529a12.0.2025.09.17.05.32.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Sep 2025 05:32:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3d6rkaaykcuqmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-3ecdfe971abso581974f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 17 Sep 2025 05:32:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUQEiOuTgmLl22JwXIvuguU/zDXcMurDRDZineXPNKfeDwFdfWNfvLqHg1oHpBpVG0HOjJnAcKY3qA=@googlegroups.com
X-Received: from wroa6.prod.google.com ([2002:adf:ed06:0:b0:3e8:8959:563a])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2c0b:b0:3ec:d78d:8fd9
 with SMTP id ffacd0b85a97d-3ecdfa171eemr2138728f8f.36.1758112375451; Wed, 17
 Sep 2025 05:32:55 -0700 (PDT)
Date: Wed, 17 Sep 2025 14:32:50 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250917123250.3597556-1-glider@google.com>
Subject: [PATCH v1] mm/memblock: Correct totalram_pages accounting with KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: akpm@linux-foundation.org, david@redhat.com, vbabka@suse.cz, 
	rppt@kernel.org, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	elver@google.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	Aleksandr Nogikh <nogikh@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=I6LkjGiB;       spf=pass
 (google.com: domain of 3d6rkaaykcuqmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3d6rKaAYKCUQmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

When KMSAN is enabled, `kmsan_memblock_free_pages()` can hold back pages
for metadata instead of returning them to the early allocator. The callers,
however, would unconditionally increment `totalram_pages`, assuming the
pages were always freed. This resulted in an incorrect calculation of the
total available RAM, causing the kernel to believe it had more memory than
it actually did.

This patch refactors `memblock_free_pages()` to return the number of pages
it successfully frees. If KMSAN stashes the pages, the function now
returns 0; otherwise, it returns the number of pages in the block.

The callers in `memblock.c` have been updated to use this return value,
ensuring that `totalram_pages` is incremented only by the number of pages
actually returned to the allocator. This corrects the total RAM accounting
when KMSAN is active.

Cc: Aleksandr Nogikh <nogikh@google.com>
Fixes: 3c2065098260 ("init: kmsan: call KMSAN initialization routines")
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/internal.h |  4 ++--
 mm/memblock.c | 18 +++++++++---------
 mm/mm_init.c  |  9 +++++----
 3 files changed, 16 insertions(+), 15 deletions(-)

diff --git a/mm/internal.h b/mm/internal.h
index 45b725c3dc030..ae1ee6e02eff9 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -742,8 +742,8 @@ static inline void clear_zone_contiguous(struct zone *zone)
 extern int __isolate_free_page(struct page *page, unsigned int order);
 extern void __putback_isolated_page(struct page *page, unsigned int order,
 				    int mt);
-extern void memblock_free_pages(struct page *page, unsigned long pfn,
-					unsigned int order);
+extern unsigned long memblock_free_pages(struct page *page, unsigned long pfn,
+					 unsigned int order);
 extern void __free_pages_core(struct page *page, unsigned int order,
 		enum meminit_context context);
 
diff --git a/mm/memblock.c b/mm/memblock.c
index 117d963e677c9..de7ff644d8f4f 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -1834,10 +1834,9 @@ void __init memblock_free_late(phys_addr_t base, phys_addr_t size)
 	cursor = PFN_UP(base);
 	end = PFN_DOWN(base + size);
 
-	for (; cursor < end; cursor++) {
-		memblock_free_pages(pfn_to_page(cursor), cursor, 0);
-		totalram_pages_inc();
-	}
+	for (; cursor < end; cursor++)
+		totalram_pages_add(
+			memblock_free_pages(pfn_to_page(cursor), cursor, 0));
 }
 
 /*
@@ -2259,9 +2258,11 @@ static void __init free_unused_memmap(void)
 #endif
 }
 
-static void __init __free_pages_memory(unsigned long start, unsigned long end)
+static unsigned long __init __free_pages_memory(unsigned long start,
+						unsigned long end)
 {
 	int order;
+	unsigned long freed = 0;
 
 	while (start < end) {
 		/*
@@ -2279,10 +2280,11 @@ static void __init __free_pages_memory(unsigned long start, unsigned long end)
 		while (start + (1UL << order) > end)
 			order--;
 
-		memblock_free_pages(pfn_to_page(start), start, order);
+		freed += memblock_free_pages(pfn_to_page(start), start, order);
 
 		start += (1UL << order);
 	}
+	return freed;
 }
 
 static unsigned long __init __free_memory_core(phys_addr_t start,
@@ -2297,9 +2299,7 @@ static unsigned long __init __free_memory_core(phys_addr_t start,
 	if (start_pfn >= end_pfn)
 		return 0;
 
-	__free_pages_memory(start_pfn, end_pfn);
-
-	return end_pfn - start_pfn;
+	return __free_pages_memory(start_pfn, end_pfn);
 }
 
 static void __init memmap_init_reserved_pages(void)
diff --git a/mm/mm_init.c b/mm/mm_init.c
index 5c21b3af216b2..9883612768511 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -2548,24 +2548,25 @@ void *__init alloc_large_system_hash(const char *tablename,
 	return table;
 }
 
-void __init memblock_free_pages(struct page *page, unsigned long pfn,
-							unsigned int order)
+unsigned long __init memblock_free_pages(struct page *page, unsigned long pfn,
+					 unsigned int order)
 {
 	if (IS_ENABLED(CONFIG_DEFERRED_STRUCT_PAGE_INIT)) {
 		int nid = early_pfn_to_nid(pfn);
 
 		if (!early_page_initialised(pfn, nid))
-			return;
+			return 0;
 	}
 
 	if (!kmsan_memblock_free_pages(page, order)) {
 		/* KMSAN will take care of these pages. */
-		return;
+		return 0;
 	}
 
 	/* pages were reserved and not allocated */
 	clear_page_tag_ref(page);
 	__free_pages_core(page, order, MEMINIT_EARLY);
+	return 1UL << order;
 }
 
 DEFINE_STATIC_KEY_MAYBE(CONFIG_INIT_ON_ALLOC_DEFAULT_ON, init_on_alloc);
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250917123250.3597556-1-glider%40google.com.

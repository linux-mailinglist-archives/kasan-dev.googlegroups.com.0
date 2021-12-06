Return-Path: <kasan-dev+bncBAABBLUIXKGQMGQEHXFYIAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id C77F246AAA2
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:44:14 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 205-20020a1c00d6000000b003335d1384f1sf213027wma.3
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:44:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827054; cv=pass;
        d=google.com; s=arc-20160816;
        b=AWCaZ4LHiN09DWW0QRkPG+Y3w5otxKbgD8M+YkjcLrwKsibyXeoQvhgwBUS5k5MpeT
         1r+xGGPf3TVv8T+34A8Z9OnJGpYsxojsUp/jmniqG4rBTm87PHmbTzpEEhsHGzy+XCnP
         FMSmi9vC2i8tbJIW1bLVOeN84F7QQmXOFlm7+xq/CdvPm7U7vG81SwqiAVboLEwf4r1v
         W4ir/qk0RvdL39CwTscVTzeS6x4MyOEbOD+BfICvacjZyXRgjYzMCILiwQh52txJLt8C
         9bPC9CxgfHiurVtGtbxuIEuktRfXeaf0IBdAvkwAv+GFkAsd1kzB5jR6KT1g0Xour821
         bfPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uTw5xqcq6kFSBVV7ppCUcnvvdu7G2deuiwJCAV2upyc=;
        b=PH839XH3FjHbSTHssEII490PHvp+x9Ovk3ASLIjAmFJoAxQAQps/PUQWi22BcPxVjH
         bQ9zd1tn9Sn2jpTC0j6IO2EDijusVnzjyPzuJOD8VvQJJ90Tn083GnzqR1A8cRXn+b6j
         kP8Z2jyI+OYYIXZ5Yj16ebZTCEh3dSjgh+f9HWccy040MqXw92/tVj32fm7nIVwWh2l7
         F2YRxJI8NqrOSAU0gmUCeSh5sZBqh1B7DdCgfI7D6Hi7HRh5qmu3w0BsfTl85nw7qBpt
         5dYOZsuMr/tENN6RLLLGbwbMDZP5oyvuL7FEhkUIISf3bPp5oXcv21vszjVxzxpjuWlv
         J8iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fuNxtXvq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uTw5xqcq6kFSBVV7ppCUcnvvdu7G2deuiwJCAV2upyc=;
        b=SYg+IfGWG0t/T8zqZyJl4kugQUzomlnOTy0NX8kibKjWa6VS5sdl3BP4gJN6PATb8e
         a23p4X/3jGMGmkmNvsXdmyroyCFIjwRD4L1G9ozAfmKW4l1yY/B49GTNT3V+XQT6YsbS
         Q9i7XFV+uD3iTNEXU4lsm6wdLch0j7Rz8Ic6jE6zq1tbwBxw8o88KBQgOCZKs90m9N6L
         Hj/t5AJ+wJrTSxcQdoSDJsZwwDmVnrYUpFjzoHBmOhNQpccTdJRm46el+vDDG9Yb9yHl
         gzsu6iSCvhxgLZRNJrdMuaKIGendm3YoqbS4c7x2n8aUm495QppXwvo61urBTyqaKTQq
         zb5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uTw5xqcq6kFSBVV7ppCUcnvvdu7G2deuiwJCAV2upyc=;
        b=ISKIKsJ7VeQx9GvxuvT6LBhiqqSdXzpHQ0c6eJnjNDiUuXDmxT9G87r8NFGtrl4tvf
         rpwfDfZUYEZ/vrrYKFJhxnYrSWo4GRcsCfwMGWfbwT8ENZjE5JwIn74k+uiDrfz51NUn
         rtr2yssaJnIbq0x33NhMkwetdoapcH4IHNArUwsaeVuAor1LXoqdIrrKoZv90fqZvhyE
         oU1AfYLacK10mrE77uNiyYkzVzZGfinT7vlkh68PvIChIGrySAHKli0c/O2HXjuVktcW
         FxtFm5EeEPE24SEz7FCls/SyH3W7i5t/ttcoguk0fogbruQT8QfO0UB2ePxyzeerGsDM
         z36w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HOeaSFn79TbW1ZnQXLJnodZFCok1J/3WwKIci1VdJ9tiSXFXB
	t8MdlPRcwijpjrb7/6yHgow=
X-Google-Smtp-Source: ABdhPJxFkenAl1JTpfThVpr2SdLc0B2LllhY/r4HWlVBkp+QnPKKp6SfxdHQXK/GqsV+kx3494Uvbw==
X-Received: by 2002:a5d:6151:: with SMTP id y17mr46523709wrt.275.1638827054620;
        Mon, 06 Dec 2021 13:44:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls1146138wrr.0.gmail; Mon, 06 Dec
 2021 13:44:13 -0800 (PST)
X-Received: by 2002:adf:e9c5:: with SMTP id l5mr45706017wrn.218.1638827053945;
        Mon, 06 Dec 2021 13:44:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827053; cv=none;
        d=google.com; s=arc-20160816;
        b=UTbZ9YgpEgTl0ueEX0rwbgoE4n3KSH2DS+FmGzu98Ok4sdkl6GayS2aU3EmCViwPPo
         dAcQBdxbAtbr3zzZm6bINBYzw3oXPRODE+GIJx+Fq1z+13Bl+zghX9T2boqyMeDkqW1u
         wLLEy4YTICLsa1MvUIXZaeN75ZoUJYu3+EOHqhHPQlLRgnVm8/6Mof1DoOVkdDiJyWqL
         fsGqQUEawWaV2AGafkKNxeFR/Cl+mxYz7NfIoAEp9MYGsQq4OCwiZ4GZ5T4NMg9Ix9rM
         ZT3R84An6YO0DSkZGsatLbQYEV27ABN7Yqjsd+1HEJ/IPjHKqTZhstC2LcJGG0Hac4v8
         9HhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Gob2lt41MqESGzJ3aS1cO67hIxM237cUiv6TAp2u4fg=;
        b=k0m1kM0pWBypKOCTDbMc9PpY+2MiUHMKJmdhujpHDeJ8grKxBfCIiGI9GJ+7bnk09B
         D6tnOUlshSftciOd91Hi8OoNTwseflmqgg5suLWldO8ZVVWGG3oIVLVDIPp4bHyoRkIf
         9Ynq9p8ZWiOvGl0Us9bYZDEUGX7wrRWu1x5NK0WJO2yIoD662bp1s1M+VDYkhxFZOU3K
         5r5CUUSpDmGX9fBTqcO91Ssq62lIkazkKfsni/E0f5pQmajf/bgFR8YHHeRtxdnaOuql
         IG3dcpTbRygi4s4vHEmC8258/L3CygagfHdU8/dI/oYRVrnGEfuMPR06G2qcnGLg5nK4
         0UYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fuNxtXvq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id 125si85620wmc.1.2021.12.06.13.44.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:44:13 -0800 (PST)
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
Subject: [PATCH v2 04/34] kasan, page_alloc: simplify kasan_poison_pages call site
Date: Mon,  6 Dec 2021 22:43:41 +0100
Message-Id: <73d7d82c2b5cf44cb429fbc7cc16479fb8776bbe.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=fuNxtXvq;       spf=pass
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

Simplify the code around calling kasan_poison_pages() in
free_pages_prepare().

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Don't reorder kasan_poison_pages() and free_pages_prepare().
---
 mm/page_alloc.c | 18 +++++-------------
 1 file changed, 5 insertions(+), 13 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 3f3ea41f8c64..15f76bc1fa3e 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1289,6 +1289,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 {
 	int bad = 0;
 	bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);
+	bool init = want_init_on_free();
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
 
@@ -1359,19 +1360,10 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	if (kasan_has_integrated_init()) {
-		bool init = want_init_on_free();
-
-		if (!skip_kasan_poison)
-			kasan_poison_pages(page, order, init);
-	} else {
-		bool init = want_init_on_free();
-
-		if (init)
-			kernel_init_free_pages(page, 1 << order);
-		if (!skip_kasan_poison)
-			kasan_poison_pages(page, order, init);
-	}
+	if (init && !kasan_has_integrated_init())
+		kernel_init_free_pages(page, 1 << order);
+	if (!skip_kasan_poison)
+		kasan_poison_pages(page, order, init);
 
 	/*
 	 * arch_free_page() can make the page's contents inaccessible.  s390
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/73d7d82c2b5cf44cb429fbc7cc16479fb8776bbe.1638825394.git.andreyknvl%40google.com.

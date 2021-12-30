Return-Path: <kasan-dev+bncBAABBTEJXCHAMGQE2R5NVCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B68D481F88
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:13:17 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id w17-20020a05651c119100b0022dcdb204b9sf5090918ljo.5
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:13:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891596; cv=pass;
        d=google.com; s=arc-20160816;
        b=p2hFIkIYWcBjNQptoTQop1aN3NBCyRQDnM0M8PiUaAES3Ais+ingG3q4jzsCj/60L5
         dF22tA3sCMcpnw7/f4H3YgduePIqpm+RBldAAyzBlcsOvmBxYpBOwDqxqgSYIwVmnvFt
         FvkznzpefjvrTpyEmLj5aNWJJHV1jzSQJU1mpA9wa2NC28SDEtTGWZMWRX41Td5VXYYx
         9p9q0rj0rMeM/vJMAwZFWaX0dr45ccK+J+GqGd18YgzVJ4CyxR0jJUdvG7U/wIyqwlSW
         x8cQqJOqnGdRa/Y3v9uLgA5fXEg8CwEUMkHmcNNGcCzq/sb6WD55/CWvCi2UJM5gee8C
         oDJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wfCvZF7aKl4cnBbYMQg3rHEXOZb9iIukgEESPl4qLUs=;
        b=g/j/tKlDs6WeWreLqUFtA3bY7bubziAHXp+I9LoslsCljhl1HffHS1E7bBcHE2rxTC
         Vop9ILTuRn8JGvh2qH8eOcMfyk5OfF1zFNWTWThhAJ6IbTOpPPKGRuG4uCt7petOhQ7J
         ZjpXZhnPtF/kh5Bw2JaZnvyeIVgJzxajuf+6XUzz15b/yCKzUIH9XdqX5AO0JWe3H+5D
         bWEwM+bmnr+1eCRYAnwwbjRK25CrWnOVjNBLyCPiJudc0dk9xzrYtQfr4L3QysWBWUvl
         Fneu1LX8cLnGQNeYe0ZkByKWcO3xUhEucZJp+FzyK6pDkQWolF8d103tMxMQqOiu0g94
         M43g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=k1PctVkX;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wfCvZF7aKl4cnBbYMQg3rHEXOZb9iIukgEESPl4qLUs=;
        b=ZNXVQWU+wax4Qq4P28qBHpfEHcTTWU9b4aoO69mcEois/TWo3k3Tn8n4vijueneuuL
         x59mRtGNI7kcXlvR26dQIKILCcPH6qpt02GNWLAeqk4g8u3ZdzE9N1SFhLE/+xLP3wYp
         lvL3ek3rV13USeZK+7v3Qvys4OFyABAvu5RbFfx9N2n2jfA7BhQB3luXMCuSaBTGKHp3
         nioO7VEwh2U2YPIw3+Cd+bFovQmo34dQfoLLcGcZZl5OQtikxRkSDRlIpcaFq7a2WK2P
         u3M6iQGg2xW+ZtF0xDHhn8tIkFcPO5TpK979pmzP5rbrmHMgakECCBrTnSmbrIJiIyKM
         MjBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wfCvZF7aKl4cnBbYMQg3rHEXOZb9iIukgEESPl4qLUs=;
        b=ZXt3+ikJZjRrzWJ0X59XhqjIn7AILC58FqKiIZPbZQ6w3xr3cTFBmVfais/p9YP/UF
         RRn+4TgaY9aSSLYZhz6a9ZB3Qy+xc11IkeSddYYkDPcCm55Gjz1OG57y8xmEugPu0zKZ
         GpJ9r0hv8IFusIudZqsGyhrlV3QAcBbwuxelbxd+0u4gj6Vmu7oo2EHg3A7JKRfIEn69
         dGM+EkmNbPkfvsAWo+7qDlfvk3JNIeSCkfiZn8ABydSYUz6QswLtx+vdSErHihhKNx6Y
         Lfiv3ZdZEH/a7jv3vx/WQAT1IqlRr5rc1XOWnDrpJwWJ7b4aar+yXC77dKUmEIhuAiF1
         pmYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Fo9TNL7X+qA4s/03fjIUm3Zc3AHljYNzUpCKJmp9x5+w3tMTl
	uJImIaX58yH0Uiu3zMVegwM=
X-Google-Smtp-Source: ABdhPJwgeFSDJ73JH2nQigw0Ol7aFbrJ0cER5Z+rAA29jiOrtS6m2YDfuD+Gbo7j8CKF3DxQxAzySg==
X-Received: by 2002:a19:9201:: with SMTP id u1mr26052784lfd.115.1640891596740;
        Thu, 30 Dec 2021 11:13:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:158e:: with SMTP id bp14ls2235632lfb.2.gmail; Thu,
 30 Dec 2021 11:13:15 -0800 (PST)
X-Received: by 2002:a05:6512:31d3:: with SMTP id j19mr28815999lfe.78.1640891595848;
        Thu, 30 Dec 2021 11:13:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891595; cv=none;
        d=google.com; s=arc-20160816;
        b=krS2tyx+4Q78NyyZPX2D9s9Ao1Ny8Sz1SQ9Nyry2O6WTrrAbUV6AyR+x+HJHHP3wQm
         1QKKrmZ+COrkFHhnCGR0rC4RtOcVzD9m6p7aVId1RYTTzUF2HJ6EBe44X0excfvEWGZN
         ldY0M6TqdRIrFO12OctBUqxvcOHzTSQhk+76ShTtXzrW1V4KvgwJOp3woapmEz2jejsX
         U8LL8tbOj0jHzHACBG98MDuPITYX7D5KWsSxrmURqOgwwgPzBWqmswOElQ7xj8UQlfyY
         qHjrhZYuuhF1+B66AFXaEO9qXM92DR1r9+jnsQqnQlvD860ZCE+FMiA+n6XznGwG3HEL
         Rv4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=53tYbTRWUl6V9TtfhMZJrf4W493M9HDh+VLN0ZtqCLE=;
        b=Wy8UhF6IjtOmK9JJRRvBP1wSJYxZbgxuN0swpi3Cis2bOn24H21vog/3UKvLcxauIQ
         UHJisz2y6udGEcc4WFP8K8RMNWJVz9vbWTAWx23X8gkJT4rv86Q1MCQOvenVZZl5ATTa
         theRG7bIvfdODGjtsgkM5y8P+LCnmooqla9Yk1NRF5/g7hRbubkw2pWVOFITdG+dT2Wq
         xTf3XohunahfFD8Gk+IFaXl3mVjv/jBAxIcO3f7BMHpmvsK+HfpDnXGsCuv9UkqukNfd
         OlknJK1xeCw24f/ZUqWqi75aAoxNGnKyLiaKOkZbZO+XTQHe0X0wIz57jIWkcXkkcG+J
         5Bsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=k1PctVkX;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id i2si1216006lfr.4.2021.12.30.11.13.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:13:15 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
Subject: [PATCH mm v5 10/39] kasan, page_alloc: merge kasan_alloc_pages into post_alloc_hook
Date: Thu, 30 Dec 2021 20:12:12 +0100
Message-Id: <91a7b6700da135078ebec103328eaa9072311d40.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=k1PctVkX;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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

Currently, the code responsible for initializing and poisoning memory in
post_alloc_hook() is scattered across two locations: kasan_alloc_pages()
hook for HW_TAGS KASAN and post_alloc_hook() itself. This is confusing.

This and a few following patches combine the code from these two
locations. Along the way, these patches do a step-by-step restructure
the many performed checks to make them easier to follow.

Replace the only caller of kasan_alloc_pages() with its implementation.

As kasan_has_integrated_init() is only true when CONFIG_KASAN_HW_TAGS
is enabled, moving the code does no functional changes.

Also move init and init_tags variables definitions out of
kasan_has_integrated_init() clause in post_alloc_hook(), as they have
the same values regardless of what the if condition evaluates to.

This patch is not useful by itself but makes the simplifications in
the following patches easier to follow.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Update patch description.
---
 include/linux/kasan.h |  9 ---------
 mm/kasan/common.c     |  2 +-
 mm/kasan/hw_tags.c    | 22 ----------------------
 mm/page_alloc.c       | 20 +++++++++++++++-----
 4 files changed, 16 insertions(+), 37 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index a8bfe9f157c9..b88ca6b97ba3 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -95,8 +95,6 @@ static inline bool kasan_hw_tags_enabled(void)
 	return kasan_enabled();
 }
 
-void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags);
-
 #else /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_enabled(void)
@@ -109,13 +107,6 @@ static inline bool kasan_hw_tags_enabled(void)
 	return false;
 }
 
-static __always_inline void kasan_alloc_pages(struct page *page,
-					      unsigned int order, gfp_t flags)
-{
-	/* Only available for integrated init. */
-	BUILD_BUG();
-}
-
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_has_integrated_init(void)
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a0082fad48b1..d9079ec11f31 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -538,7 +538,7 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 		return NULL;
 
 	/*
-	 * The object has already been unpoisoned by kasan_alloc_pages() for
+	 * The object has already been unpoisoned by kasan_unpoison_pages() for
 	 * alloc_pages() or by kasan_krealloc() for krealloc().
 	 */
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index c643740b8599..76cf2b6229c7 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -192,28 +192,6 @@ void __init kasan_init_hw_tags(void)
 		kasan_stack_collection_enabled() ? "on" : "off");
 }
 
-void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
-{
-	/*
-	 * This condition should match the one in post_alloc_hook() in
-	 * page_alloc.c.
-	 */
-	bool init = !want_init_on_free() && want_init_on_alloc(flags);
-	bool init_tags = init && (flags & __GFP_ZEROTAGS);
-
-	if (flags & __GFP_SKIP_KASAN_POISON)
-		SetPageSkipKASanPoison(page);
-
-	if (init_tags) {
-		int i;
-
-		for (i = 0; i != 1 << order; ++i)
-			tag_clear_highpage(page + i);
-	} else {
-		kasan_unpoison_pages(page, order, init);
-	}
-}
-
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_enable_tagging_sync(void)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index c39e6acdd7c4..51ea8cbd2819 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2398,6 +2398,9 @@ static bool check_new_pages(struct page *page, unsigned int order)
 inline void post_alloc_hook(struct page *page, unsigned int order,
 				gfp_t gfp_flags)
 {
+	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
+	bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+
 	set_page_private(page, 0);
 	set_page_refcounted(page);
 
@@ -2413,15 +2416,22 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 
 	/*
 	 * As memory initialization might be integrated into KASAN,
-	 * kasan_alloc_pages and kernel_init_free_pages must be
+	 * KASAN unpoisoning and memory initializion code must be
 	 * kept together to avoid discrepancies in behavior.
 	 */
 	if (kasan_has_integrated_init()) {
-		kasan_alloc_pages(page, order, gfp_flags);
-	} else {
-		bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
-		bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+		if (gfp_flags & __GFP_SKIP_KASAN_POISON)
+			SetPageSkipKASanPoison(page);
+
+		if (init_tags) {
+			int i;
 
+			for (i = 0; i != 1 << order; ++i)
+				tag_clear_highpage(page + i);
+		} else {
+			kasan_unpoison_pages(page, order, init);
+		}
+	} else {
 		kasan_unpoison_pages(page, order, init);
 
 		if (init_tags) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/91a7b6700da135078ebec103328eaa9072311d40.1640891329.git.andreyknvl%40google.com.

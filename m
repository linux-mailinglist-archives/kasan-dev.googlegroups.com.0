Return-Path: <kasan-dev+bncBAABB5GTXOHQMGQELD25OBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 58FB649879C
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:03:33 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id g8-20020adfa488000000b001d8e6467fe8sf2201642wrb.6
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:03:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047413; cv=pass;
        d=google.com; s=arc-20160816;
        b=pKZ3hTmCmMPoK/4U5+jYC3c//z8gn0QmrDwDP4UoaMjWkr5Gc0hSm/8BgPDkbGsjJI
         pWvVi7JMA8jKukD1UjnesOA0YWB+7HU3Nh6iOoj0J0jjjpbecfNQgg5RQTgaYwYwc2Du
         M25sdmrlOvpW+fnl/rW9TOMcLb0kmFr5E+eFceGrSI+w3Dz0EmJbD9LR12/yCHZ3I4Xr
         WfZRLJ0CNyVIlN6mteUaEFM/qjR8dzDanuVN55W72B+gRAtTcpXtXCnIfpL9g+FFd3kM
         JjfDZv3LKm1tuL5Ry8q7oYUx5amD22hQPgcUeo/jfw1XDr8WZzH+PaRjva1QNflhky7R
         0e7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+zMD12yUbDv4ezMrMMMLVcgxdmeqP6+Y6ojwXL26pJ0=;
        b=Iyerf4BflpJiHhfAYjobBOH4zVTjGDzyB9P1QvlQI15WSprwJjliXCnl4PLCRJs9fc
         8dwlXq3jDh/oO+dSEPwvLnCnBG913NH5bW+BPtTfPbEV/9mEP0cefntk33hCdo9tCCKJ
         80klg/9jUSUPiitIJ9SBKwYgkFMcNukaZEUnnmYrTVIV0UDR5HuduNJTqgiS1qb6RW8d
         x+pVk0pwTbU05D7EV7TH+uzvQEiqoiIRywuTlJgsPbKtierxcPlZ8YAz6jpEiNDn3MHU
         1j1pc7ey7aq/dYvfamvxhJqkvGycGT2T6R7673KjMIeBkK/h+d7io8w261z9+uwlYOGR
         H+PA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ewd4EoS+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+zMD12yUbDv4ezMrMMMLVcgxdmeqP6+Y6ojwXL26pJ0=;
        b=gwzxgiyY6r4q86yC1VeXiEI05TBHwa73hm+lACp1W+pQMp9Kb2Lhz0DYizh4Ccz22M
         EPf/4FejWS79qu32pMV+xULmZm1Wih6qc+qAHNuuPht73ZLBf3UT0uxmdum3o2XcCZ9R
         V2Hyf+MAr+v3UVc/5BWAYBEa7tG742TWNxlXUSfPOpilD9ebgHFoLhHPePwuxgEJmOIa
         dg2I1gdYZkCmpDe/kifcgfv/ge38qxhLxImf4eVYiLOPE6ZTAO56jELlDdhBMGdJOUGJ
         SBINCyUTuxclM4whwF2ibeTOVVqZt+Nf1dzi2q+U5KvX917+jYjFsAiI5OTImIoKUpVd
         7RAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+zMD12yUbDv4ezMrMMMLVcgxdmeqP6+Y6ojwXL26pJ0=;
        b=AFhV2m2PuSL+zUJMpU8JdNQiNXrofDMjhBIRSbwqZJ3rVLUpb00M7V+6qtdtfBPNlE
         13ozvg/wN9+Pwf9BIHG3GejZVO1s7TOcDifdGP8Ftz9+atf3SXp8OfRf/YaZjCsz7bcH
         1QvAXM7hElstT+eAfZMSAhc89K4XarZYBNSCzplCb2x7Gw0XDc6LMy//r5we+7gaG93E
         lqndKpGa2w3RPXV6f2k08NyDwl4NtnqTWHbK8++f74MGEBfs/GIJGjVwrltGn3eVb0nY
         d0Q084kclndZ+8bQMz3yNOKXKSrG8bMGoRfgLzRqYKNXZOIwxEG7dXihNEzkXmQO35HU
         tWdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531bctE+BrviAmbwBfWID4M/zGfluLNJSbG2OWzHbCjsT1n4GZwh
	BTN4jGdpPoT1DnMTYdOC04U=
X-Google-Smtp-Source: ABdhPJzR/snzCeG68EhlOhJI9iASZwfoBJiXl0B70l1bxyr9qCODVPrc5YgJmL32MkHM1tB1qYzN0Q==
X-Received: by 2002:adf:e510:: with SMTP id j16mr15575946wrm.58.1643047413131;
        Mon, 24 Jan 2022 10:03:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:500e:: with SMTP id n14ls41521wmr.0.canary-gmail;
 Mon, 24 Jan 2022 10:03:32 -0800 (PST)
X-Received: by 2002:a1c:e914:: with SMTP id q20mr2819799wmc.70.1643047412381;
        Mon, 24 Jan 2022 10:03:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047412; cv=none;
        d=google.com; s=arc-20160816;
        b=ngz/fWx08lYrW2p+eZWNRf5NkHku6MOWEqKrm22zqGKCtNJX2U4X8XiCHy0HiSbyss
         BfMJY+9b4eTqLdia9sJyoEXIKlDvUwMVntf83j1u8xtuS0zjLlmXcrIroP2jrfHfhUwO
         gf3I0wzaShyeZ1MODqTFgVjQYfnvGK/3uVzF4+lJ9ORALo+RsrTVzxN0IGdK5YhyC4e5
         ElJV5HZcc/Sq9SrTQ6xPVxiZHnTwnaB8XxfKXiaqhDBH5MjfyYgHZqQ2qV+jMlLLkkBn
         QlZQKfe2ZNp3MX2Ka/XZKaMN4PE2mptk/YjAKG0BENDsl856hNuPXgbYlxpUPoTZAW3N
         o+kQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=w/5MGH+6es3Fk1qg92YmO6ftiYPgmqt9uv7fZJ7G30w=;
        b=uEpLZZztruvWEQApJKrKeHDKMvjI/Rw17oz0Pz4Bd2sQwGCpQViUC798SIHXj54ope
         g08KCySEFACmCHVeDxwrMEHnE55/NLtTuKJSrOFWqVAF7thGHcZtzQBI0sM6J4vAX5jl
         wBflEIOO7qEHnD8TwXDQFPtRDdSmhBmeAWQ3EWp44oWabmoDXA8yItObbLAEM0NcSW6W
         flZ34HepQ3iwhrqllTpsvOvvMTlz92HsRp+NN/bTm4Lj5DD0+/lUDkDbSnIdXQR+RjHM
         PnlcOrI/EBoc2PBfjnOL4qWDh4B3Kj0t9l2Wuz/HH45O8kIKeIcVi89e2lG2B8rianZM
         fNUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ewd4EoS+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id d14si578602wrz.4.2022.01.24.10.03.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:03:32 -0800 (PST)
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
Subject: [PATCH v6 10/39] kasan, page_alloc: merge kasan_alloc_pages into post_alloc_hook
Date: Mon, 24 Jan 2022 19:02:18 +0100
Message-Id: <5ac7e0b30f5cbb177ec363ddd7878a3141289592.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Ewd4EoS+;       spf=pass
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
index 868480d463c7..abed862d889d 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5ac7e0b30f5cbb177ec363ddd7878a3141289592.1643047180.git.andreyknvl%40google.com.

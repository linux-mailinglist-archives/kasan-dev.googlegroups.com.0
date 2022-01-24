Return-Path: <kasan-dev+bncBAABBUOTXOHQMGQELBHRGHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 93B80498790
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:02:58 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id u4-20020a2e8544000000b0023aeea9107dsf785347ljj.21
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:02:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047378; cv=pass;
        d=google.com; s=arc-20160816;
        b=a/K3YmwsJHRELqqP0e4qfW6QKBMxnB2Lw1vhmntMqEJDoRwIYDyXolMJ6Cqb/vLbdJ
         hDkEjLLrqR1OWgkiYdUJuBq1eeNJoGwr3sFW00v1Nhdmtn31YDpsJk5Qun6gtu8dVEvQ
         QoPv+uvFH8R6+mbf+XvSSx3S8mk4hFB9Ra8+3CHG13fsD+Ge6K64TmoSRjYMjcN9HDrG
         8d78JDqeIp8FtyVUdSOA1+QBP2jo+XASzo7LD52c2dl8VtF7AvO30lJv1lF/XUT3+96y
         I9H3JtoZ4ADys8CsQx/PmOsOxjzoMXkiOufXiNg/SF+qqzsODxN2u970dhLKlT2HTT7N
         G7zA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=m8tNGjHM3y+4Om0Jcvw7FiwhVwEZwZfB0jgwe+G4bXU=;
        b=ywz5+fJX5DKgHNgSTgmmHj1abxjOxDV9dIWBU0YEKhGvn+34NzYseAXgYYknqAp+PX
         KZMZe1DXOax4YU9MeCc5dOZQvSVqIQbnne+YojCVDjQZp3P8lJ8a/LJfxA0sq18/uK6d
         5rcjs4NYDLx4HTpPftYD7HmgJwdqOp6yAZtw6RADbGozibHK6e3uWTakt7jReEA3DynE
         m2myHc71X4BZBAvYesA4vGU9dASn5uoWrnLseyLTvr7MGPpuclr45X11WXIySqOdD7lo
         vsPXDgHwYDocOp8Ezqn5WO7F2gh6P/iqy3DefYPRdCcRaqdEd1pv4GeIwZ7hN7k0ZnIh
         FVmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FSawIJBA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m8tNGjHM3y+4Om0Jcvw7FiwhVwEZwZfB0jgwe+G4bXU=;
        b=UMqs3pvYXPgZkUEx5VxEQf1sd+VsoJ6T9rbStb16dtCuATV5OqImqH3qYqvRzTjNAI
         Fqf9YLfaYqhQg8khDNJZJmKYKe6tQ1G2Za79co79aWHYDMTG6ZCWmqN7HppUw8FaNEWo
         znsZdjRZMrGAWiqSrQuddpy+iBstc4Xx/OXmCgK5JWe8b5pzLRfrSZwXnaueIvscji9z
         UB5PDR8g6lGlyIuYB8cxXS77EVjG32oi9B/wGok1aSWjaxLabbTEHDcUskeMZyLJcUcP
         eWPY7ApSpm2WI2hKDp2z7AnJS9fC65cMW3YF5dJvM/jbwdTnW//yflKlZSgkp0OARLkv
         ziSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m8tNGjHM3y+4Om0Jcvw7FiwhVwEZwZfB0jgwe+G4bXU=;
        b=3mFI9VvAT6WQJqFXTrhOWA6V8mG0E3lWLMQGY2n/pGStyzJngLc1plYY6h8CmDVu0j
         VLIm1vOB5kRpaBLeYZgdorydRpR2A7ZaGIVtJFXgICdWjrHp6Koxz0bjAkraBRo5jnMz
         6fqpkskno6MY/OpGDglDdmn+OJryNLncBGk+xZ5zvtPoP/WgXfMbWJE3eF0Va8BLtQGq
         BAWAKJ0UvBMIq2jQQ46hBNrPvOwYaT31+UWnaD5ESyTfVZN84yBSHGm8zDtNVbKqpNUZ
         yhk/LNN8IC4dPY8V1/ftJmGkfHtJkrg3S+HHL2NyaNxt48/DVxjSJoaDa4ORcH79137R
         k/hg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532/iZKUPBQIuqyGQ/13fx0JxKywIBmvpda3Yqbu5q9R1P+5ZVih
	ddSnhbXC+jCNsPr5kMlwReQ=
X-Google-Smtp-Source: ABdhPJwXVVU3ydVEb7nOFp8E6Dw9DoNB+7TUhn6Vr7N6Z3wR18NR2noku63gSNf+9TkvCs/Ro5HPIw==
X-Received: by 2002:a2e:b545:: with SMTP id a5mr3692128ljn.414.1643047378151;
        Mon, 24 Jan 2022 10:02:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c97:: with SMTP id h23ls229245lfv.2.gmail; Mon, 24
 Jan 2022 10:02:56 -0800 (PST)
X-Received: by 2002:a05:6512:2350:: with SMTP id p16mr14098397lfu.336.1643047376483;
        Mon, 24 Jan 2022 10:02:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047376; cv=none;
        d=google.com; s=arc-20160816;
        b=VkhHjua8Pk9X4hihrOZM4icgXy4bLFqhZ8K9H3mIX/mAP1V3nDmAn9/2/WQtKmuGhv
         3hmpYGyCQEkKxxjrdK+Y8llyq7w8GgWWjACi9HkMSM4Wgd6k4Q5e81CZpw9CWcJLMGRh
         CAj5Sa/6aXK/zefpzSBl7dljy6AB4KsFsGQLB4auIWhOG8NIXRwmgBTwkZcH3rKg4Zz5
         v97Y+00XrpeC/UgFyOmFu6kqPZuKIOD0uMRGes5OT+q0GKu9KeyXruggCt9MUIpVwbT2
         BHwnrfKd74QzcTYzc1RgxS/Nrca3IPIDUsxNaU5ysFMCmLYXDPGkWhseHwCjTK985LzD
         yoIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JeuhmVhr16WrUz1cholyqQm1OzZJjys1/2dFsfvc630=;
        b=UsfzSiGHA/inP8ljdPgM36Gh0rOUJ4eAUS7k75fXOA46lpBGmOhTAcyNLGA+NfvfyT
         2tcsf9MZO0R8FU6KaEdtU/h37wTyJi1WqWnAv+mv3MjHZB3MyOaBOazR6sO9mtCxgkKU
         8xLoPrJGNA741mxLdq1zZhuIzpm5H5iaDw0Zz/9vzchNvJyoiPULC9nznFf+j8twxTSm
         OOQ94u+7bKk0SZSULzGLF++L6kIxnlHI2zFZcZIQcFb2VYc9lWV53jVLLP1SXqJbnE2N
         2fzzqsF+TToDZ4IQxw/EW+oGCTR3OSTk2mdwsVzniSyLFbzpF7cRmGbiniL5glIw9CyC
         UAuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FSawIJBA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id a6si629609lff.13.2022.01.24.10.02.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:02:56 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH v6 03/39] kasan, page_alloc: merge kasan_free_pages into free_pages_prepare
Date: Mon, 24 Jan 2022 19:02:11 +0100
Message-Id: <303498d15840bb71905852955c6e2390ecc87139.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=FSawIJBA;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Currently, the code responsible for initializing and poisoning memory
in free_pages_prepare() is scattered across two locations:
kasan_free_pages() for HW_TAGS KASAN and free_pages_prepare() itself.
This is confusing.

This and a few following patches combine the code from these two
locations. Along the way, these patches also simplify the performed
checks to make them easier to follow.

Replaces the only caller of kasan_free_pages() with its implementation.

As kasan_has_integrated_init() is only true when CONFIG_KASAN_HW_TAGS
is enabled, moving the code does no functional changes.

This patch is not useful by itself but makes the simplifications in
the following patches easier to follow.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---

Changes v2->v3:
- Update patch description.
---
 include/linux/kasan.h |  8 --------
 mm/kasan/common.c     |  2 +-
 mm/kasan/hw_tags.c    | 11 -----------
 mm/page_alloc.c       |  6 ++++--
 4 files changed, 5 insertions(+), 22 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 4a45562d8893..a8bfe9f157c9 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -96,7 +96,6 @@ static inline bool kasan_hw_tags_enabled(void)
 }
 
 void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags);
-void kasan_free_pages(struct page *page, unsigned int order);
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
@@ -117,13 +116,6 @@ static __always_inline void kasan_alloc_pages(struct page *page,
 	BUILD_BUG();
 }
 
-static __always_inline void kasan_free_pages(struct page *page,
-					     unsigned int order)
-{
-	/* Only available for integrated init. */
-	BUILD_BUG();
-}
-
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_has_integrated_init(void)
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 92196562687b..a0082fad48b1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -387,7 +387,7 @@ static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
 	}
 
 	/*
-	 * The object will be poisoned by kasan_free_pages() or
+	 * The object will be poisoned by kasan_poison_pages() or
 	 * kasan_slab_free_mempool().
 	 */
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 7355cb534e4f..0b8225add2e4 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -213,17 +213,6 @@ void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
 	}
 }
 
-void kasan_free_pages(struct page *page, unsigned int order)
-{
-	/*
-	 * This condition should match the one in free_pages_prepare() in
-	 * page_alloc.c.
-	 */
-	bool init = want_init_on_free();
-
-	kasan_poison_pages(page, order, init);
-}
-
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_enable_tagging_sync(void)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 012170b1c47a..e5f95c6ab0ac 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1368,15 +1368,17 @@ static __always_inline bool free_pages_prepare(struct page *page,
 
 	/*
 	 * As memory initialization might be integrated into KASAN,
-	 * kasan_free_pages and kernel_init_free_pages must be
+	 * KASAN poisoning and memory initialization code must be
 	 * kept together to avoid discrepancies in behavior.
 	 *
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
 	if (kasan_has_integrated_init()) {
+		bool init = want_init_on_free();
+
 		if (!skip_kasan_poison)
-			kasan_free_pages(page, order);
+			kasan_poison_pages(page, order, init);
 	} else {
 		bool init = want_init_on_free();
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/303498d15840bb71905852955c6e2390ecc87139.1643047180.git.andreyknvl%40google.com.

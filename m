Return-Path: <kasan-dev+bncBAABBOPZQOHAMGQEZJ2AXSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id D4DD947B578
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 22:59:21 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id v23-20020a05600c215700b0034566adb612sf2463433wml.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 13:59:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037561; cv=pass;
        d=google.com; s=arc-20160816;
        b=ciA5R2dyCyzCSLLRphBzm9ACsrIzs2VUIDZCDM++lTT+kaZVMVyBNAmgsywiISFhPg
         Q6cytej3Po8AOddEMhVzp18G5Fe4YrQwXkq4xGuIe2MrYlg6rTychd7SJwpTDSY/wTyw
         J/uptPxQcgXe3ErcXJ0i7wK3Vr1qnC5OwVkZbuhF8JC6ABPj7fBJ12ewANA2vTBzha6T
         MivoVGIo7PM3apk1MEzVxtUjPNN584qAptZqMeuTvTXP+wOFTE2+fgWh+akamU57of0c
         ucjpRsc65K6Do0PhWFDrWMqF1NX8lHrgbhbi/R6g8B/DBD/232IvAENdBKqQi1QAjGzJ
         LktA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5Wg0kSG0YSYYDl2yBpWtWYwqPMgP5dcR7ZwYLkfu56w=;
        b=YpXQ90cKf+j8hxVd8bgBmWmLlXLKdEe2w80geesPQ03WPUcbBtj3QAgUuXxb7f/My+
         bJYcyoHY9Fl3Ayg6UncAKXbJ3/4aUo0scPLwzBor/pS9ntIzOllx67FzrBgrr+j0SOIH
         OmgdCOjZAPnAEjIQfCNvl3bCbGiGlv7TYLiYORekTMCUryUJ8DaPQnxStmbf8EhlgvHK
         z4UvlgOnYoEpLMz3ioGFQlS+vipZNQeq8HJTn75EM0MjIGAoBW5Jd9xFAagBfsi6U/zG
         cwbCX5Z2Gt40rNhM36h8xYfjA411X2OqwBYW3CVQtlF3NDiADuO2pQlDv+mNvJm2z9RQ
         ydXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Q+FD7bXG;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Wg0kSG0YSYYDl2yBpWtWYwqPMgP5dcR7ZwYLkfu56w=;
        b=YMlBKHrJs46IAUGo11lnKJoDrkhuwxCO32Z79n6H0AHd4NZQchYA9KRPm71VN+gZDx
         zVsoaRObAQduG8FEkKSbn0GRrOAJRx4LWZj6EOz59rRvGc1z+AJutk+8df0OWtyH54g5
         ByvJdcw1pWKPN9UCE9Z8FOYJkFU1a7d5sOro9P9J7gSx8IFSpx9DcsdWQ6jL8pCK0n03
         VRWSO45TqQl8jFKyOa45ELsGi4nlsLdSuuPtjCcYUxAjU0Anv+mvj7vmPT7p33h5mHbF
         +j2e/w080SI8Jt/FOnWxf8wu5oJS7N/I3MrasoIYtCtTCkISOk/tRDtUVmpeX0AEiAnS
         f9Hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Wg0kSG0YSYYDl2yBpWtWYwqPMgP5dcR7ZwYLkfu56w=;
        b=1K5gAlCqhmGOtQyUvrFGKDjtkAA9CV6v4ZDG7yxqpudCFfJcjORO7Co6extP3JA4Pq
         lcIUeCPBapVFIohm/+MWhStR+QE0H4DFR1vNToByUrKgC1W52zhOANlXH6mWmmhmFImb
         de1Zcyir1Fg9857DuxF9rGOF2YZYGMw0GtCoOnI4YqM85z/iS5sJAQOFrC0IppXXkvMv
         W5ilRoWPGF0p6c5hGvAvYOOFfnErAPcevRlYoszOR36KWh4RTfZvCka/yi6v864jMCPS
         faGpulAg1yBRSLnebqF7cryv5ONwhCkd09NIczaWb+ekD1Q98OgaChSnnG5Z/duahXF3
         xHaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lL12nX/4vOboODSXNTv2or7sqSs+z85SVgtyJdjG6AImDONn/
	8pmm/Y5ZMelA7xtBq8HSmZs=
X-Google-Smtp-Source: ABdhPJxin+dJlX/OHR1oElp3rIc0dwmbN9qyYxwJlelYajp1WbK+Hl3ZrZWLuiHppLLZnruJKv9FdQ==
X-Received: by 2002:a5d:6d0e:: with SMTP id e14mr89154wrq.407.1640037561633;
        Mon, 20 Dec 2021 13:59:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d21b:: with SMTP id j27ls6377943wrh.3.gmail; Mon, 20 Dec
 2021 13:59:21 -0800 (PST)
X-Received: by 2002:adf:a489:: with SMTP id g9mr88344wrb.235.1640037561086;
        Mon, 20 Dec 2021 13:59:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037561; cv=none;
        d=google.com; s=arc-20160816;
        b=tWVmIRTVSGPCxXY9C3QyFZD5VDVadwRT6oY8FX+kym22ENAu4K8feedMH/LZM8g8J1
         3SH47/VKGDlQwaxMd0kfwGrWBdchcMCLcUjE5rmhQsGajgSSnwouj4hauNfMmWuD/5jG
         pTwYsDqNAJaz/qmoV+T04zQBHDatZPfM/7WRY3x0JGT3vXbmpcRGB9cWFxHnJi3o1ezq
         y2joU7McWQ9hsEA9ZKo7xWl2OCwRSSNl4/KasYvyaycY9TBEC32Xrq3HVF2wsT3cPiea
         4kjuOJLNKMY9tP2k07VM/ouxRnpmK8xZpC9XO2d365LJvR7Jj/BD4o41pHT+iRDTVsyp
         2tfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=W+nNbb3pTxbMZ8HlsYjmZQU7bd/tE4UK1EaMgljEPUA=;
        b=TwabyHl9ykx39daLckmUnaR0+H01q2pRi9uAvRYJPfX2VP2hUQUc0xLOxQoDWrXjmE
         c1p9IgBZxQfLUA4l5xHjGEjBYq9nW9G7TH7PTJ3E51+d3Qvs5XzKr9xsw6Wr9Z1HiUEN
         +sUXABp3CTvbUWLXMwGxgHI1R8JiDJKQLv9RlV31+aIbM4NDZkxHFcElqFEYzicgBXfS
         4PuwoRhBgH953/frc0FvNrUvA4takx96Hv1TKKLGuZpWfRL7kZT86trJfwp05lVZTsjs
         jHh0X2+NSZ+9OCyO24pZpZ2g6vDFWbacyiiSFkrZYj9c+VpBf+fC6qUc4BwhZi9CS5kp
         JC8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Q+FD7bXG;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id p22si48846wms.1.2021.12.20.13.59.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 13:59:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH mm v4 10/39] kasan, page_alloc: merge kasan_alloc_pages into post_alloc_hook
Date: Mon, 20 Dec 2021 22:58:25 +0100
Message-Id: <e6f1e29d26a729affccae19df8e2c95edb997575.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Q+FD7bXG;       spf=pass
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
index 9ecdf2124ac1..a2e32a8abd7f 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2397,6 +2397,9 @@ static bool check_new_pages(struct page *page, unsigned int order)
 inline void post_alloc_hook(struct page *page, unsigned int order,
 				gfp_t gfp_flags)
 {
+	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
+	bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+
 	set_page_private(page, 0);
 	set_page_refcounted(page);
 
@@ -2412,15 +2415,22 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e6f1e29d26a729affccae19df8e2c95edb997575.1640036051.git.andreyknvl%40google.com.

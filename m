Return-Path: <kasan-dev+bncBDY7XDHKR4OBBBWWXSDAMGQEEZPYF7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id B490D3ADE34
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 13:48:23 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id f24-20020a631f180000b0290222eb79d493sf7516418pgf.8
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 04:48:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624189702; cv=pass;
        d=google.com; s=arc-20160816;
        b=gKL2js5YLdtTm+o+YsYf1T8XR+CLXo7nDWVvYC+JhWIcXrlyUR7ZZlvAULdmvExPCo
         XXB092CpU3u5D28lr53sFOui2a08aTIZPa9vAJdDwt8e/NCpvPJ3A131Vi2hAobfCrTW
         +FihU0tsDdpOQ/hBCSPKtYsmZm9g2QcWrCcJan+Og3SuZArPgqmeVZaoZPWnBLPS+bJa
         /nTqsCq0ShwKYqecH9KONvK6dDXcQapg9MV18IYXKeuZjF+/v5oSUZdIsAV/5W3AJ3rc
         nECgCz/IRFBNsnJtvI0UMp4G8NBD5IomzG/ARCO4qiWkVapV3aW6RkUoQ0ce/bUkhbg4
         udzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+umxjjF/yv9quW0X+KeQy4HBlS2n1N4FyExgKPiksjU=;
        b=Ym8LSHWDvdRBvmiKhyiChINDIWLcBrFcATNOmmb/sC8fLcZquO9pu4ovC8WnxngaeQ
         ivh1hWwaghy6FZ7jx2NqaHbo0K249I8amS49bkLOTUQ1f/6Z4f4PJhRaEh9Umw6tOWGs
         3DsY77UePcljLGDan+XRhsWVAIL90f5UbvBmN2UojRqq024DTs15oqD1rR3TPAZWtecZ
         I3eDp5RAGbFshgI3rKqZyLWA+S9qq5LxY4MXdXh/6giu4CP4wTrgWwBa88dHDWpdru2k
         ZcOh29CeBW/A+qaCPpc27tM9YvKxc+Mq53D1LhoBkoFMwEjT4JEPYQ/GmLd4HIkN7KYF
         7r1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+umxjjF/yv9quW0X+KeQy4HBlS2n1N4FyExgKPiksjU=;
        b=DrczuEdHatzv3/XD26gSVGrPaobgnCXpFVgNtgeNJoO6NF1IUZXKxG6EDot5uwx6/6
         wSWtM9iF25aAL4JCKMzLnZaxcKTi79gHISKy58NFNiOT8kwyU3467vz+PguaruHx6T1c
         TYg/oiTFgbwEnk+ikZSrkSPmov1ZfQ9CzIcOa6vNV6lWCwJT5ZecRhoaNjkNvqpEKDtf
         51foLHc7SRh0/Dn7+UxXYFSxktm60z5XqwKa2/azOKLIbZBdGg98omvWmJ/D+sovhfqD
         4vCl9DHg5+IsIkpY/TMSRBSduDWs6TfEq4qaCw4STOoRxzSF7gIoY910A9EUTBpA8m7J
         XMqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+umxjjF/yv9quW0X+KeQy4HBlS2n1N4FyExgKPiksjU=;
        b=BtXug3eZRoT3RREZeo7mNakqkLsSZH3bY+dBL9l6omSkgJY/eVINBFOY0EMTTkDte5
         ENIBLaJhkR+MT48DtsQpAhoIDhz4l0dWW4Fd2k/pMkLKMZGikMzFWyY50W4Fda+sgyZL
         yleTRoCZSvyS4koNioBWQR6APQy3IcsZi3huv4u+KgHfmjOhKlbmHfdb2J9YK2DC2FOv
         6bzPxutZYtVG7/A56JwW/v6tRsLcGMZHwrYHcBXZQPbcjISIBtAMG3PgQZBKWxMrRKFB
         AbKhRhKFnrT4pJJpa8lssO5VEF250/weYiLtAmH0FPGY6OEyF61fxeG600jGv9gZxDfQ
         afYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5313qgAdyI9sgkEaQL4yXZ80Z4uCsOuTkWNyVDGADDp9MckpKUU+
	Fp8EwJzIVTn1nWWiKhA0k8E=
X-Google-Smtp-Source: ABdhPJySt8CGXFEh36HbM/QfeDrGvMMhlr9JxEe3ZXy9SgwXLmM/V3U6dRhJXjaGJFSGpbXjxJRIGQ==
X-Received: by 2002:a17:902:694b:b029:118:b8b1:1e23 with SMTP id k11-20020a170902694bb0290118b8b11e23mr13037182plt.31.1624189702226;
        Sun, 20 Jun 2021 04:48:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1d2:: with SMTP id e18ls7176673plh.6.gmail; Sun, 20
 Jun 2021 04:48:21 -0700 (PDT)
X-Received: by 2002:a17:90a:f291:: with SMTP id fs17mr2616254pjb.47.1624189701664;
        Sun, 20 Jun 2021 04:48:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624189701; cv=none;
        d=google.com; s=arc-20160816;
        b=e2dnbMuL0y+eB41rsaZJQMxSfBQxGoQEYEdpI33URNmo97ZU1xGDA5KMOTVyrJZIPx
         aOH2uMORR/H43oXxk2wXuHURZb9HDGBYCagABVOGtPXBqf/sWh2FxfWgb0G6hIyCPr8L
         35UEV5WcUBqajHiUPM1oGr8jd+ug4Nb4naIl/8Ff52kgWyPq9+HE4IPkfZaYtrnDszDJ
         isnlgJzwI3SJfMJeMjZdiU5DYzR/T+YT0cSjCaNgABjX/gWomsjdgwMvdH20tE3DJubb
         0f+CagURKTKnJKOP0KZdavrXTYzDsBhYYYojKlWz8s69mUXewXtp/ZeJ40YHK2szmZxy
         T7BQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=+4encSbvis6xMEH3OsaTbn9VEXfIKmsNg9IoT4QG5kA=;
        b=rtr6cYUxa5Ma/KV51Qwnu/rztcsogdt3iLyPNju4kfEIbNdfDVr9cV9EDa6wfjOqEN
         V2PlFVRCruCW6/G/ElvhvI4YqxC5rxkZ8SgfZV12VjY78OkzlkjxPJ0st0Mpbu0/5/SG
         jKwmnY1Wavq/UJGWkaNPJ6VtVRvseOLNKriAa97vPP6brSg+CmSOD52Cc9EnFoz2LQ7f
         Q2t4H56inVtTW2hHGb6KVh6lMak0qSYKzl7bnYB/M6psfkiTNO+im4qan3AbC6G/qrf5
         xY9bJpHg2/DHKLcODQpZ/LVzsoXg6Qq7k4/BeqD35AE83rjjtju1SsjPwhC2HiyvgHdk
         0fsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id z17si1138133pjn.2.2021.06.20.04.48.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 20 Jun 2021 04:48:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: bdeb2ea4e5b344498d3bc2a8548bf087-20210620
X-UUID: bdeb2ea4e5b344498d3bc2a8548bf087-20210620
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1556148139; Sun, 20 Jun 2021 19:48:17 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sun, 20 Jun 2021 19:48:09 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sun, 20 Jun 2021 19:48:09 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver
	<elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>,
	<chinwen.chang@mediatek.com>, <nicholas.tang@mediatek.com>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v3 2/3] kasan: integrate the common part of two KASAN tag-based modes
Date: Sun, 20 Jun 2021 19:47:55 +0800
Message-ID: <20210620114756.31304-3-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com>
References: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

1. Move kasan_get_free_track() and kasan_set_free_info()
   into tags.c
2. Move kasan_get_bug_type() to header file

Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Suggested-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---
 mm/kasan/Makefile         |  4 +--
 mm/kasan/hw_tags.c        | 22 ---------------
 mm/kasan/report_hw_tags.c |  6 +---
 mm/kasan/report_sw_tags.c | 46 +-----------------------------
 mm/kasan/report_tags.h    | 55 ++++++++++++++++++++++++++++++++++++
 mm/kasan/sw_tags.c        | 41 ---------------------------
 mm/kasan/tags.c           | 59 +++++++++++++++++++++++++++++++++++++++
 7 files changed, 118 insertions(+), 115 deletions(-)
 create mode 100644 mm/kasan/report_tags.h
 create mode 100644 mm/kasan/tags.c

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 9fe39a66388a..634de6c1da9b 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -37,5 +37,5 @@ CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 
 obj-$(CONFIG_KASAN) := common.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
-obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o
-obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o
+obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o tags.o
+obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o tags.o
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index ed5e5b833d61..4ea8c368b5b8 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -216,28 +216,6 @@ void __init kasan_init_hw_tags(void)
 	pr_info("KernelAddressSanitizer initialized\n");
 }
 
-void kasan_set_free_info(struct kmem_cache *cache,
-				void *object, u8 tag)
-{
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta)
-		kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
-}
-
-struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-				void *object, u8 tag)
-{
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (!alloc_meta)
-		return NULL;
-
-	return &alloc_meta->free_track[0];
-}
-
 void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
 {
 	/*
diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
index 42b2168755d6..ef5e7378f3aa 100644
--- a/mm/kasan/report_hw_tags.c
+++ b/mm/kasan/report_hw_tags.c
@@ -14,11 +14,7 @@
 #include <linux/types.h>
 
 #include "kasan.h"
-
-const char *kasan_get_bug_type(struct kasan_access_info *info)
-{
-	return "invalid-access";
-}
+#include "report_tags.h"
 
 void *kasan_find_first_bad_addr(void *addr, size_t size)
 {
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index 821a14a19a92..d965a170083e 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -26,51 +26,7 @@
 
 #include <asm/sections.h>
 
-#include "kasan.h"
-#include "../slab.h"
-
-const char *kasan_get_bug_type(struct kasan_access_info *info)
-{
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
-	struct kasan_alloc_meta *alloc_meta;
-	struct kmem_cache *cache;
-	struct page *page;
-	const void *addr;
-	void *object;
-	u8 tag;
-	int i;
-
-	tag = get_tag(info->access_addr);
-	addr = kasan_reset_tag(info->access_addr);
-	page = kasan_addr_to_page(addr);
-	if (page && PageSlab(page)) {
-		cache = page->slab_cache;
-		object = nearest_obj(cache, page, (void *)addr);
-		alloc_meta = kasan_get_alloc_meta(cache, object);
-
-		if (alloc_meta) {
-			for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
-				if (alloc_meta->free_pointer_tag[i] == tag)
-					return "use-after-free";
-			}
-		}
-		return "out-of-bounds";
-	}
-
-#endif
-	/*
-	 * If access_size is a negative number, then it has reason to be
-	 * defined as out-of-bounds bug type.
-	 *
-	 * Casting negative numbers to size_t would indeed turn up as
-	 * a large size_t and its value will be larger than ULONG_MAX/2,
-	 * so that this can qualify as out-of-bounds.
-	 */
-	if (info->access_addr + info->access_size < info->access_addr)
-		return "out-of-bounds";
-
-	return "invalid-access";
-}
+#include "report_tags.h"
 
 void *kasan_find_first_bad_addr(void *addr, size_t size)
 {
diff --git a/mm/kasan/report_tags.h b/mm/kasan/report_tags.h
new file mode 100644
index 000000000000..1cb872177904
--- /dev/null
+++ b/mm/kasan/report_tags.h
@@ -0,0 +1,55 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Copyright (c) 2014 Samsung Electronics Co., Ltd.
+ * Copyright (c) 2020 Google, Inc.
+ */
+#ifndef __MM_KASAN_REPORT_TAGS_H
+#define __MM_KASAN_REPORT_TAGS_H
+
+#include "kasan.h"
+#include "../slab.h"
+
+const char *kasan_get_bug_type(struct kasan_access_info *info)
+{
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
+	struct kasan_alloc_meta *alloc_meta;
+	struct kmem_cache *cache;
+	struct page *page;
+	const void *addr;
+	void *object;
+	u8 tag;
+	int i;
+
+	tag = get_tag(info->access_addr);
+	addr = kasan_reset_tag(info->access_addr);
+	page = kasan_addr_to_page(addr);
+	if (page && PageSlab(page)) {
+		cache = page->slab_cache;
+		object = nearest_obj(cache, page, (void *)addr);
+		alloc_meta = kasan_get_alloc_meta(cache, object);
+
+		if (alloc_meta) {
+			for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
+				if (alloc_meta->free_pointer_tag[i] == tag)
+					return "use-after-free";
+			}
+		}
+		return "out-of-bounds";
+	}
+#endif
+
+	/*
+	 * If access_size is a negative number, then it has reason to be
+	 * defined as out-of-bounds bug type.
+	 *
+	 * Casting negative numbers to size_t would indeed turn up as
+	 * a large size_t and its value will be larger than ULONG_MAX/2,
+	 * so that this can qualify as out-of-bounds.
+	 */
+	if (info->access_addr + info->access_size < info->access_addr)
+		return "out-of-bounds";
+
+	return "invalid-access";
+}
+
+#endif
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index dd05e6c801fa..bd3f540feb47 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -167,47 +167,6 @@ void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
 }
 EXPORT_SYMBOL(__hwasan_tag_memory);
 
-void kasan_set_free_info(struct kmem_cache *cache,
-				void *object, u8 tag)
-{
-	struct kasan_alloc_meta *alloc_meta;
-	u8 idx = 0;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (!alloc_meta)
-		return;
-
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
-	idx = alloc_meta->free_track_idx;
-	alloc_meta->free_pointer_tag[idx] = tag;
-	alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
-#endif
-
-	kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
-}
-
-struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-				void *object, u8 tag)
-{
-	struct kasan_alloc_meta *alloc_meta;
-	int i = 0;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (!alloc_meta)
-		return NULL;
-
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
-	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
-		if (alloc_meta->free_pointer_tag[i] == tag)
-			break;
-	}
-	if (i == KASAN_NR_FREE_STACKS)
-		i = alloc_meta->free_track_idx;
-#endif
-
-	return &alloc_meta->free_track[i];
-}
-
 void kasan_tag_mismatch(unsigned long addr, unsigned long access_info,
 			unsigned long ret_ip)
 {
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
new file mode 100644
index 000000000000..8f48b9502a17
--- /dev/null
+++ b/mm/kasan/tags.c
@@ -0,0 +1,59 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains common tag-based KASAN code.
+ *
+ * Copyright (c) 2018 Google, Inc.
+ * Copyright (c) 2020 Google, Inc.
+ */
+
+#include <linux/init.h>
+#include <linux/kasan.h>
+#include <linux/kernel.h>
+#include <linux/memory.h>
+#include <linux/mm.h>
+#include <linux/static_key.h>
+#include <linux/string.h>
+#include <linux/types.h>
+
+#include "kasan.h"
+
+void kasan_set_free_info(struct kmem_cache *cache,
+				void *object, u8 tag)
+{
+	struct kasan_alloc_meta *alloc_meta;
+	u8 idx = 0;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return;
+
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
+	idx = alloc_meta->free_track_idx;
+	alloc_meta->free_pointer_tag[idx] = tag;
+	alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
+#endif
+
+	kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
+}
+
+struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+				void *object, u8 tag)
+{
+	struct kasan_alloc_meta *alloc_meta;
+	int i = 0;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return NULL;
+
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
+	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
+		if (alloc_meta->free_pointer_tag[i] == tag)
+			break;
+	}
+	if (i == KASAN_NR_FREE_STACKS)
+		i = alloc_meta->free_track_idx;
+#endif
+
+	return &alloc_meta->free_track[i];
+}
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210620114756.31304-3-Kuan-Ying.Lee%40mediatek.com.

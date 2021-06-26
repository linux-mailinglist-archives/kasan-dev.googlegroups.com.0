Return-Path: <kasan-dev+bncBDY7XDHKR4OBB2HZ3ODAMGQE3DXRT6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id C90A73B4DE7
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Jun 2021 12:09:45 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id z5-20020a17090ad785b029016ef9db92bfsf7171135pju.0
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Jun 2021 03:09:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624702184; cv=pass;
        d=google.com; s=arc-20160816;
        b=rZlyiQAYeYJV2fSAU2vNGmGRTKDzln5r5N4K7ZKJUOBpmPr8tu3alMi/f5NisDPBLf
         gub15YmWesU/umJBHzV4r5ArjH8g+K8AgKCbZDWT+DosXm1sBmQVcO6lpDcxyMXVn/Sa
         +gU2u69UP+npQua5kqVBO2trkACpMaCzZz9woBzYO4lrMiiCWBSf8xR6s2906g9dX4cT
         6dRPTtc7YszO2ILQg+1Vek+XxomhX+geSsgDbn1gEndAQEY8c70oHSYZ57LMu7J7YWx/
         1QxuyhI8tH5nPsC/rVBdXMlYJdRxevFAgD1F+Cu301dlP/FNTIbmCH24iaGT0+y3ehbg
         w49Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=A8DtS5nJpU2r9O6BIcC8wRC2sVm0nyE5nv44YHKZPVs=;
        b=dDulfdGimu4DHQt4wjsyPydjRn66PpSmaNA4YSkEBknc9/JFrXV/qwLcQPOTrwrtHn
         evMO+gyBwqEAgobSgDWt4rKNw6HTdZ6aOHsOvgUBAB2BsKD8mWH+CoXLms8Q8HQZJwVO
         JmvnhDGrgoF54FBDR/7N3eGrClVEjc1ztFrOH1LARCbSToPSXQS8F3sjpql48mM8UFQ8
         Q+ZIb3/Ua7oAj223gViZDgL0gvMx9z9IOdvTC2NaxBgqK85oMfuVhol96RsBdrHcw3Al
         7YODJYawUhAiP2/8rc+VB3WPJVYVAGrcydm0Eawk3attMcdEnuUevTyax0OemVxyhmtE
         /2uA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A8DtS5nJpU2r9O6BIcC8wRC2sVm0nyE5nv44YHKZPVs=;
        b=GxHDwQ6VS2WHFx3F8MYNmwDTo8DvTiGheHF9awvkxYxWjI6aK8u7rdxhYf7lzYgBtv
         8tVNOY2FdVZt/D8yxuclyqQtZr4YTTtdTSqQgxbwVmMIg5SavJaWjdLNqFO5za3Ae/SP
         UUDMEaW+WRIEdXhysR1hBwpv5BM/o11DOzZ2wtr3+2rP6Q9/Qcj/PfiHsE2YDkAuJ3g1
         1l7xcB218oK5M6QA0KODBmfeDTDck98FTbjdga2qzCqy9pjNHinhjDI4Ut8y0OEXIgm8
         VXuBqJYc2rjjF+bwFiEfSzxj4kj3VpV9L7os9uypv1NgPGN6tJADHVHsn9BtkKFXFxCb
         xdJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A8DtS5nJpU2r9O6BIcC8wRC2sVm0nyE5nv44YHKZPVs=;
        b=VeDw+FZkBamgIk1jq9OXUQMQflxJzGwiymfwLoMLGQ1W0EGM7wDwXbtD8qmyH+Xcqq
         yb789TnqYMVnqKx6Q8LMmSFKFTSZm8gFPn14smmFJRfKqvr3kLF0EnpGFv8Gp63oegzN
         m6Xe9N+bP9crGTx1HisYCDiAqhwimbHsIpDpm/9V7M7AfFMCu32VDjhHckcTL09trLj2
         UW2FiQ3GhJNnjxszLGsgqjCQtAElxgZe+H6I6QWzrD8fCia9lxQXstEGUBWwyvRU8BIH
         PP+Gpps/4u28K9UoSlDRNwKpMNSWY96DoitzS0fSVZcnFLK4XYFzHnRfeUkCN4ds8g0v
         93zQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5321g8GXS7+H33HyIacf0mnz32zxOXMJH6hGNvcHl3BEvSg9exEy
	AoiWCv+iKr0TGqamAMfzO/8=
X-Google-Smtp-Source: ABdhPJycFMk94JO3VyXwBkJ9BuEXN0veu7o266Tpkx8csHEpZSs3BzkVnAGoY/uK1EFQIbIMeq3hcQ==
X-Received: by 2002:a63:e14:: with SMTP id d20mr13925906pgl.35.1624702184564;
        Sat, 26 Jun 2021 03:09:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b418:: with SMTP id x24ls6119243plr.7.gmail; Sat, 26
 Jun 2021 03:09:44 -0700 (PDT)
X-Received: by 2002:a17:903:304e:b029:11d:41c:fa73 with SMTP id u14-20020a170903304eb029011d041cfa73mr13044407pla.82.1624702183998;
        Sat, 26 Jun 2021 03:09:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624702183; cv=none;
        d=google.com; s=arc-20160816;
        b=L6t+kVUAnElaaOdfVOdlALm9kPXrpdqRtPghJ90v+P7sUTiM90jBL8VxrqiPYqvzOM
         m7KHKaXwCqzNU8q24Dq2LAcjqWh0OnVCdxQA1yFL993LHfHrZu9gpJCgwvD2NcxF0Rbj
         IukYVcbpxPIoxJJqvi/EIXrLyjdFSPy6tpkLxsLmFt3vDKGTVN9Sll9Ds52suKpeBvjd
         IFlKsmAcj/IczwsL308QpmKm2IKQ0251TJ+y+KbKPeLpuqhBD3VvApVQ9bhLOT6MvvgE
         V6+8IccJesMn3O/RCaqelzMmfqNea0WbkeYKkMwzTg33jEjc7ZLm45f8HHzdk2BRvamM
         0OZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=m3Fk88H0ZmXdJd0sTPa8MeDf1SADq8YjrIyazKMhoHw=;
        b=WbqL3GZAQSj0OT6aCf0ODLVYcIEb5FHOKYavXXx3HZ7RQz9WalELlizVHBIRyB0Blc
         WuiPR4AfenvMIDXNZ2YDqWECk846bv52kXMJ7kOQtgU7Ju4R542VBxcrMtFeHyfIyZcQ
         UXuop0yvZulYd9jlsD3VeJQHaXLTZW0AF/vbgXMjQxtonjnBCmLnfDnteYS5ei5pXIad
         wX6JWgRSBVUsxr8ssxFy3KyJsmRJx7azyZWocbqaUB35HlGIiJqAsXenIYgRcN7E19jj
         kr17uteg3D6MBX0dqIloSR4KNnelGYO3PXUIGzmogrGHTcIwddpdsbKWQ0v5BUGh8ei4
         +fKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id b18si592899pfl.1.2021.06.26.03.09.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 26 Jun 2021 03:09:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 63f7999c6052484eb8d685a58c06e5fa-20210626
X-UUID: 63f7999c6052484eb8d685a58c06e5fa-20210626
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1508738528; Sat, 26 Jun 2021 18:09:38 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs02n1.mediatek.inc (172.21.101.77) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 26 Jun 2021 18:09:36 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 26 Jun 2021 18:09:37 +0800
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
Subject: [PATCH v4 2/3] kasan: integrate the common part of two KASAN tag-based modes
Date: Sat, 26 Jun 2021 18:09:30 +0800
Message-ID: <20210626100931.22794-3-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210626100931.22794-1-Kuan-Ying.Lee@mediatek.com>
References: <20210626100931.22794-1-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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
   into tags.c and combine these two functions for
   SW_TAGS and HW_TAGS kasan mode.
2. Move kasan_get_bug_type() to report_tags.c and
   make this function compatible for SW_TAGS and
   HW_TAGS kasan mode.

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
 mm/kasan/report_hw_tags.c |  5 ----
 mm/kasan/report_sw_tags.c | 43 ----------------------------
 mm/kasan/report_tags.c    | 51 +++++++++++++++++++++++++++++++++
 mm/kasan/sw_tags.c        | 41 ---------------------------
 mm/kasan/tags.c           | 59 +++++++++++++++++++++++++++++++++++++++
 7 files changed, 112 insertions(+), 113 deletions(-)
 create mode 100644 mm/kasan/report_tags.c
 create mode 100644 mm/kasan/tags.c

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 9fe39a66388a..adcd9acaef61 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -37,5 +37,5 @@ CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 
 obj-$(CONFIG_KASAN) := common.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
-obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o
-obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o
+obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o tags.o report_tags.o
+obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o tags.o report_tags.o
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
index 42b2168755d6..5dbbbb930e7a 100644
--- a/mm/kasan/report_hw_tags.c
+++ b/mm/kasan/report_hw_tags.c
@@ -15,11 +15,6 @@
 
 #include "kasan.h"
 
-const char *kasan_get_bug_type(struct kasan_access_info *info)
-{
-	return "invalid-access";
-}
-
 void *kasan_find_first_bad_addr(void *addr, size_t size)
 {
 	return kasan_reset_tag(addr);
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index 821a14a19a92..d2298c357834 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -29,49 +29,6 @@
 #include "kasan.h"
 #include "../slab.h"
 
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
-
 void *kasan_find_first_bad_addr(void *addr, size_t size)
 {
 	u8 tag = get_tag(addr);
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
new file mode 100644
index 000000000000..8a319fc16dab
--- /dev/null
+++ b/mm/kasan/report_tags.c
@@ -0,0 +1,51 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Copyright (c) 2014 Samsung Electronics Co., Ltd.
+ * Copyright (c) 2020 Google, Inc.
+ */
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210626100931.22794-3-Kuan-Ying.Lee%40mediatek.com.

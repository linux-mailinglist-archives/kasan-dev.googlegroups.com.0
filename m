Return-Path: <kasan-dev+bncBDGPTM5BQUDRBWOVRD3AKGQESIETG5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B3331D70EB
	for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 08:27:39 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id i128sf8011912pfc.4
        for <lists+kasan-dev@lfdr.de>; Sun, 17 May 2020 23:27:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589783258; cv=pass;
        d=google.com; s=arc-20160816;
        b=tqTuJxp16yzUfUXKSZHZlz/neCy0Ghm2Am21MQigHL4p6w75ntS3TPI83PVrg1GOSf
         ZBorJgJhzn88T+z2hTaqYwf7KJ2jej8P0sQKjr14nQqwsD1X9VoS3tz44qjKgdZQOlka
         WPP0qPoeLpQNe/x9cf34Vp2+sbaN1e+hNBs8Xrt1wwJj0E1tAkAajManOigxlrwmV8jZ
         Jozv4bPJ+qXz2RQjP6A7u0mw7KlgijSaunDF1oVCwgQYkB0isJlcatI2ODtnmNEPVQ4s
         mlMxZHYAqAgJqPY7PYq6gHeP4PtG+w80hU3MyyxUHNeZ0f6mYBjhpKSFU17iBy8dWpmw
         /5tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=xYHbHPhvEb9eHUdDxx9y/NVytkl8tpd4gLlgz4T8jR0=;
        b=mFb2UFBvf2ZCICSVx2GRmkC7lk8pO5XOpfORpnysHpPhOqqbgTbQydzCobHkiDXEJT
         qhLYw3+HFtmsQE0WjydPbo6u+W3b6LxCRbXK/HjIPD517Ku2nqUOvq8R7s2jCkKcpShW
         8RjQwt3ZVtJ+/gz2FPOXNADyVXckd6VW2bmxC3ZliEYcvXP7odVAym9czCOnUoxDpJDc
         iHYxeXAJo1QuoYSC/gp/tEZe/DM0xzGZcMegZkQ1NoavjUoOkMIFyYwmktxR2UQHvd97
         r1HNOlCrzumkREGAcIPSEK8VlWDEhyUyoJX1Htja+7N1q7RXFYYds2XJnMfzuNiMwZvj
         16cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=nHwFdGhZ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xYHbHPhvEb9eHUdDxx9y/NVytkl8tpd4gLlgz4T8jR0=;
        b=rA3Sqx/vIRJ3nGyRIAWE4iJEUkACcYEqnOR7hz7N4qi5Ok0lSKWLQxJoU/Q00T9yOG
         LPHy2IoQZ/T20kABXWQXqTBABG80f4+9yihrbTom2pE/F1jGDtd6dHmhZn8fwZz+6gVs
         jGgX3zsNBcan/MEHR14MBsJebR5m6LImeTl+PkeEV3bMEZHqQ0XkWM2iutuZ4ljNWOvU
         pGIDlRPm995PUJF8pxpHQl0Lg/tuaEz4vgRqFPi05VXsvm1fCehXq6ImomDvjWbq4Mxo
         XJeTYIXJzWOQPtLG7rOsiKfuivXekQJGUMQq6bTS6cvJyuxS9omTPvBV3/gG1GDAW6DE
         7fRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xYHbHPhvEb9eHUdDxx9y/NVytkl8tpd4gLlgz4T8jR0=;
        b=amI6gsLMLzoADHDdpAZg1sZCd0GrsX1du0Vi1wwBU8hKvb5fxZJ/dgIkg4/52sKmGs
         p+T3VGiI83GF0MfMW223EYo0vTnACxbTzz3IEazqz4ABPxp3zU6g9e466q6F6pRJXIJy
         W1GLimP0gwCGpcYjpGIsUADKPwbH1D1ttbj4P29ogFD/pCrUa+cbytqzsBhs/8LzIYTh
         UP5wK00XMkIz6ApxpFEVYMvMhcHAO6gRgRh6uS35IvAq46ZktUFEOn063AqtTKt9A9Of
         lniTECTrt89IFXm+aC+vEJZeHWOaBHtPbfzADUirvy/NM37ap2rEub3ayZ1AshRqYuBG
         yf6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533WMILFwptmlz76srZzdM8JmTQGv1KwybeDOjR+fVH9xxcuqV6M
	6Jfaf1lIhP8BgQ7YcVgjz7w=
X-Google-Smtp-Source: ABdhPJwZqAcUZt7IlwH5Ej+Ztm7BfMa3lLHbKwhci/hWcLC7AX/qlJ4X0yz2czD1w9pO8qvkSsL4TQ==
X-Received: by 2002:a17:90a:5287:: with SMTP id w7mr18200088pjh.66.1589783257900;
        Sun, 17 May 2020 23:27:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:384c:: with SMTP id nl12ls4727220pjb.2.canary-gmail;
 Sun, 17 May 2020 23:27:37 -0700 (PDT)
X-Received: by 2002:a17:902:b484:: with SMTP id y4mr8751138plr.21.1589783257334;
        Sun, 17 May 2020 23:27:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589783257; cv=none;
        d=google.com; s=arc-20160816;
        b=DGHxtx1ALAITG5lg5oMySmfpvb/rqN5YCteovHoFyvqdc5vM/7nTso7GnEXUlM23ca
         hPN+8lJykIxHCOuiK9wy/XIQEGCxz0EWz+kRfXMruxm2wTW7bmZ0unc9wKP+I4im9fE+
         PGBYn6cEMdRJWvLRcYu8+y1Ve+NIEd/lH2Ed1oy+V0OTV13CJ2mzz4QiG8GwJPT+CVYi
         IqDrh64L9+PSba6Ceh9LX8+svnJSeW3bxvQvUktJON3Pb+rUsnG2fVC+WfQ1lCeYYtcx
         5ReT9btawIS2zmKYCk+JIhpSvGne6O6wRPCe4l5aIolzTM1emI9cqA8J6Nf6QmV5mug8
         s9DA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ISBcatq6mVn60qvM3IFa85BGa9k8Ralk+4f4AH+hBXM=;
        b=c/8B/uF1XtT444NdbNEzTWVPY2AODN8LlNG9uqjzZTLOqgwK4OY/kHSa/j0OHqbt99
         IlhkTtzikIYH6i+NHHj6CsV27fba/bLL35dXmxIgXSJUglzwVTB943eYVFL2qfqapJGD
         DWGyI3LYlvZ8LfDuxF6HI+PFLIWz5M9QyUhBX2wRqgn1Ba9/QaJvbsJDRdbmh3sgbOAB
         CQss6/XVuLO5Yls7TpzmPbWPM8GagSro5JMnpRJGw98tEoYOwT5hEC+DXeSN0HIfSfTz
         a6TQuoeU9RegLmhziPYOR/7eXs26Wk5YLwpEYD8YdRstnr8i1atVAHyphxu7rdwWhr84
         3Bbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=nHwFdGhZ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id bi9si691441plb.3.2020.05.17.23.27.36
        for <kasan-dev@googlegroups.com>;
        Sun, 17 May 2020 23:27:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 21cbb749ac784cbb9868ef3736957364-20200518
X-UUID: 21cbb749ac784cbb9868ef3736957364-20200518
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1093623343; Mon, 18 May 2020 14:27:32 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 18 May 2020 14:27:30 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 18 May 2020 14:27:30 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v3 2/4] kasan: record and print the free track
Date: Mon, 18 May 2020 14:27:30 +0800
Message-ID: <20200518062730.4665-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=nHwFdGhZ;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
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

Move free track from slub alloc meta-data to slub free meta-data in
order to make struct kasan_free_meta size is 16 bytes. It is a good
size because it is the minimal redzone size and a good number of
alignment.

For free track in generic KASAN, we do the modification in struct
kasan_alloc_meta and kasan_free_meta:
- remove free track from kasan_alloc_meta.
- add free track into kasan_free_meta.

[1]https://bugzilla.kernel.org/show_bug.cgi?id=198437

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
---
 mm/kasan/common.c  | 33 ++++++++++-----------------------
 mm/kasan/generic.c | 18 ++++++++++++++++++
 mm/kasan/kasan.h   |  7 +++++++
 mm/kasan/report.c  | 20 --------------------
 mm/kasan/tags.c    | 37 +++++++++++++++++++++++++++++++++++++
 5 files changed, 72 insertions(+), 43 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 8bc618289bb1..6500bc2bb70c 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -51,7 +51,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags)
 	return stack_depot_save(entries, nr_entries, flags);
 }
 
-static inline void set_track(struct kasan_track *track, gfp_t flags)
+void kasan_set_track(struct kasan_track *track, gfp_t flags)
 {
 	track->pid = current->pid;
 	track->stack = kasan_save_stack(flags);
@@ -249,9 +249,7 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	*size += sizeof(struct kasan_alloc_meta);
 
 	/* Add free meta. */
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
-	    (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
-	     cache->object_size < sizeof(struct kasan_free_meta))) {
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
 		cache->kasan_info.free_meta_offset = *size;
 		*size += sizeof(struct kasan_free_meta);
 	}
@@ -299,24 +297,6 @@ struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
 	return (void *)object + cache->kasan_info.free_meta_offset;
 }
 
-
-static void kasan_set_free_info(struct kmem_cache *cache,
-		void *object, u8 tag)
-{
-	struct kasan_alloc_meta *alloc_meta;
-	u8 idx = 0;
-
-	alloc_meta = get_alloc_info(cache, object);
-
-#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
-	idx = alloc_meta->free_track_idx;
-	alloc_meta->free_pointer_tag[idx] = tag;
-	alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
-#endif
-
-	set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
-}
-
 void kasan_poison_slab(struct page *page)
 {
 	unsigned long i;
@@ -396,6 +376,13 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	alloc_info = get_alloc_info(cache, object);
 	__memset(alloc_info, 0, sizeof(*alloc_info));
 
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		struct kasan_free_meta *free_info;
+
+		free_info = get_free_info(cache, object);
+		__memset(free_info, 0, sizeof(*free_info));
+	}
+
 	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
 		object = set_tag(object,
 				assign_tag(cache, object, true, false));
@@ -492,7 +479,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		KASAN_KMALLOC_REDZONE);
 
 	if (cache->flags & SLAB_KASAN)
-		set_track(&get_alloc_info(cache, object)->alloc_track, flags);
+		kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
 
 	return set_tag(object, tag);
 }
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 78d8e0a75a8a..988bc095b738 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -345,3 +345,21 @@ void kasan_record_aux_stack(void *addr)
 		alloc_info->rcu_stack[1] = alloc_info->rcu_stack[0];
 	alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
 }
+
+void kasan_set_free_info(struct kmem_cache *cache,
+				void *object, u8 tag)
+{
+	struct kasan_free_meta *free_meta;
+
+	free_meta = get_free_info(cache, object);
+	kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
+}
+
+struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+				void *object, u8 tag)
+{
+	struct kasan_free_meta *free_meta;
+
+	free_meta = get_free_info(cache, object);
+	return &free_meta->free_track;
+}
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 870c5dd07756..87ee3626b8b0 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -127,6 +127,9 @@ struct kasan_free_meta {
 	 * Otherwise it might be used for the allocator freelist.
 	 */
 	struct qlist_node quarantine_link;
+#ifdef CONFIG_KASAN_GENERIC
+	struct kasan_track free_track;
+#endif
 };
 
 struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
@@ -168,6 +171,10 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
 struct page *kasan_addr_to_page(const void *addr);
 
 depot_stack_handle_t kasan_save_stack(gfp_t flags);
+void kasan_set_track(struct kasan_track *track, gfp_t flags);
+void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag);
+struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+				void *object, u8 tag);
 
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5ee66cf7e27c..7e9f9f6d5e85 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -159,26 +159,6 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 		(void *)(object_addr + cache->object_size));
 }
 
-static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-		void *object, u8 tag)
-{
-	struct kasan_alloc_meta *alloc_meta;
-	int i = 0;
-
-	alloc_meta = get_alloc_info(cache, object);
-
-#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
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
 #ifdef CONFIG_KASAN_GENERIC
 static void print_stack(depot_stack_handle_t stack)
 {
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 25b7734e7013..201dee5d6ae0 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -162,3 +162,40 @@ void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
 	kasan_poison_shadow((void *)addr, size, tag);
 }
 EXPORT_SYMBOL(__hwasan_tag_memory);
+
+void kasan_set_free_info(struct kmem_cache *cache,
+				void *object, u8 tag)
+{
+	struct kasan_alloc_meta *alloc_meta;
+	u8 idx = 0;
+
+	alloc_meta = get_alloc_info(cache, object);
+
+#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
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
+	alloc_meta = get_alloc_info(cache, object);
+
+#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200518062730.4665-1-walter-zh.wu%40mediatek.com.

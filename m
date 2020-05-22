Return-Path: <kasan-dev+bncBDGPTM5BQUDRB77ETT3AKGQED7YYQFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DF201DDCF0
	for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 04:01:36 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id b21sf6119062iob.17
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 19:01:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590112895; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nw9mVuEFrYE1dOyvcFEJCOWMlJcLj/UTzbmCqOwR3E/xXaXZri2XjbIT8IQPwTq9pt
         gxF37pAVJKfY7ZYPyZHzcKTr+mAsjxct1SDNQL99UCLECEASe5pndcSN+D9IEikJh63k
         lCLGSwHMkTht/A7XlQxR9rW72JavzdZADYqSQ5WYMsVykwSAzwglOHONVnLyPHcgDiXS
         +qy4UveS6BhKq5lyh9htd04yHgSuL2FOHh/RiR38xCE4NfuUlLocBzNvgq5slFlbwYMp
         jwEZLV0Xyj/F8K50rbR/aMUa/q1KQnO4gWboeCrGVMBHe0nPDCzZrjO+5hEh+TKhUXdX
         8h4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=l3vYBdiKXd7htnwW0lg36sVGPEFq4bUHYaWXxS8fU6I=;
        b=Z0MF+FtkmIgo0DdTL4bvIS61YE6K1l3CFzG6+zqCfBlisaQXBEFP06LVPAqE4+gbIf
         xNU3BqeEM/Nb74SmYmXDwQzSoKAFngQ/7kNTIDKphGhSBnYHGun7SSJzC0HJfrKWnQIj
         vDUr6YQAH3SFgCI2qNcS8aJ9yHYlKvz1OqS6wluDXKQfj4eD0g5qhKFJnfh7ZyiTWHTs
         RQxaQ5iEtgQ1ZVq0K5FrOLpqXCDhVi8GZ9JGLpm1oiYopoTPs8xBU9EI0pysDgOrnYuZ
         1C0tWJUT78cxg482dq15tEfpe1q7Z+XBKbERVUVemV/oA5Dp86BVOuwIsq7lUuEdZO5j
         8l/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="c0/Vqv2U";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l3vYBdiKXd7htnwW0lg36sVGPEFq4bUHYaWXxS8fU6I=;
        b=QxjoDp2wtPCc61t87WIC7Mnl+PdpfnPFonywc24Cx5H8QdFEAxq9rwHDG2Zu1Jscvk
         osELQtzxV+htbYZZg1HMT0UTj5Veh1+ygV5+C77NfllHwqMwit2jO+BP0qMjcAH702OC
         v6lv0zQfCsoRGkQzMxq0S1EBNjHyBtGsy2KNwrFwCyfyVZ80BKgklmPOV0V9geZz5T80
         aL028agxTkauez5FAP4cJHwhDUKUF1aYWmD7WMBrfEruH16rn9EHiwLTm+yglJ1Zl8Gd
         waqEeSNpS5pE/1jiyMRBpL11ZA91BAStTJANfxyYMsmwl1vJfQib4oMTOm0np92ur2Bm
         pvXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=l3vYBdiKXd7htnwW0lg36sVGPEFq4bUHYaWXxS8fU6I=;
        b=MCrITY3hw/QRjBoxis4x6HnYLq1eumSwxQfp3DiC+lKYca6U8QGBI7Jmsjn9QkHsIK
         m40OeHdMT2EG/065ByNbuRB2u4sCFd/ktiKLvIJUcvTiG4PlQP8CzwCSDA2XZCaxSa6y
         Gq/BOEV4uHhKM8N3YgHy3ReZhydd5djJHDy+IODBK+292RWKbJEpTGRVyP/qhoHEMn92
         rPmrWXJXvQTOEe2EnTTip6ryRZy7L23enzMbIQSA3Pj9z71yRxEsBsUzkbefRKBI0eH4
         BDGFZ1u+Q1fjqguzS/N00RyPvtYGMtDi74I4xlmBKL/vmwShIl2AphKyn/N9i+wrl328
         QjIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533x3sE2GFgxUuQwe1ILfgTI7r5GfkAj+9li0yjfhcpdnNvHpSSy
	1O5I5TEJG6ggS65KwBgRvEs=
X-Google-Smtp-Source: ABdhPJzxyUOZ4TBVKSwNxzep4l7QcqUjWPTRugXKdlGf69OfuKA9gLQhzJieJFfMx/3/4fPsC5m0PQ==
X-Received: by 2002:a92:5a5d:: with SMTP id o90mr11348889ilb.206.1590112895102;
        Thu, 21 May 2020 19:01:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5b8c:: with SMTP id c12ls13907ilg.5.gmail; Thu, 21 May
 2020 19:01:34 -0700 (PDT)
X-Received: by 2002:a92:3d0c:: with SMTP id k12mr3428733ila.46.1590112894766;
        Thu, 21 May 2020 19:01:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590112894; cv=none;
        d=google.com; s=arc-20160816;
        b=RK/LBHQD44sGdU/5riQwcwu7ctB/1OC8kYiDHL0oBGWX5J0GNV3yq8rk/GWEGQM427
         dyOBKhx9Gut9kcXblAVWH/v1WprKOFGpRErgiOYd+hO/fTAi1y4jg06kN7MikLJBDw69
         ebcUUxernqOYyvh6fm5TQ3Exd3VVw+8Ql27a+VDKqCOM1XrINUMlk9GZUlmIF7RtOk2w
         fYZ2FbUsD34qM9cfhVbgf2UMuC4thSzqj+spayN753pU1Skfp2Kr9aOk6qkd4xUwpZrm
         ufnFFFGqDLrh8okVPqXkmGDQLxCkWE7nd+T7g1rmvOI0aGR3nCowcPsv8mH1AIKB/z3M
         pTwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ygxU9L+teLE9h+8ckCc3XIvMVVxtE0J3NAV4/iqXpQ0=;
        b=UFhIJ5GfCinbBziOkFvF/7TGXYoZgHlAXr50FddfRVB1+YPAbSPbfnmdj48xfo4ybh
         6UTST7mX5n0AHDpT6OV7SNiqUWad4RdQ00hXbEEo6HiA7sCdkftQvP4v6M3/z+W88aOQ
         6z17V17pTEdw5NooxplM6uS4ooppImetJRtmdTFO/1P4D6u6rX2NBm+ONd+kV+3BL9YB
         cBtOBCiTu/IQ2IqErnbFagz2W8o4Q9nsmf2r902TUo+WCfRcwmMlYTxzpKMfLR+po65K
         fiQD4MKsJJtA99uLMGt6rPgWIz3unkow6OSmlVFH79Iq+jZCjKxwXbBYuVWQKzMnaB7J
         LM4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="c0/Vqv2U";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id d3si518185ilg.0.2020.05.21.19.01.34
        for <kasan-dev@googlegroups.com>;
        Thu, 21 May 2020 19:01:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: de79162e14814ce886e5b28c7a44c117-20200522
X-UUID: de79162e14814ce886e5b28c7a44c117-20200522
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1094467034; Fri, 22 May 2020 10:01:30 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs06n2.mediatek.inc (172.21.101.130) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 22 May 2020 10:01:27 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 22 May 2020 10:01:27 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v6 2/4] kasan: record and print the free track
Date: Fri, 22 May 2020 10:01:27 +0800
Message-ID: <20200522020127.23335-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: C05555AF27A2F975019ED4F7F8AC95149C28085B11B06F35329B9402831811992000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="c0/Vqv2U";       spf=pass
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

Move free track from kasan_alloc_meta to kasan_free_meta in order
to make struct kasan_alloc_meta and kasan_free_meta size are both
16 bytes. It is a good size because it is the minimal redzone size
and a good number of alignment.

For free track, we make some modifications as shown below:
1) Remove the free_track from struct kasan_alloc_meta.
2) Add the free_track into struct kasan_free_meta.
3) Add a macro KASAN_KMALLOC_FREETRACK in order to check whether
   it can print free stack in KASAN report.

[1]https://bugzilla.kernel.org/show_bug.cgi?id=198437

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
---
 mm/kasan/common.c         | 22 ++--------------------
 mm/kasan/generic.c        | 22 ++++++++++++++++++++++
 mm/kasan/generic_report.c |  1 +
 mm/kasan/kasan.h          | 13 +++++++++++--
 mm/kasan/quarantine.c     |  1 +
 mm/kasan/report.c         | 26 ++++----------------------
 mm/kasan/tags.c           | 37 +++++++++++++++++++++++++++++++++++++
 7 files changed, 78 insertions(+), 44 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 8bc618289bb1..47b53912f322 100644
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
@@ -299,24 +299,6 @@ struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
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
@@ -492,7 +474,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		KASAN_KMALLOC_REDZONE);
 
 	if (cache->flags & SLAB_KASAN)
-		set_track(&get_alloc_info(cache, object)->alloc_track, flags);
+		kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
 
 	return set_tag(object, tag);
 }
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 8acf48882ba2..4b3cbad7431b 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -346,3 +346,25 @@ void kasan_record_aux_stack(void *addr)
 	alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
 	alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
 }
+
+void kasan_set_free_info(struct kmem_cache *cache,
+				void *object, u8 tag)
+{
+	struct kasan_free_meta *free_meta;
+
+	free_meta = get_free_info(cache, object);
+	kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
+
+	/*
+	 *  the object was freed and has free track set
+	 */
+	*(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREETRACK;
+}
+
+struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+				void *object, u8 tag)
+{
+	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_KMALLOC_FREETRACK)
+		return NULL;
+	return &get_free_info(cache, object)->free_track;
+}
diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
index e200acb2d292..a38c7a9e192a 100644
--- a/mm/kasan/generic_report.c
+++ b/mm/kasan/generic_report.c
@@ -80,6 +80,7 @@ static const char *get_shadow_bug_type(struct kasan_access_info *info)
 		break;
 	case KASAN_FREE_PAGE:
 	case KASAN_KMALLOC_FREE:
+	case KASAN_KMALLOC_FREETRACK:
 		bug_type = "use-after-free";
 		break;
 	case KASAN_ALLOCA_LEFT:
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index a7391bc83070..ef655a1c6e15 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -17,15 +17,17 @@
 #define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
 #define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
 #define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
+#define KASAN_KMALLOC_FREETRACK 0xFA  /* object was freed and has free track set */
 #else
 #define KASAN_FREE_PAGE         KASAN_TAG_INVALID
 #define KASAN_PAGE_REDZONE      KASAN_TAG_INVALID
 #define KASAN_KMALLOC_REDZONE   KASAN_TAG_INVALID
 #define KASAN_KMALLOC_FREE      KASAN_TAG_INVALID
+#define KASAN_KMALLOC_FREETRACK KASAN_TAG_INVALID
 #endif
 
-#define KASAN_GLOBAL_REDZONE    0xFA  /* redzone for global variable */
-#define KASAN_VMALLOC_INVALID   0xF9  /* unallocated space in vmapped page */
+#define KASAN_GLOBAL_REDZONE    0xF9  /* redzone for global variable */
+#define KASAN_VMALLOC_INVALID   0xF8  /* unallocated space in vmapped page */
 
 /*
  * Stack redzone shadow values
@@ -127,6 +129,9 @@ struct kasan_free_meta {
 	 * Otherwise it might be used for the allocator freelist.
 	 */
 	struct qlist_node quarantine_link;
+#ifdef CONFIG_KASAN_GENERIC
+	struct kasan_track free_track;
+#endif
 };
 
 struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
@@ -168,6 +173,10 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
 struct page *kasan_addr_to_page(const void *addr);
 
 depot_stack_handle_t kasan_save_stack(gfp_t flags);
+void kasan_set_track(struct kasan_track *track, gfp_t flags);
+void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag);
+struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+				void *object, u8 tag);
 
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 978bc4a3eb51..4c5375810449 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -145,6 +145,7 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 	if (IS_ENABLED(CONFIG_SLAB))
 		local_irq_save(flags);
 
+	*(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREE;
 	___cache_free(cache, object, _THIS_IP_);
 
 	if (IS_ENABLED(CONFIG_SLAB))
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 2421a4bd9227..fed3c8fdfd25 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -164,26 +164,6 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
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
 static void describe_object(struct kmem_cache *cache, void *object,
 				const void *addr, u8 tag)
 {
@@ -195,8 +175,10 @@ static void describe_object(struct kmem_cache *cache, void *object,
 		print_track(&alloc_info->alloc_track, "Allocated");
 		pr_err("\n");
 		free_track = kasan_get_free_track(cache, object, tag);
-		print_track(free_track, "Freed");
-		pr_err("\n");
+		if (free_track) {
+			print_track(free_track, "Freed");
+			pr_err("\n");
+		}
 
 #ifdef CONFIG_KASAN_GENERIC
 		if (alloc_info->aux_stack[0]) {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200522020127.23335-1-walter-zh.wu%40mediatek.com.

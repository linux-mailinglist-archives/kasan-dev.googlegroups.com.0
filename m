Return-Path: <kasan-dev+bncBDGPTM5BQUDRBQ432L3AKGQEETBNHZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id A34F81E9CF0
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jun 2020 07:10:28 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id y16sf4807746pfe.16
        for <lists+kasan-dev@lfdr.de>; Sun, 31 May 2020 22:10:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590988227; cv=pass;
        d=google.com; s=arc-20160816;
        b=hXRBl99NjqyaOpt9Km2fcNuFgLI/1HRvHcZ1ZghSO/N47QG46buLPMqD6WC8OCFdPj
         y/IAmdoHlA5Y7VvcQOHZKt54ZDi6CSUKZemWM//O6261jMKDJHvRf4WAw7lLBdK3dozB
         EPhRFb0VCg+M3AT5Jy/fp3Nvb8EL8DowJyTlnru4xdJ8Uj5kQWwngCDhTWs6Je0QcI2u
         ppQhw9JUXWtvvTEfS6oWQp1m3ZynpIXov07Uw+AMPTd5Pap8vQhBFmEPrbWyttUSxjhS
         cuVk6p/CsG+zrmO6hkisugpp8wV1XMn+g85J62PGzwY6lQB+zdhmP2amblsMPQ2RnQDr
         1ejg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=0AxE52ILvVORy0VYmws6VxoK9Lp/EImUXtLfbuDcI14=;
        b=UzKSpMZqgZaPgCp+Q8vOTnZbK9yLXZRFG9hyno5mNiPxnV9z0CV7r0u1ecJOh/o5SP
         YP4T6K6oMRFzQ1XWIAT9/4k1hlE8wmRN7Me6POnu5VXx8PFq/TGS51rFNzSmYmzK/gZJ
         jsUQL6nZWNlfvZz4+tIS5EtFfTTjbn3U+gnY94a8X/1Mw/WYzvBwA9QZqqwHDQu69uVM
         xYLXKSWJPYfceKzUnJbnjsPFKujLpgBCYRHH8QjQ9Uhr+Hkb7egp2arRTeR/iXw/MN1I
         FwPm5kKnSkk8LjmKAqTEzU4eT2NCyP7XIkWr1PLnr8RtIvYY45BZvt+l0SkMCqxoW6sK
         otkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=SfFFeBqN;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0AxE52ILvVORy0VYmws6VxoK9Lp/EImUXtLfbuDcI14=;
        b=Ad+xqY7htAC5K2HBwYbMDnnHWjPynubpEEJmCvG/qoOFe4M3PKV5ah1HRYPa/FarY+
         0ra8dEdlIxrfF1gnR4IUH8tXoCTZKdClq66BBVeahvNyyj46yJpzDkNiZu+RZf35Jw3T
         A3yyDJRMW2C68U5J0O8VZS5t85aYOxQs2SYkUZ1d22715S/ADCrpUPDhpfKLiN9kbxsE
         8S6eNGAtNPX/Me4fkazqsDj0U539M7nfoXcKVOJ5wH2qjQv4XDS3ZD0N4ePRQOIMK2Pa
         NRmsoTXnUdpK+p1DP8kU+AB3nNj8SrCJRZ4PMpHsjm8iD0a2SDBgTdQR/3kuFyBSAHQL
         qV1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0AxE52ILvVORy0VYmws6VxoK9Lp/EImUXtLfbuDcI14=;
        b=jUb6jU6fnLcPj/2ZlNAxnAv/7A5fol+/hVmKGkB7qiWbVL8/VkDmJR6KxFXwQ4P1z6
         MzQFe2i8MVjcQTDn1jrckyvZ6Q8cN8uT73/6hPlXGwxoEPl0N36/YNjTbBUJj48Ksb+i
         lgttIoU8UMdHMWKjA0NXMMCQoMasDHTchfY7qAxW66E0a7IuWgOjbbTTw/a237B2SUAR
         o/pCMJpDp9XLEa/lvYR6hROAhQXpAcleYSs7a1FT6/Y9ZEAoI4ktXEJw8r6tp4FKif7M
         XmEc7U+E4cHgvapxgaTrnPwSo6Huw2v7UKJDVMmxfVvkXOkptliZjxRC0hLaOFYy2SRe
         wXZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xz+DXPly/D7F9Dc0orUawkgzcI17+5Ed54kOZwG1hRnDVXMxz
	2t4oxAD3xN9x2az1AXXGP3s=
X-Google-Smtp-Source: ABdhPJwITPZ9TsYUfnOF6PVxS16O3cjIt1Ko2TAfSEITLRmdu3cR8ifg+krdaECWLqxknzxdK1Y+vw==
X-Received: by 2002:a65:46c5:: with SMTP id n5mr18927274pgr.204.1590988227359;
        Sun, 31 May 2020 22:10:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d90e:: with SMTP id c14ls5290725plz.0.gmail; Sun, 31
 May 2020 22:10:27 -0700 (PDT)
X-Received: by 2002:a17:902:9b8e:: with SMTP id y14mr18712690plp.109.1590988226896;
        Sun, 31 May 2020 22:10:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590988226; cv=none;
        d=google.com; s=arc-20160816;
        b=W7Qcxl8ja+LN+1kaURw6ZxAeShYiFDWJPht+S3VipCINURl+7iR9jabq5KSJGaG4gV
         tSpOZiwhIUKnO+Vl0pdq0IKWukOZOiS5USaSeOzyoSQ538ZDOklFcmANmXleDroYQQg6
         IlJKYPOvhm7USS6MiaDU0T3ZnppcKuOC34v2+kcxwh7oIhcADMabCCMM25gLxrszNLja
         xSji+1wjKfPxVv4FL+Vt/VaBB/gZNpaKwgUw/2dVaX/blpgEaT4gYArzlXeg59JfqCLu
         BsnMIkm9smHN9c+AOnzN0OHmF0ZcwRKe4GUqm3ho4pEqbc+4E5/Jrz/PQIp0gEN9SNjt
         /SRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=co+J9kGSLsuZqwzKx9sgfxcjEsF3XOHEfEFldRg7xfo=;
        b=iajuCz3CcAwAhST0LWND25uNZbJdybA28JK+hpelNWOCQblGLehcnsjnQHQ2H3yiPq
         ASN42dQc9WD0aqGfnlzKDAzoe/cD7IJBOtAOeSgiNSHAfyX7I7wwU02vF2zp/ysjEuZJ
         ozQjPIKmgTXgcp6fMYLFCoZFsLltSGGPBlICOgOZ35aXTA+GoQZwHqPGiH629g2JUZLk
         6OeiuyuM+3dhtxywcJJR5TnpHazyhaBURWNqOiIHC83ps9WpuTDPwoY2Rkp661Seee5E
         CO4WKrNlLJtNlnxqhyLXNK6eyEBYg8/IXANgd3MhhY1mm5aZvPvYVcSD8D/eGwo+yhVd
         bPBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=SfFFeBqN;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id g10si165639plg.3.2020.05.31.22.10.26
        for <kasan-dev@googlegroups.com>;
        Sun, 31 May 2020 22:10:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: df31c7348e8a4906a2e57657b2d05a77-20200601
X-UUID: df31c7348e8a4906a2e57657b2d05a77-20200601
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1308180801; Mon, 01 Jun 2020 13:10:24 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 1 Jun 2020 13:10:17 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 1 Jun 2020 13:10:17 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v7 2/4] kasan: record and print the free track
Date: Mon, 1 Jun 2020 13:10:22 +0800
Message-ID: <20200601051022.1230-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=SfFFeBqN;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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
Reviewed-and-tested-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200601051022.1230-1-walter-zh.wu%40mediatek.com.

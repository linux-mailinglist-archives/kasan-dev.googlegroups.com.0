Return-Path: <kasan-dev+bncBDGPTM5BQUDRBWWIST3AKGQEWV5NAII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id A480E1DB3A3
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 14:36:43 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id k10sf2695686pjj.4
        for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 05:36:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589978202; cv=pass;
        d=google.com; s=arc-20160816;
        b=snii44a/iRLr2MCFXFOrqPDhzfLYGFFvDtonWCpv3uqg0uuHnfn9FXLwttHn7Pgt9H
         aS5x+O4+B4FRsYR7kurFMPSNU21kPiVjJ1X0q+C/L7gFkoPd4mZUfXQLlUC2epjcmTov
         z/iGZTqhbTrdOgebzZAhVFaYdexsNZYEAAriRJ+mOjNL5OdvKc036/z4qicH7d4o3p93
         oewigx8KGwCOSyaq96mEdi63bNmloyjqgKz8JQyGTvjldLfuGg1TcWBt6GNkRmXvmcVE
         ZgNDUUbgZISVA7oXI34TTaqhLqTvEcD/UbYr+xETH+I1BfUiyBZMQ62HIs0QNkIefCeT
         IpzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=TPR5Rwvq6sqe7Fhbt34MoRbtM/VdF246seU+4P8ksQ4=;
        b=fxZXDFxIsl6K9lkwVRAXJv3o+zBQNd1FSqwhgI2cuaakno2vrCAKnDIOmbKj/c2Z3r
         eseVEwoDD/gD2tOuS23CaGKqBmcFKrq8dmapKhDpq9oCFhn6Cir1TQ9XSsdMjPdR1S49
         loGgtUx8+sBMqbobvfg5EXB3Gozrk1Aju8INrTYrXwsMVnwaJ7CEt/nW7ksGffbo3Z6A
         97tY8lQrUgOuoBWBw8+cmQuQXf8TqUG0S4G4OuwPaFvkqPrbMq6/16u3qko2EU9JwXDy
         WJwwOkOIsS47kQYevuCG/L9V/bXuTi1PjH7swuU4mjva7sHLHiqhqhGcEmCWHFXC/Zew
         YNVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=BeejYFGD;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TPR5Rwvq6sqe7Fhbt34MoRbtM/VdF246seU+4P8ksQ4=;
        b=TVZL+rz61TptC2OQTNpTkQRzw2n9y3LJhr/b1MaRQNhPuyiJOUWvXU8NN6ifAxnMkq
         tEn/Xg5w+QZYdmbeea4X1idDKTd2eyLaLs98SGVaS6JP5SKhUrLO4iGbg0V5tfpdhqGi
         G4RXBsocJ23NOOFnI7nnDfrJJ63i5AbSkpGwd5sOp0EpumvGLr7l7FsL+xHcHaYV6Da0
         IpOh9dTj2A/tMaSkaUEROdyfAmVvKc/cc0JmwyzvlPWeyxTh4xQ1o0EhOaH8fKcJscR1
         OB/ATABhjnyL2eFl/HsRgjn8aIBxX3hcha4nbtloAlJhVvPBDDVnBJ/N78NKRDYX1D0j
         xy+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TPR5Rwvq6sqe7Fhbt34MoRbtM/VdF246seU+4P8ksQ4=;
        b=eQOwUfIt2ZwIeRhFE/OyjLTjLitfo+xTR2bxaTo9PmTuUDbnUODq2Gd2u4lBWewTVG
         naSXf0ajS8HjTjrf45g6DoiCGzppSsnYdyQVfZS2vYfAleAZPTN5TbYGfqBb7A/Lo7OF
         Oq8jbbRIJye3vjUNXwUkrJ6LKRIwewroHXicQEzW8LYtmAlTXyJNOCRxNNwx8FGN6JfY
         9G7n9sKezO02Ub71umwFXnLZRg0q4wmqYq4LcS2fchSVlUO5VlQ8PNAUI/UphzVsCpVB
         lZSc8/NmfloZJrS56DXNYqBYEGaAn/OLzIbhS+6fAg3P4ORrag2a+Yum9gRgiG1FaOxk
         iRmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532egjcuRbjIaxFYqg/hhbzBgZ4WFh13SFvs3VRPsAxDZm8DPogI
	FCyTVDtQRKGLXOd7/epueBE=
X-Google-Smtp-Source: ABdhPJxfhgEr/pefdktj7V+WTd8sM98xuvRMINIGBVguPeERgdfChux9PCNwEwhCRO/ClIhC5ApneQ==
X-Received: by 2002:a17:90a:a402:: with SMTP id y2mr4941031pjp.24.1589978202296;
        Wed, 20 May 2020 05:36:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:668c:: with SMTP id b12ls851136pgw.10.gmail; Wed, 20 May
 2020 05:36:41 -0700 (PDT)
X-Received: by 2002:a63:cf56:: with SMTP id b22mr3882806pgj.393.1589978201851;
        Wed, 20 May 2020 05:36:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589978201; cv=none;
        d=google.com; s=arc-20160816;
        b=uP/qFMFyoIxa9ApNECbrDrO2Kb0rkv7Rx/jBXXa4EaO0RHavWLgjMpON9jQwtXHoF+
         FS0GwWaN6D06DQSSDZN5fZ0CNvA+Ucx4M7LtVJRPT2hgOkgOGJbal8ABpeGp2GGee1jx
         S9cYi6JBFWXINcUsBGor4pe0xYotMsJyW8YBNVqMOhY5omnMdRX5PmBl6qcL+oY4AIBv
         G5dpOxS5OurfY7ZQPO5mdgX3VjRMCYvAOyrL1SdNxeoyLxFWIQ07IAqR2zT0Jzgb/bA7
         U71aZ/ShTw3DBKJTY2ac+4jSGGOCizCWjnJ+dLZf2nKAzLbE4yJ09X6rJR0UuzsQpGpN
         IZ8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Pwtdqua4C8EFsZiafKrIKlZSpGuf7w5Db4mwt3cBCP0=;
        b=kX9GFuJFO7J43BcL+Tn1euFQ9NKdqh0bC+S2msq+g7pEGX6QylfKWBFGCrR6xgwZ/S
         sP5GjVoua8P3YpZ11l+gc3xVxTmZ+axIepww9o3VMpJ8td5ZgZIuHxyHWGcFN8oq64qA
         gAaVW3FeZXwNErU5nSq6HJkEKhzbxNx90ius7bQp+1aqsLwqflyjHutpWn/s5ctO8O8d
         gpeWY2DKA4ZZAEx9drZAVjTSktNDCC+12EV62JAjBAyc6Dzhv8Pxe+6Y33LCPwX/MJum
         eMrQmsTFiLZHVnyOYbkKFTlvnhg1GgXajUnOIB/LzKrSK5cLgmHp3OFRknJtXYukhoTu
         NIAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=BeejYFGD;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id e6si482817pjp.3.2020.05.20.05.36.41
        for <kasan-dev@googlegroups.com>;
        Wed, 20 May 2020 05:36:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 8afe1c4d6c35493b886f7a847bf383b0-20200520
X-UUID: 8afe1c4d6c35493b886f7a847bf383b0-20200520
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 119742408; Wed, 20 May 2020 20:36:38 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 20 May 2020 20:36:36 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 20 May 2020 20:36:35 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v5 2/4] kasan: record and print the free track
Date: Wed, 20 May 2020 20:36:36 +0800
Message-ID: <20200520123636.3936-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=BeejYFGD;       spf=pass
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
   print free stack in KASAN report.

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
index 29a801d5cd74..94b76a1df976 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -170,26 +170,6 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
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
@@ -201,8 +181,10 @@ static void describe_object(struct kmem_cache *cache, void *object,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200520123636.3936-1-walter-zh.wu%40mediatek.com.

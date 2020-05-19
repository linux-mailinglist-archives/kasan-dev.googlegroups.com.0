Return-Path: <kasan-dev+bncBDGPTM5BQUDRBFEHRX3AKGQECT4Q4HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FF131D8D98
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 04:25:25 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id m2sf8948067plt.17
        for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 19:25:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589855124; cv=pass;
        d=google.com; s=arc-20160816;
        b=orF1cmqChARY33eo215+iT29sUBzrZuqBRwXaC1qqCbX0v2SltRn8tNfg6J2Cnvvke
         Ldu3dFIlOAWHMDpAnTnigISdWyYtLQ6QW2WWcFu/8GrCFdXVwsehs35PnGxOEJ47abMH
         yg/KDv68qibKWagjJDJ0uy0yFYR6MsBH4Yjc66HaFl9x2VDIDifsjogHF/PKUiRIkkGK
         QkBVHVIyTakYV5+qg54p0kQxQcJ0J2z+ZY7nJWB9x+uo3SFiKEYTNZm/KuB6RdtjZ4/w
         FwEYuUpEFbTcyaGMyTA0NnrwRgZkuI8Qtv2xSYYaCGf12/Wz0U1ug+HccHMCHPYOtcwx
         t9Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=+L/Dyt4NhfgYmmEksMDVGde8NZaoLWdGqevxFMTJfUQ=;
        b=OLwEsjt4wRhi8nTdG7SjsrtaVVqutdTvqKlkY/JlY//hzSD5Z8ConaJaRxveRcvNgw
         DUuinLG+TyuQK7C6WtvpIEJ4LQcMFIG2kuuEEgNe7KBNij+QX6S3yAY/tUIvfrlNBwdN
         drEFXdoti7bLGwgg1WEey4jKR5iVuUeI0qVYdnsESp5atOKGMsa28N3y0NHyhJfG5IBC
         0bJreyaaNPygl4YVbEbkyWej8mf4LGaCv07bLaCBTCHLp3cCXpTcS89UXx8BQguJWolE
         xGom8QsAySm+ipVORHNvVqIjyM8CcHg6cXm9vcM6ljwXJaiY2gpC7daSAaU+5oAdE5N7
         pQqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=kieAlXgs;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+L/Dyt4NhfgYmmEksMDVGde8NZaoLWdGqevxFMTJfUQ=;
        b=BwowbKub8b8KeOuhQzdfdQrlTbDjIiVBDHshRVdBKxNaPoxj2e/mBBm3MaMwx+gh39
         5ake/OxaxZPU8UcFwu2alwH5tAn969/tYj6N6iAiounTDtAbcdGn45L3eg/K1nxFvz/P
         xN6jwds/wSHSUfcYCmiO3FRz6ODYqL7N11R0bedBEP41dwK9eTGANNHzg8wIBnAZOLRJ
         DhaY0dtSNoYoSOVR9FQPUlFiq2s4R+ZzfXFsFAp61Ya9lq89XjZWjWdl1JyEG2M0ANgU
         m/Aqc2NA2Z2maSHJRnEvJX/+rjhlH3Lq1QUDAHeNeyw6X80ZKaiMJdVjltOZdxeLTx+q
         6+BQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+L/Dyt4NhfgYmmEksMDVGde8NZaoLWdGqevxFMTJfUQ=;
        b=VNbcwkofEpicaXKKQmlGvyAfJRTjzEmCEKvRCygQFZT8QDt5vn3jxtmFe7ADlCvJXz
         ujBbEunGvMPZHLXnaya9mUDSiVMIgEHeN8EoqDlklEbzwSHv5ZifI5qo8+dBqxR8j0Bv
         XBHdrsZmJh3zyu+O+Do735Y31PoqG4FJlrmM2Z6vnzToVcSPd3L7dqZsAMcZX+w+6fl7
         nZe/o6fncqD1lz6o5erTybq0GVN9gh6soMbNiA8ky3NfcQ7kSaufBvuXGgIE8c/LJTO1
         qc0Vl0y3XJKLI1Zq9psInem3eE8AW29MeRNK2YtL3pDWVvF7JmPzHH7tORDZMFG8Zhm8
         cxdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531S3iRsgwgTIhnEgVYv4yquXbiIp/r64OEcysEBOtpj7iyFSVb0
	vjSd5f2/1mfmc/GOUJpXUpY=
X-Google-Smtp-Source: ABdhPJwnYu/yEB8zIAjHg6a1HGZhFIoL9Rq0kdDSdwaQIVvMivgtUWPpjdnSLaktDnUr2lgur+oY9Q==
X-Received: by 2002:a17:902:bc4c:: with SMTP id t12mr19345000plz.282.1589855124258;
        Mon, 18 May 2020 19:25:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7203:: with SMTP id ba3ls4038763plb.4.gmail; Mon, 18
 May 2020 19:25:23 -0700 (PDT)
X-Received: by 2002:a17:90a:7787:: with SMTP id v7mr169995pjk.199.1589855123791;
        Mon, 18 May 2020 19:25:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589855123; cv=none;
        d=google.com; s=arc-20160816;
        b=AgunUXZc1gyoZ4AMqSj1+IueXR+w7+WzHFxvrf2TgHb55SqPhyc7vZjXZ/U7NUkDjJ
         jRPQAozh8fT3RARfhFw1nOOYHt4PeKdMMBkCIkelQ4HaS9ILuEJRkeLoIS4HEy1yQ0Hp
         qYC7MmTd6tGnrgkLzCuiv1sCV9CDxPxy7yGPDTMVIpuICiaekM2r4ZivWyn7/9Rm3ZTW
         RD9i70GSeAvT80ck2s/gE4DNctmLAIr7LfvtawVVYF79KMU877YXr8POTtg2klEDc8ot
         iefzNs43LFDcp7btfnFzZ2PgKc81ANh6hM/gdtCm+jBntOl71sCIDvRlvpgGfdgGhk33
         PDBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=xIbyfEVfNhDzDf6khLyqSfG9Nt0s7YrzEMxFG3zAGv4=;
        b=JDKDWVULuXurSUiTZIqTsEZSsc3BYSJ7QAxxOS3VhYDPrZ6s1myL04kMnkO072Mt/R
         PwhEJUFxEmtI9qk/tTyd/T2LwLzrOlViEN0i1na3fTDdySNoditBOkH4gR9l5apqMO7I
         d3/c+qywAnXaFuatjmalvgr0V6H1nP4R/ZWkGkCTDvfouLgvWo7whOGHbz8LbgtmbY/q
         riVOMdOh1lLBL9+1WSke9ynagIrooLZgX6d/DdkQcwGM+GXOnH3ayp4ETD4b3GoRHRcD
         kAWdYfvbQiu1s7EzOixYvO/fSwHSDhDg/3nlbdNoj1IM47jderFfgtaBq1EglpKdCjdB
         Ijlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=kieAlXgs;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id v143si830438pfc.3.2020.05.18.19.25.23
        for <kasan-dev@googlegroups.com>;
        Mon, 18 May 2020 19:25:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: e8ae0a43571943bea2af57b10e57c510-20200519
X-UUID: e8ae0a43571943bea2af57b10e57c510-20200519
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 512744146; Tue, 19 May 2020 10:25:20 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 19 May 2020 10:25:18 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 19 May 2020 10:25:18 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v4 2/4] kasan: record and print the free track
Date: Tue, 19 May 2020 10:25:17 +0800
Message-ID: <20200519022517.24182-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=kieAlXgs;       spf=pass
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
 mm/kasan/common.c  | 22 ++--------------------
 mm/kasan/generic.c | 18 ++++++++++++++++++
 mm/kasan/kasan.h   |  7 +++++++
 mm/kasan/report.c  | 20 --------------------
 mm/kasan/tags.c    | 37 +++++++++++++++++++++++++++++++++++++
 5 files changed, 64 insertions(+), 40 deletions(-)

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
index 3372bdcaf92a..763d8a13e0ac 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -344,3 +344,21 @@ void kasan_record_aux_stack(void *addr)
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
index a7391bc83070..ad897ec36545 100644
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
index 6f8f2bf8f53b..96d2657fe70f 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200519022517.24182-1-walter-zh.wu%40mediatek.com.

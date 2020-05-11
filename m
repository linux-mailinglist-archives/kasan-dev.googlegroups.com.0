Return-Path: <kasan-dev+bncBDGPTM5BQUDRBIPS4L2QKGQERSM6RJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id B2CDA1CCFC1
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 04:32:02 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id c18sf16170580pjo.2
        for <lists+kasan-dev@lfdr.de>; Sun, 10 May 2020 19:32:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589164321; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lthz9ymWXFZZ2Shw+alwarWe/U20enJ2gbUsN0nK6c1sAZd7yknNi+OMQHjR5T8Pv+
         7cr5CXV8EKWe6ZaqD5Ht3GAfFaH/6nCGxGlyzC8KuX7sMbUexHX16PTxbO3MNJiWs/+E
         6jPxj8z/WGz44AY9KlAB20tyQMX0CgrC4osWKe65J/9SIqvXVff02xmBE4YyrtvoQmKi
         lZ7hzKUPGwrOoCU9TD3JbxXoJGmJIFMIu5HLuoo0dIHnocwHZ7rtUXmlSA5N8VyXQk1S
         zv55M1fDVdRG2k4miGfxLU/r4aNnqcJnEjgUa5rRfZ3dKAVeFTQjwOVkVnCHxoEKhgYY
         yNKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=t7SGaWfJdiinLtAJkNsBVM/mEBSevfZUjmnpA9Ks6WU=;
        b=VR/tAP36kD9NMO4VmWFel3Y6+qv9UvUrKU8oqfgwqBtj3PRzWcIQ7NOgU6cF6H1b7C
         hRUJfH599H8RXMCSQmeWRcnkFet4QDUZWRHOh+VarGoH0uCMWmwf3deW1mVI5RpKDRJI
         B24kj0PmV+mG4UKsDqlC2AvXlZfYi0GkgOA1s4HLmF7yt9Cqxz1kzIIYNKlm3fQrUEN5
         UF1qaNfhOqO6Q+2B5zWZvM8ivrc+l+Gp78kmkRbsAlTsPCenE5Ss3EjhZbAP552l13n6
         MYCQ497uUYpHaJLj+hvqQY+Pdy89WBtuK25SEPIvdD0pgg2DjGW3NPw10bThgXi8QixC
         k18w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=RrigfM2l;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t7SGaWfJdiinLtAJkNsBVM/mEBSevfZUjmnpA9Ks6WU=;
        b=A2PDhbN4jrjSrk6ySy/muJF6cxoUIh2qDvRcyHsr7uw7UEXz1KCKuTFg2M/AVY9mtJ
         OhrWs5U5Ne3KJ197diBJGEhyuuVP8SuR+Y0yqMahNbeysa3DMCXtNtzYrjc2zSuG1lxs
         8ogLFWsoXj3C1uA3yipkQjcqjgr/OUkQUBJdPdEnRn4Sc583Koh7FcGydLx+v6xvd6mO
         P+/WA873YJPQSEOX43HX+sQLIyu3aF5/M/I57d/+APlxsJbc7WDvNdgAZNblucXsHS91
         d/j/i62gmuBcPcKI2RL6g0ln0zH4StOKifI8LimyJn8EfNxb5WC0K1N1J5j0Fyh36+co
         XebA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=t7SGaWfJdiinLtAJkNsBVM/mEBSevfZUjmnpA9Ks6WU=;
        b=KBDE0lUTNvz4YPVNVGQpgfQjh70eaTPQgytEmuwPdmtR67vknxZZRnQHeULpQdRUv0
         sJNB0d5FjOEw12uG3PDHlTwjJkWxwkD8Vmo3I4POPAcK0/6LIq0Ah2zADmNVNCi44cJW
         vkpKh4VgrQpg8KYh1Z5yfLZBu9gyqKDpPaQOWcyEY6KjAxE6kwj/AcR6gT2Agm5UZCvH
         5hYCB0H2cmJ8Xc+5Z4c5HHHEkDzf27OOLl6vMNjLQakd/xj1KpWHV0psvgZ6A3FrpCDW
         9VXIusHRq37oLGPl3BSxKms9khMvISQMCaZ4hAJ05NDOYrsReTgdrIY2vCL6edhttU1e
         BCaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubBRKiifpeTmov5aLWrn++g2DNTSfDmd88bMFGmBrdZDMwb0PsZ
	OsJbW9jRZOC3mzEDAozsJVs=
X-Google-Smtp-Source: APiQypJo+1T7PjGj2Spz82t+B4V18UbIKqRBm8onMCHLr2g27GelSMExQSekH4eKr3ytfMQ78ycbcQ==
X-Received: by 2002:a65:611a:: with SMTP id z26mr12217681pgu.341.1589164321186;
        Sun, 10 May 2020 19:32:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d713:: with SMTP id w19ls4312010ply.9.gmail; Sun, 10
 May 2020 19:32:00 -0700 (PDT)
X-Received: by 2002:a17:90a:3268:: with SMTP id k95mr19599208pjb.185.1589164320768;
        Sun, 10 May 2020 19:32:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589164320; cv=none;
        d=google.com; s=arc-20160816;
        b=026Pi/JhiSOMBxM6yKY7KPvU9mO2iz7Xv/1KSgpsbmnlsDOZOZhWQV1Cc9GGO+ZsCY
         GmJIG3lmfKiO9TAArGg6RstZIamv+4QKMz0E7uQ9gsufHvJCweB8q4qXDIU3Zyv5amfG
         +uHpS/cn27BHjAIMwv72fx1PpVd5Wm7sMdmIHWelVYkZX6ByNt4+ZWAMRDEFUBpPRl3v
         5U+JMjc+CftDW1bbLhxe9oqYY1ByxHpL0prNmzeDreE2xTU1SNK37qto3Z4NanGWSiIZ
         s+wSXEJIfNsnt7m8u2n2hUHU18SpbyUqujlI8f6YvMOXywL5sSM+DeO57QL4vp79+Foz
         QxmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=AKvJsme/BN0IY0oO7wwke7B4wAJvK+2g3DFOzBvrhf0=;
        b=CIMaBNUY9rymDvEl9122LHBWIfmuD3T4pJMP7KAueoOgW1b/6Q3iruqH2DG+Rs5gOQ
         BfX+a7wN13a5Hnl1sI3Tcuso4px6ghcwbTcaPbJjhAix5LdR8FnF6elJzgqiKAbrAU6P
         VzRnuatWW00bjrw6RB3tWn6Yf/AwTutDQpSsY8W060/tjzZMwgc9ynfnEdd3klLjnymr
         rAQ5HDnT/vzA5qv/cSfBKEptLOSVVFV1L3r72fQ5VRP2LnA2qXBTAjf7h6rG2STSjfR+
         FKqQWYnBvx9iz8hxX0lcIKeE5s5uqaHDDALAYrlX7QplcTRevtyluGV3ADA6dco9+VrW
         XZmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=RrigfM2l;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id x5si682563pjo.0.2020.05.10.19.32.00
        for <kasan-dev@googlegroups.com>;
        Sun, 10 May 2020 19:32:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 2c9984473f0248cbbc37d7100aa5dae1-20200511
X-UUID: 2c9984473f0248cbbc37d7100aa5dae1-20200511
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1731409954; Mon, 11 May 2020 10:31:56 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 11 May 2020 10:31:55 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 11 May 2020 10:31:55 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v2 2/3] kasan: record and print the free track
Date: Mon, 11 May 2020 10:31:53 +0800
Message-ID: <20200511023153.15376-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=RrigfM2l;       spf=pass
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

In order not to enlarge slub meta-data size, so we move free track
from slub meta-data (struct kasan_alloc_meta) into freed object.

Modification of struct kasan_alloc_meta:
- add two call_rcu() stack into kasan_alloc_meta, size is 8 bytes.
- remove free track from kasan_alloc_meta, size is 8 bytes.

Because free track is stored in freed object, so that if it is an
allocation objects, then it will not have free track information in
KASAN report.

This feature is only suitable for generic KASAN, because we need to
know whether objects are allocation or free.
- if slub object is allocation state, it will not print free stack.
- if slub oeject is free state, it will print free stack.

[1]https://bugzilla.kernel.org/show_bug.cgi?id=198437

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
---
 mm/kasan/common.c  | 22 ++--------------------
 mm/kasan/generic.c | 22 ++++++++++++++++++++++
 mm/kasan/kasan.h   |  4 ++++
 mm/kasan/report.c  | 28 +++++-----------------------
 mm/kasan/tags.c    | 37 +++++++++++++++++++++++++++++++++++++
 5 files changed, 70 insertions(+), 43 deletions(-)

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
index b86880c338e2..dacff05a8107 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -354,3 +354,25 @@ struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
 	return container_of(&alloc_info->rcu_stack[idx],
 						struct kasan_track, stack);
 }
+
+void kasan_set_free_info(struct kmem_cache *cache,
+						void *object, u8 tag)
+{
+	/* store free track into freed object */
+	kasan_set_track((struct kasan_track *)(object + SIZEOF_PTR), GFP_NOWAIT);
+}
+
+struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+						void *object, u8 tag, const void *addr)
+{
+	u8 *shadow_addr = (u8 *)kasan_mem_to_shadow(addr);
+
+	/*
+	 * Only the freed object can get free track,
+	 * because free track information is stored to freed object.
+	 */
+	if (*shadow_addr == KASAN_KMALLOC_FREE)
+		return (struct kasan_track *)(object + SIZEOF_PTR);
+	else
+		return NULL;
+}
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 1cc1fb7b0de3..f88d13f86ed3 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -173,6 +173,10 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
 struct page *kasan_addr_to_page(const void *addr);
 
 depot_stack_handle_t kasan_save_stack(gfp_t flags);
+void kasan_set_track(struct kasan_track *track, gfp_t flags);
+void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag);
+struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+				void *object, u8 tag, const void *addr);
 
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index f16a1a210815..51813f02992c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -163,26 +163,6 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
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
@@ -193,9 +173,11 @@ static void describe_object(struct kmem_cache *cache, void *object,
 
 		print_track(&alloc_info->alloc_track, "Allocated", false);
 		pr_err("\n");
-		free_track = kasan_get_free_track(cache, object, tag);
-		print_track(free_track, "Freed", false);
-		pr_err("\n");
+		free_track = kasan_get_free_track(cache, object, tag, addr);
+		if (free_track) {
+			print_track(free_track, "Freed", false);
+			pr_err("\n");
+		}
 
 		if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
 			free_track = kasan_get_aux_stack(alloc_info, 0);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 25b7734e7013..30a27f8c1e6e 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -162,3 +162,40 @@ void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
 	kasan_poison_shadow((void *)addr, size, tag);
 }
 EXPORT_SYMBOL(__hwasan_tag_memory);
+
+void kasan_set_free_info(struct kmem_cache *cache,
+		void *object, u8 tag)
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
+		void *object, u8 tag, const void *addr)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200511023153.15376-1-walter-zh.wu%40mediatek.com.

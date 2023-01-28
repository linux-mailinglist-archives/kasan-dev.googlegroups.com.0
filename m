Return-Path: <kasan-dev+bncBDY7XDHKR4OBBH7R2SPAMGQEIK27VWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 25BE267F8E7
	for <lists+kasan-dev@lfdr.de>; Sat, 28 Jan 2023 16:00:49 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id w2-20020ac84d02000000b003b63cd590dfsf3403197qtv.14
        for <lists+kasan-dev@lfdr.de>; Sat, 28 Jan 2023 07:00:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674918048; cv=pass;
        d=google.com; s=arc-20160816;
        b=GiWqDa7KeBQYlOo4bZ6Uhi0kfyM/OExwrxRBuljSmxuWyjKcjQr/ZSevrnstoIX5G9
         LeBxiKpa1/ZhfurcpjXg/KG4PQq425o58ZedTWKCsvBpY0g9rn9KidwY26pPsYteIvjz
         9PbpB4PWjenfnbKaCCEaEmCqy5qyFSrJCLGtqv8p4I2LS2C3F08DFlhKdFQhKJFkuSiP
         TWr3uO9kZUdYlIPMbAjBo99dwb9IYTJgXsOu15aUXkwetOQIiMsAPuQSWXhVvwQh3rNf
         qEL3dj2zzSzLhyh4R6rdXEAz/OWtlShc96qXYWRvxHaTlZrFv9aNrgAsRiHcO9gj348D
         2q/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=AHfSHAdaDG2N7AkqfNLUmLecbVo4e0eLqsQteUmuv2U=;
        b=EF2camE/uHQ9pd3Tl0a8xu50BEShxcZuCOHXb2SEyhc2QALopbJa31loWFyRT7JKSP
         O8+nPvxy3V7xlQNdHnW7sEedCmKIlmvGDciPOj6Ke9vA8aNKjOos45Sa6wUu/ERIfo7n
         uGaikHF/VuHiG9pVMRD5OYE9nNz6ttK8CW+Y5cXjFhd8jhc2GjponpUuD5IOAlp4eHYV
         AZDYsbtmXo0EG0k7/TlG45VEF4doyldgfnsBSMI+p3b6p5LzvtbJW0bzeoQ9DhyLxODQ
         kResj1T4WNieDgAxKuGQDEZ2ErnDrv2PnH6BT1Yzwkl++fPgj4xGd0gHND4ePHeHr+0J
         Xh7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=MWy9Bool;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AHfSHAdaDG2N7AkqfNLUmLecbVo4e0eLqsQteUmuv2U=;
        b=aWU5QP8rWxLZ5KkeBJNH53uOxrdkXpkJ3HPoJuj5wSkxd8hx8mZwC4nMDZFo0OltoT
         YUSq/MEKjbUiE62o/izzbyMX0YoU6gAsHIl74YfOA8rCwSdg+4z/p98LBJA762T66OON
         9dA4Ys/ekDfm+ecL7PCmFqWaVRo384oPEafRETLTEkawshYzB5dUyGAW3rIVO9JnElzY
         RAWCbFzPx6itrf5iAD/cBbsf/x3buXhmYUjRTj+laql00B9M8Jd4D181x3diGfbHbSzf
         XS+y9MkgB9U1gxpYsH0D+gt5XMKWyKWAN7Im6ZUvFg7yIlfnGSsG5Cyhj6e6E/pozsha
         YK4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AHfSHAdaDG2N7AkqfNLUmLecbVo4e0eLqsQteUmuv2U=;
        b=46w9SqWWIY5b3ukN5j7x+w5p0/m7HI7QMO415kKlqM8cqJuM/33AjveQxcjParF4vg
         5FjOdpe0s7W9ZrHqaNZk+C7s0tVVxUGfuDH2nLricqnJZLgveWoQfH8pEHZDTz9Fzwhs
         +owMlCkKcB32qbxNVkVCQd1a2v3cf6eczzlBideJ83aLAmoxu65FTMqIS5A2vOLdTWgU
         Bg0rv2qJqVPAfzEQpbr+yQCkFfz+vFrRw7VD6DED/s23usv46xpWcxaQKjmeTOckffZG
         Yd8kQNeJeQ7IM5B5VHub1nRF6LRMzV80eR2C6Qa9W3zB5tAAlHTGDZQGK9ERxHuOXAGz
         SwRQ==
X-Gm-Message-State: AO0yUKUPRiu8/Lvgi+pUxM0HtoZ0BBlg4LBvgYAPTqcNjovK4nWWYGYw
	G1nGs9Q1fKjsTFsE2ir61gQ=
X-Google-Smtp-Source: AK7set9lnp83X18tOR8Jw3Q0XdIs1paUTBW+SHBbpPx8pDexk83jEWTc09zfNYwe1ZiG5MrycbCkLA==
X-Received: by 2002:ad4:5225:0:b0:539:fc2f:b52c with SMTP id r5-20020ad45225000000b00539fc2fb52cmr136081qvq.2.1674918047796;
        Sat, 28 Jan 2023 07:00:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4813:b0:3b8:2529:98c4 with SMTP id
 fb19-20020a05622a481300b003b8252998c4ls3221193qtb.9.-pod-prod-gmail; Sat, 28
 Jan 2023 07:00:47 -0800 (PST)
X-Received: by 2002:a05:622a:1818:b0:3b6:3022:688e with SMTP id t24-20020a05622a181800b003b63022688emr3926976qtc.53.1674918047023;
        Sat, 28 Jan 2023 07:00:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674918047; cv=none;
        d=google.com; s=arc-20160816;
        b=onZQHg1ByifWSKW0AmO/vr4KynOcXNRy3Et88lDChASvDuefP2No1WSuH5KaEo9rrg
         NQ6Y9sxqcmIiqqgVQe1Zyrx9szXkop4L3sV/bvyiyBzjmf0dd5fYFEVGp1xccNXbjPbm
         f/Hb7Cip5XVS4j1itE2OIgsyQc9X80uTzuCrYVg1kd1BYtOLXofTFQ6f82sgbVjzb7zG
         PbKzJZES4y6J3UDVgEDtHcgMIJlFg+Wtch0sNIWeCwoyMvZP5GH1oqoMDnp+WDK2su4g
         HWxyQV/FMxcNwRczcUCpvltB759SvrBMga4LDgICeuMdm1z0nrGZVT+BaB5CRi0DFKKP
         A6Ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=vhIe4AvtvdMXch+ZxnC9Rbxwru6rdzgNxb9LJZ07quU=;
        b=uyThr+mMu3lDN3E9TYBYZKPj0Vkp0kGdzdle+7enZQ8cPf336aPC9rPZFEcWndHYR1
         RNiodg5o4Qe1+wboINzLceK/AxsisZxq31Q9BxYohslAXJAt0MXgy0eH9mGn1iUUYXmk
         uqe3VvAGmJDyFYcP2QgL0+KvRkUNVB/gRdPm0e9724XaTHYNJgVmWemovob7K0YK0MK6
         sixzgffcrfPHqeTPQMJxEQjC0HE+1iXHHTenRAwKig+971D9hFFTeKMpl+T4bPrcqOcq
         ayrZcrmQKglpr0eRG+xTDHZ22M4txYaao7WGG87UdWzHMt41zZDeNFy/jZTdbkxBB1xt
         NAoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=MWy9Bool;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id z12-20020a05622a124c00b003b82ce6a004si308332qtx.4.2023.01.28.07.00.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 28 Jan 2023 07:00:45 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 85a9db369f1c11eda06fc9ecc4dadd91-20230128
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.18,REQID:7dfb5055-4431-4f58-b3b6-61d4f3a9dbfc,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:3ca2d6b,CLOUDID:fa069c55-dd49-462e-a4be-2143a3ddc739,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0
X-CID-BVR: 0
X-UUID: 85a9db369f1c11eda06fc9ecc4dadd91-20230128
Received: from mtkmbs10n2.mediatek.inc [(172.21.101.183)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 2008729776; Sat, 28 Jan 2023 23:00:36 +0800
Received: from mtkmbs13n1.mediatek.inc (172.21.101.193) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.792.3;
 Sat, 28 Jan 2023 23:00:35 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by
 mtkmbs13n1.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.792.15 via Frontend Transport; Sat, 28 Jan 2023 23:00:35 +0800
From: "'Kuan-Ying Lee' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, "Andrew
 Morton" <akpm@linux-foundation.org>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <chinwen.chang@mediatek.com>, <qun-wei.lin@mediatek.com>, Andrey Konovalov
	<andreyknvl@google.com>, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>
Subject: [PATCH v3] kasan: infer allocation size by scanning metadata
Date: Sat, 28 Jan 2023 23:00:23 +0800
Message-ID: <20230128150025.14491-1-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=MWy9Bool;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Reply-To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
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

Make KASAN scan metadata to infer the requested allocation size instead of
printing cache->object_size.

This patch fixes confusing slab-out-of-bounds reports as reported in:

https://bugzilla.kernel.org/show_bug.cgi?id=216457

As an example of the confusing behavior, the report below hints that the
allocation size was 192, while the kernel actually called kmalloc(184):

==================================================================
BUG: KASAN: slab-out-of-bounds in _find_next_bit+0x143/0x160 lib/find_bit.c:109
Read of size 8 at addr ffff8880175766b8 by task kworker/1:1/26
...
The buggy address belongs to the object at ffff888017576600
 which belongs to the cache kmalloc-192 of size 192
The buggy address is located 184 bytes inside of
 192-byte region [ffff888017576600, ffff8880175766c0)
...
Memory state around the buggy address:
 ffff888017576580: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
 ffff888017576600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>ffff888017576680: 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc fc
                                        ^
 ffff888017576700: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
 ffff888017576780: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
==================================================================

With this patch, the report shows:

==================================================================
...
The buggy address belongs to the object at ffff888017576600
 which belongs to the cache kmalloc-192 of size 192
The buggy address is located 0 bytes to the right of
 allocated 184-byte region [ffff888017576600, ffff8880175766b8)
...
==================================================================

Also report slab use-after-free bugs as "slab-use-after-free" and print
"freed" instead of "allocated" in the report when describing the accessed
memory region.

Also improve the metadata-related comment in kasan_find_first_bad_addr
and use addr_has_metadata across KASAN code instead of open-coding
KASAN_SHADOW_START checks.

Link: https://bugzilla.kernel.org/show_bug.cgi?id=216457
Co-developed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>

---

Changes v2->v3:

- Rename obj_size to alloc_size and change its type to size_t.
- Add comments into kasan_get_alloc_size.
- Infer and report alloc_size for all report types.
- Update metadata-related comment in kasan_find_first_bad_addr for HW_TAGS.
- Use addr_has_metadata for Generic and SW_TAGS modes instead of
  open-coding KASAN_SHADOW_START checks.
- Introduce slab-use-after-free report type.
- Print "freed" when describing memory region for slab-use-after-free bugs.
- Only print memory region state for Generic mode.

Changes v1->v2:

- Implement getting allocated size of object for tag-based kasan.
- Refine the kasan report.
- Check if it is slab-out-of-bounds report type.
- Thanks for Andrey and Dmitry suggestion.

---
 mm/kasan/generic.c        |  4 +---
 mm/kasan/kasan.h          |  2 ++
 mm/kasan/report.c         | 41 ++++++++++++++++++++++++++++-----------
 mm/kasan/report_generic.c | 32 +++++++++++++++++++++++++++++-
 mm/kasan/report_hw_tags.c | 35 ++++++++++++++++++++++++++++++++-
 mm/kasan/report_sw_tags.c | 26 +++++++++++++++++++++++++
 mm/kasan/report_tags.c    |  2 +-
 mm/kasan/sw_tags.c        |  6 ++----
 8 files changed, 127 insertions(+), 21 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index cb762982c8ba..e5eef670735e 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -172,10 +172,8 @@ static __always_inline bool check_region_inline(unsigned long addr,
 	if (unlikely(addr + size < addr))
 		return !kasan_report(addr, size, write, ret_ip);
 
-	if (unlikely((void *)addr <
-		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
+	if (unlikely(!addr_has_metadata((void *)addr)))
 		return !kasan_report(addr, size, write, ret_ip);
-	}
 
 	if (likely(!memory_is_poisoned(addr, size)))
 		return true;
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index dcc2a88e8121..3231314e071f 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -207,6 +207,7 @@ struct kasan_report_info {
 	void *first_bad_addr;
 	struct kmem_cache *cache;
 	void *object;
+	size_t alloc_size;
 
 	/* Filled in by the mode-specific reporting code. */
 	const char *bug_type;
@@ -323,6 +324,7 @@ static inline bool addr_has_metadata(const void *addr)
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 void *kasan_find_first_bad_addr(void *addr, size_t size);
+size_t kasan_get_alloc_size(void *object, struct kmem_cache *cache);
 void kasan_complete_mode_report_info(struct kasan_report_info *info);
 void kasan_metadata_fetch_row(char *buffer, void *row);
 
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 22598b20c7b7..e0492124e90a 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -231,33 +231,46 @@ static inline struct page *addr_to_page(const void *addr)
 	return NULL;
 }
 
-static void describe_object_addr(const void *addr, struct kmem_cache *cache,
-				 void *object)
+static void describe_object_addr(const void *addr, struct kasan_report_info *info)
 {
 	unsigned long access_addr = (unsigned long)addr;
-	unsigned long object_addr = (unsigned long)object;
-	const char *rel_type;
+	unsigned long object_addr = (unsigned long)info->object;
+	const char *rel_type, *region_state = "";
 	int rel_bytes;
 
 	pr_err("The buggy address belongs to the object at %px\n"
 	       " which belongs to the cache %s of size %d\n",
-		object, cache->name, cache->object_size);
+		info->object, info->cache->name, info->cache->object_size);
 
 	if (access_addr < object_addr) {
 		rel_type = "to the left";
 		rel_bytes = object_addr - access_addr;
-	} else if (access_addr >= object_addr + cache->object_size) {
+	} else if (access_addr >= object_addr + info->alloc_size) {
 		rel_type = "to the right";
-		rel_bytes = access_addr - (object_addr + cache->object_size);
+		rel_bytes = access_addr - (object_addr + info->alloc_size);
 	} else {
 		rel_type = "inside";
 		rel_bytes = access_addr - object_addr;
 	}
 
+	/*
+	 * Tag-Based modes use the stack ring to infer the bug type, but the
+	 * memory region state description is generated based on the metadata.
+	 * Thus, defining the region state as below can contradict the metadata.
+	 * Fixing this requires further improvements, so only infer the state
+	 * for the Generic mode.
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		if (strcmp(info->bug_type, "slab-out-of-bounds") == 0)
+			region_state = "allocated ";
+		else if (strcmp(info->bug_type, "slab-use-after-free") == 0)
+			region_state = "freed ";
+	}
+
 	pr_err("The buggy address is located %d bytes %s of\n"
-	       " %d-byte region [%px, %px)\n",
-		rel_bytes, rel_type, cache->object_size, (void *)object_addr,
-		(void *)(object_addr + cache->object_size));
+	       " %s%lu-byte region [%px, %px)\n",
+	       rel_bytes, rel_type, region_state, info->alloc_size,
+	       (void *)object_addr, (void *)(object_addr + info->alloc_size));
 }
 
 static void describe_object_stacks(struct kasan_report_info *info)
@@ -279,7 +292,7 @@ static void describe_object(const void *addr, struct kasan_report_info *info)
 {
 	if (kasan_stack_collection_enabled())
 		describe_object_stacks(info);
-	describe_object_addr(addr, info->cache, info->object);
+	describe_object_addr(addr, info);
 }
 
 static inline bool kernel_or_module_addr(const void *addr)
@@ -436,6 +449,12 @@ static void complete_report_info(struct kasan_report_info *info)
 	if (slab) {
 		info->cache = slab->slab_cache;
 		info->object = nearest_obj(info->cache, slab, addr);
+
+		/* Try to determine allocation size based on the metadata. */
+		info->alloc_size = kasan_get_alloc_size(info->object, info->cache);
+		/* Fallback to the object size if failed. */
+		if (!info->alloc_size)
+			info->alloc_size = info->cache->object_size;
 	} else
 		info->cache = info->object = NULL;
 
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 043c94b04605..87d39bc0a673 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -43,6 +43,34 @@ void *kasan_find_first_bad_addr(void *addr, size_t size)
 	return p;
 }
 
+size_t kasan_get_alloc_size(void *object, struct kmem_cache *cache)
+{
+	size_t size = 0;
+	u8 *shadow;
+
+	/*
+	 * Skip the addr_has_metadata check, as this function only operates on
+	 * slab memory, which must have metadata.
+	 */
+
+	/*
+	 * The loop below returns 0 for freed objects, for which KASAN cannot
+	 * calculate the allocation size based on the metadata.
+	 */
+	shadow = (u8 *)kasan_mem_to_shadow(object);
+	while (size < cache->object_size) {
+		if (*shadow == 0)
+			size += KASAN_GRANULE_SIZE;
+		else if (*shadow >= 1 && *shadow <= KASAN_GRANULE_SIZE - 1)
+			return size + *shadow;
+		else
+			return size;
+		shadow++;
+	}
+
+	return cache->object_size;
+}
+
 static const char *get_shadow_bug_type(struct kasan_report_info *info)
 {
 	const char *bug_type = "unknown-crash";
@@ -79,9 +107,11 @@ static const char *get_shadow_bug_type(struct kasan_report_info *info)
 		bug_type = "stack-out-of-bounds";
 		break;
 	case KASAN_PAGE_FREE:
+		bug_type = "use-after-free";
+		break;
 	case KASAN_SLAB_FREE:
 	case KASAN_SLAB_FREETRACK:
-		bug_type = "use-after-free";
+		bug_type = "slab-use-after-free";
 		break;
 	case KASAN_ALLOCA_LEFT:
 	case KASAN_ALLOCA_RIGHT:
diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
index f3d3be614e4b..32e80f78de7d 100644
--- a/mm/kasan/report_hw_tags.c
+++ b/mm/kasan/report_hw_tags.c
@@ -17,10 +17,43 @@
 
 void *kasan_find_first_bad_addr(void *addr, size_t size)
 {
-	/* Return the same value regardless of whether addr_has_metadata(). */
+	/*
+	 * Hardware Tag-Based KASAN only calls this function for normal memory
+	 * accesses, and thus addr points precisely to the first bad address
+	 * with an invalid (and present) memory tag. Therefore:
+	 * 1. Return the address as is without walking memory tags.
+	 * 2. Skip the addr_has_metadata check.
+	 */
 	return kasan_reset_tag(addr);
 }
 
+size_t kasan_get_alloc_size(void *object, struct kmem_cache *cache)
+{
+	size_t size = 0;
+	int i = 0;
+	u8 memory_tag;
+
+	/*
+	 * Skip the addr_has_metadata check, as this function only operates on
+	 * slab memory, which must have metadata.
+	 */
+
+	/*
+	 * The loop below returns 0 for freed objects, for which KASAN cannot
+	 * calculate the allocation size based on the metadata.
+	 */
+	while (size < cache->object_size) {
+		memory_tag = hw_get_mem_tag(object + i * KASAN_GRANULE_SIZE);
+		if (memory_tag != KASAN_TAG_INVALID)
+			size += KASAN_GRANULE_SIZE;
+		else
+			return size;
+		i++;
+	}
+
+	return cache->object_size;
+}
+
 void kasan_metadata_fetch_row(char *buffer, void *row)
 {
 	int i;
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index 7a26397297ed..8b1f5a73ee6d 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -45,6 +45,32 @@ void *kasan_find_first_bad_addr(void *addr, size_t size)
 	return p;
 }
 
+size_t kasan_get_alloc_size(void *object, struct kmem_cache *cache)
+{
+	size_t size = 0;
+	u8 *shadow;
+
+	/*
+	 * Skip the addr_has_metadata check, as this function only operates on
+	 * slab memory, which must have metadata.
+	 */
+
+	/*
+	 * The loop below returns 0 for freed objects, for which KASAN cannot
+	 * calculate the allocation size based on the metadata.
+	 */
+	shadow = (u8 *)kasan_mem_to_shadow(object);
+	while (size < cache->object_size) {
+		if (*shadow != KASAN_TAG_INVALID)
+			size += KASAN_GRANULE_SIZE;
+		else
+			return size;
+		shadow++;
+	}
+
+	return cache->object_size;
+}
+
 void kasan_metadata_fetch_row(char *buffer, void *row)
 {
 	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index ecede06ef374..8b8bfdb3cfdb 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -89,7 +89,7 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 			 * a use-after-free.
 			 */
 			if (!info->bug_type)
-				info->bug_type = "use-after-free";
+				info->bug_type = "slab-use-after-free";
 		} else {
 			/* Second alloc of the same object. Give up. */
 			if (alloc_found)
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index a3afaf2ad1b1..30da65fa02a1 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -106,10 +106,8 @@ bool kasan_check_range(unsigned long addr, size_t size, bool write,
 		return true;
 
 	untagged_addr = kasan_reset_tag((const void *)addr);
-	if (unlikely(untagged_addr <
-			kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
+	if (unlikely(!addr_has_metadata(untagged_addr)))
 		return !kasan_report(addr, size, write, ret_ip);
-	}
 	shadow_first = kasan_mem_to_shadow(untagged_addr);
 	shadow_last = kasan_mem_to_shadow(untagged_addr + size - 1);
 	for (shadow = shadow_first; shadow <= shadow_last; shadow++) {
@@ -127,7 +125,7 @@ bool kasan_byte_accessible(const void *addr)
 	void *untagged_addr = kasan_reset_tag(addr);
 	u8 shadow_byte;
 
-	if (untagged_addr < kasan_shadow_to_mem((void *)KASAN_SHADOW_START))
+	if (!addr_has_metadata(untagged_addr))
 		return false;
 
 	shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(untagged_addr));
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230128150025.14491-1-Kuan-Ying.Lee%40mediatek.com.

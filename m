Return-Path: <kasan-dev+bncBDY7XDHKR4OBBWNN26PAMGQESNCCF5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 4419167FC4C
	for <lists+kasan-dev@lfdr.de>; Sun, 29 Jan 2023 03:15:55 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id q130-20020a632a88000000b004a03cfb3ac6sf3471373pgq.6
        for <lists+kasan-dev@lfdr.de>; Sat, 28 Jan 2023 18:15:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674958553; cv=pass;
        d=google.com; s=arc-20160816;
        b=Da37XJTr5jwCE5cIM1laaovKnNHd8M6ZaOdhwedBF0EXCUnCd+5Pl6jUBD9ynsvDm7
         ml30oxmfVS/22bpgCvsosnjKltwCTrsm+9nQSYr10Q6Hwi+fUnzf4m7bmym+9jySMq0J
         yhMUxMWFOOpJ5t37tpLJo/hBODUDjsgmit6oqUzLhYyzNbg+tUAUCauQF8o4JQjIgzbG
         ov6OVQ1d3XDbqMQdvtY+KZVPrFAOCyTeheL1A8eGqh80bstLZHLIbGzbZ59NCfznHFww
         aQY22znpzcuvwz9KCZdpxc5/aublouenTPSNemuVuES57N6rJc2NrHo3uWBKR2eSAMba
         X/uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=U5eC5Uui5WLjS54TGv8Z0MO4HD4kr3VoaYU7gI4KiUU=;
        b=E2fc3KGDlPgpAX570OIaGikxRv5AXdMdnZCBJhkCM1OQzdznue5NgQUcA3Hc7wI5Zm
         yjl9HkGDNFlUJyyMNr/3R+p3ITfOuquqPdfslx1yI4nDQ0lyc8uFrPoD4hs+6fih5e8h
         /Qawj1amYEZUJT3raK5u+xBsP/V4odHT3X6XQ8j3Cf+BNSWB8m+6HKhatp1/y1CniaL6
         DxqGJ9n1j5MkRvWpDU3ZFDDqlEAwAW4AXFbPuTPSOLX155VygPle5g3nN8u7amWK4Rzd
         j/cBv/GnA7SQhmOhW+hTBCDGdBTn7wekVlB8RWbn8dPcNjr4Up3cAkwlqZg7wlLzStk5
         tabQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=nRPuXgax;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=U5eC5Uui5WLjS54TGv8Z0MO4HD4kr3VoaYU7gI4KiUU=;
        b=f5Szv76Oll6M3L6ULeNNA2RZLjScncSYwM7j+ROLEQHikxOF+X7XDYWZNtVTyAWnvs
         sbjwNi7laZ84TZtzXJX5BdUwFDZfFFjn8tE4qV5XRrVYYr60XyheXhy6e1Hvdep/rjN+
         Ft3JtOK7e4Xx4EOfxuz/UIrvZtPnnY0rvh0HqBokIlCxpev74R/IfzcHXGacEwdqLxK+
         4gSfd29vhX42K/N9ePgzT+V5pmIgEYXEQjUM//SIqRaVR3sOSnnIx58aVhJ0YgUQBNEX
         AD03aVTDCErqTm6XOO8Qh3JwVDVtCjuO7aG+6WXBD8n0HaaTUAJYyYhL8ghYGKnC2L9w
         vOLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=U5eC5Uui5WLjS54TGv8Z0MO4HD4kr3VoaYU7gI4KiUU=;
        b=ZBvpJlpQkvQ+BAaHMlderT2bVv9VXJOIuSilzgCDNgEciCymfUjVzBFQQdvqQ9wEvM
         EzoYTPQUYVKmr32cGVnpyt9vfWUCEk2eV9AV3VMFdrX7yQXqXpDqHM9OABPz2+Vj4nZN
         xhWuafEC0jrbkh522Oee+HpzHx8j69wGrT0mNoQAexSRTxc0DsKQm6njmwe58u2MB+cQ
         OiD8HpSXp6ESDruO/KAxJrArBjOTiixbuKTsgbWFygb+5e7NRSBqVHJzxZN9qZDZ8ff1
         AQfATn8mcZoXrbKgIlJs3gy93Ad1tTaVCyyt1Lvz6D9PrvYUMgzNQgGvu8x//WyUS5n3
         x2UA==
X-Gm-Message-State: AFqh2kp9kB9hhB0xoeXywUKsa7l4Xtc5cHbtvPpR625cGCImLc0BDtVz
	i8DrKm24lOW2zvom1ilGluo=
X-Google-Smtp-Source: AMrXdXvmetRg2Pmy3HXK+UQ/EIYt2+s7u/kHyG7a1AdzgEoKFtddgRV5TGF6tSYpVVQ4FE+spsriWQ==
X-Received: by 2002:a05:6a00:1490:b0:58d:be61:7d94 with SMTP id v16-20020a056a00149000b0058dbe617d94mr6204580pfu.65.1674958553316;
        Sat, 28 Jan 2023 18:15:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7987:0:b0:592:4dc1:49e8 with SMTP id u129-20020a627987000000b005924dc149e8ls2006696pfc.0.-pod-prod-gmail;
 Sat, 28 Jan 2023 18:15:52 -0800 (PST)
X-Received: by 2002:a62:1495:0:b0:592:528e:72a1 with SMTP id 143-20020a621495000000b00592528e72a1mr8829518pfu.27.1674958552517;
        Sat, 28 Jan 2023 18:15:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674958552; cv=none;
        d=google.com; s=arc-20160816;
        b=IN2LSkrMPeu7ci0+ZpowWr1LLLTQRfEcljLhdGgbh9irWG7GQCdyp9FK68T3rKPWIq
         Qwq4TDSlWhBaTOPumM3uDOWUa5j/xrsaXIhJAl8qcJuhWclUG6da3vRFlANoubvWvLIG
         n02hix1pzyjQIMUx9dmZDYo5gnowTdShE0egk7b/jst9LakTd8ZY0glZ2XhKVZH0OeWx
         fYFBrFwUrikZwaymKaHHTTn087speTtmtKNbzmiWPBMvydf4ilPw29vifH/JGv5BAAak
         gXEXqiZYVUhBScnlUtw5Rtw04xNj+NgScx8f0zjQHNDw+CFPVcSkljcfxA42ImWbZPU8
         w6Hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=XhHmJ2XlHdSznR6d+1zWQZ89NMCKCkYujHZawrbnfto=;
        b=GojJ9/gjOs3FF9UILdxzpOTXxb2y1rmt0bDRRj8QFl/u0w/P2VP91zY9wPTng1l9nK
         N8MjD5kWce+0Xq3IYQZh9uC79yJKYOa6mIpPD7e5H/cbrFchMVzRz4UBNnBHLEt6YQ/C
         kdSJ6pyW9Nwh9vTsE+yMw+GToeomBK/nBxbkxQvR+k0VAdT01U/qiuqx3z4ctNguL2DC
         T2AqC3wDopb25E8aqxzff6nSva1ote0GV1RTifWBLJz/HTZ3vveFhxFty01oFZQ1IX1p
         G8G5xmK2L1GvlptsYSn/OsIWuv5F6jNc0Fde1TKttNvJMoqqcQHroEg8Mi6yAbiBh50t
         OHgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=nRPuXgax;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id o191-20020a62cdc8000000b0059076272a23si627409pfg.3.2023.01.28.18.15.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 28 Jan 2023 18:15:52 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: d72321f89f7a11eda06fc9ecc4dadd91-20230129
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.18,REQID:80850fa4-3b81-4ed5-98fa-4f9352435c7a,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:3ca2d6b,CLOUDID:e4d9a055-dd49-462e-a4be-2143a3ddc739,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0
X-CID-BVR: 0
X-UUID: d72321f89f7a11eda06fc9ecc4dadd91-20230129
Received: from mtkmbs10n2.mediatek.inc [(172.21.101.183)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 530970514; Sun, 29 Jan 2023 10:15:46 +0800
Received: from mtkmbs13n1.mediatek.inc (172.21.101.193) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.792.3;
 Sun, 29 Jan 2023 10:15:44 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by
 mtkmbs13n1.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.792.15 via Frontend Transport; Sun, 29 Jan 2023 10:15:44 +0800
From: "'Kuan-Ying Lee' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, "Andrew
 Morton" <akpm@linux-foundation.org>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <chinwen.chang@mediatek.com>, <qun-wei.lin@mediatek.com>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>
Subject: [PATCH v4] kasan: infer allocation size by scanning metadata
Date: Sun, 29 Jan 2023 10:14:35 +0800
Message-ID: <20230129021437.18812-1-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=nRPuXgax;       spf=pass
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

Changes v3->v4:

- Change the author

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230129021437.18812-1-Kuan-Ying.Lee%40mediatek.com.

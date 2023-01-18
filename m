Return-Path: <kasan-dev+bncBDY7XDHKR4OBBOP4T2PAMGQEHDQEJIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id ECBEA6717EB
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Jan 2023 10:39:06 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id cz20-20020a0568306a1400b006849b669d65sf13003432otb.10
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Jan 2023 01:39:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674034745; cv=pass;
        d=google.com; s=arc-20160816;
        b=jhsCb0VWSAdVX5L2ytmwufJiIgrtgr2N+iWM/pahDXpHBAUZWrBLxl8OeRh5uoU9Sb
         FwmT98WAWvVPH1I8r8i5uFP6i5NIvxFDhsDfHCZRf7GhXnejDVDIR4fz5raTZWSkLRvc
         kVexTgCIkgXJeI14Ft4yuQA+xeaakgDmkuKexofsXtDa+XLXPPAUdaR3Mfh+iMO7/ctC
         QNyk85gujVgrgP9tOWLXIQhM40uD3R/QF/ds2q5W4BQctC6N5DaHbeKC5/i2kBbycKNK
         AlXZi/RFgKo+9l/GsrQrEvRwWxZfN6A/QwWbgZlg0VfdO3QXosodTsuhHSFsTWRFpybo
         +HlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=f0kKIYguWPRPR/tKcBZKYBlGrYKwQio/h2YmI97Duzg=;
        b=SDBDIGcZEfrH1t9MPU0wXNteIzFMnONLEBYhcH1r/PQWhLNcASjYpVx24YEdT7Vdab
         ki0gdISOMaiOnMUsjZPybqwqSGTgR9+SL4OmpSxi5oam18PPtPBmDs+NI6zfuATfYliW
         6KCfdWo+I6UmJxueVI2O7e4VSdpdYPUI8gksqqFNGw3/vsmGnC9kIkMYoVIaW9IK0Yys
         Y7oXflvcHwOU+69r+qN7hzXJfQBpH3m6OwIToh3ZGoO3fJNOujfbYYKthQRdZ+bV+YAs
         AaUdU1U7U4NGmSo6ZG8lYlUxD8dhw2jXi0WOQDu+K3kibKjNU1AdwTJSZEC2gFprnkUu
         yrOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=V8eIWzGw;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=f0kKIYguWPRPR/tKcBZKYBlGrYKwQio/h2YmI97Duzg=;
        b=snfEoWWgb8L7bveh/jEScZ1oY8747LEnoYkfFcEFWFy+GMupTNXKung8MYc4qnY6CS
         nfA0k9KOgAycWn5x7hUg4ievr0VkL79GXO9ptec+eYTAiI3Cdj847YYvKgMhr2GXvYpD
         bYPjmbk6DWR5qjN26RVas60qxVoA7171MV50nZdhiCO55LbGrS5XReXCmFOh0HxkeBo2
         vD60RVA7YWafDZ2iIllSe6LUfPereODGvffsTcfA+hl29/9AXsY7ldAOaYnCzqsbfr1V
         G4Y9Z+TqdQv3EJzTvaiYZUO+cHohsbxgf5a4Iqwm2SjonNBdfI6XRkUvb1goAnBGdTFT
         OSbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=f0kKIYguWPRPR/tKcBZKYBlGrYKwQio/h2YmI97Duzg=;
        b=OEMyONYnYQkhKWVNQdu2dJYJUW3eKEDhTwN4g/RMJfVCEvkBxxKmmTDotMRCzpJlcU
         DHUHFv7Eb9naUCD/o3DGvDwXMeBEo9EaC0844zyYtQRNvLRGsLWb/uP4Qs5jQOQC7tQG
         mt2yc3+npRSNRjBqrVNQsjGxIlzY52NkJ0BpbLRgYyIAIreeuGPHKCvtqCpXyN2BE9XF
         jQ1J40R9AQMC3Qdg6pFOpr/vbv+HDI0HSsfohQrbRK9VcKB8lYBEiH3iYrunUVGDkcR+
         LbEgGgx2ZRGQsQxmyB2EXcHvH4diPrut2ckt1urm1q8Msx65ZpxNytIDR0GGeslcdHYt
         4alg==
X-Gm-Message-State: AFqh2kpJJ2vW4ld4U4zo/Ebv64V2DQuMFajTwCg3SBgwFv/bQTvfK8Cz
	nxvRVsbKgdOle1UtoU6xuCc=
X-Google-Smtp-Source: AMrXdXsgsF0d/lEo30c6JLzjH5IwbXUk9XSDqrU79KicyQF8fS0o6vYhwJzbUXONZPrnBY170uLfKA==
X-Received: by 2002:a05:6830:448:b0:684:c7ad:9c7a with SMTP id d8-20020a056830044800b00684c7ad9c7amr335296otc.254.1674034745453;
        Wed, 18 Jan 2023 01:39:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3a2a:b0:150:5959:52ad with SMTP id
 du42-20020a0568703a2a00b00150595952adls7393271oab.3.-pod-prod-gmail; Wed, 18
 Jan 2023 01:39:05 -0800 (PST)
X-Received: by 2002:a05:6870:be8e:b0:15b:9ab9:75ee with SMTP id nx14-20020a056870be8e00b0015b9ab975eemr3323621oab.48.1674034745088;
        Wed, 18 Jan 2023 01:39:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674034745; cv=none;
        d=google.com; s=arc-20160816;
        b=MJ5N+7veLlaqFtIRf+C12m9ywGwwCBOqEgH0WYJxRTylFFguESCx82sHpatNIxrVDv
         kwWALcrn3YwKNrv8bgiyKIjojDx+6+2NjpZO2ou8oWZZA7zFsCicxkDowJdcQto9HcUb
         4ZJmZWxYIVk3D2kpExOFterA644FnnHBhsI2XuaMkMAfP5I06ohzwBx8lVQN0zxWQa/I
         91pvof8Gy5SMKnqdHKl9+JtJBHCnMDh6Vc/+QK5HUhVPP45OzMZmEY3ajLGADLy8cGYR
         yaxSS5qdKmsesC0OzECEFzdLifYWjwc5KY9nDcJ3DE868j+c5243q9M07ECb0zxLxjGQ
         dq/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=WaDG+rrqxlJT/6GIGWHNWGiT1aQrPsWBNzoW/dbYNnM=;
        b=s2qacNU88G7hV58J4vgz4ysvmUfIVpEPpetNX7WdDbAKNcOZxVIzbfr0KIr8gEn3GP
         zhZEiNTvrL+I/WDAsKvzPhi8MB99+jHYQZ5EqkfmH/krnIKkA/0dXVXaT/zyupyK2WK4
         ROvcH08GK4zfJSs3LWyV6V4mAVtQr5faDeDbFuvyeEuRZvi6Zv3KBUieXCsxOnod7o+j
         U3pUiRriI4gem6b9iRwJNf2xSN6ia/zU+y5AW83tU6uS9tLCC6wQdfKTuGfTvJ1qT3vy
         9i8aqnz+e32mFXb597JJdQ1qnrZHuA9uDuX48+FQ7u5YED4bdjIFOq+jARF5dXXoaIA6
         jcAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=V8eIWzGw;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id z15-20020a056871014f00b0015452b4f27asi3129327oab.3.2023.01.18.01.39.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Jan 2023 01:39:04 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: eed0a592971311eda06fc9ecc4dadd91-20230118
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.18,REQID:7f928ffa-14cd-4fb0-8d02-1bf6c2c1c9c6,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:3ca2d6b,CLOUDID:b6c69b8c-8530-4eff-9f77-222cf6e2895b,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0
X-CID-BVR: 0
X-UUID: eed0a592971311eda06fc9ecc4dadd91-20230118
Received: from mtkmbs11n1.mediatek.inc [(172.21.101.185)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1301835293; Wed, 18 Jan 2023 17:38:58 +0800
Received: from mtkmbs13n1.mediatek.inc (172.21.101.193) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.792.15; Wed, 18 Jan 2023 17:38:57 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by
 mtkmbs13n1.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.792.15 via Frontend Transport; Wed, 18 Jan 2023 17:38:57 +0800
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
Subject: [PATCH v2] kasan: infer the requested size by scanning shadow memory
Date: Wed, 18 Jan 2023 17:38:30 +0800
Message-ID: <20230118093832.1945-1-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=V8eIWzGw;       spf=pass
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

We scan the shadow memory to infer the requested size instead of
printing cache->object_size directly.

This patch will fix the confusing kasan slab-out-of-bounds
report like below. [1]
Report shows "cache kmalloc-192 of size 192", but user
actually kmalloc(184).

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

After this patch, slab-out-of-bounds report will show as below.
==================================================================
...
The buggy address belongs to the object at ffff888017576600
 which belongs to the cache kmalloc-192 of size 192
The buggy address is located 0 bytes right of
 allocated 184-byte region [ffff888017576600, ffff8880175766b8)
...
==================================================================

Link: https://bugzilla.kernel.org/show_bug.cgi?id=216457 [1]

Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
---
V1 -> V2:
 - Implement getting allocated size of object for tag-based kasan.
 - Refine the kasan report.
 - Check if it is slab-out-of-bounds report type.
 - Thanks for Andrey and Dmitry suggestion.

 mm/kasan/kasan.h          |  2 ++
 mm/kasan/report.c         | 20 +++++++++++++-------
 mm/kasan/report_generic.c | 24 ++++++++++++++++++++++++
 mm/kasan/report_hw_tags.c | 18 ++++++++++++++++++
 mm/kasan/report_sw_tags.c | 17 +++++++++++++++++
 mm/kasan/report_tags.c    |  8 ++++++++
 6 files changed, 82 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index abbcc1b0eec5..15ffd46fec6a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -185,6 +185,7 @@ struct kasan_report_info {
 	const char *bug_type;
 	struct kasan_track alloc_track;
 	struct kasan_track free_track;
+	int obj_size;
 };
 
 /* Do not change the struct layout: compiler ABI. */
@@ -306,6 +307,7 @@ static inline bool addr_has_metadata(const void *addr)
 void *kasan_find_first_bad_addr(void *addr, size_t size);
 void kasan_complete_mode_report_info(struct kasan_report_info *info);
 void kasan_metadata_fetch_row(char *buffer, void *row);
+int kasan_get_alloc_size(void *object_addr, struct kmem_cache *cache);
 
 #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 void kasan_print_tags(u8 addr_tag, const void *addr);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index df3602062bfd..dae0d4ae8fe9 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -210,12 +210,13 @@ static inline struct page *addr_to_page(const void *addr)
 }
 
 static void describe_object_addr(const void *addr, struct kmem_cache *cache,
-				 void *object)
+				 void *object, int obj_size, const char *bug_type)
 {
 	unsigned long access_addr = (unsigned long)addr;
 	unsigned long object_addr = (unsigned long)object;
 	const char *rel_type;
 	int rel_bytes;
+	bool slab_oob = false;
 
 	pr_err("The buggy address belongs to the object at %px\n"
 	       " which belongs to the cache %s of size %d\n",
@@ -224,18 +225,22 @@ static void describe_object_addr(const void *addr, struct kmem_cache *cache,
 	if (access_addr < object_addr) {
 		rel_type = "to the left";
 		rel_bytes = object_addr - access_addr;
-	} else if (access_addr >= object_addr + cache->object_size) {
+	} else if (access_addr >= object_addr + obj_size) {
 		rel_type = "to the right";
-		rel_bytes = access_addr - (object_addr + cache->object_size);
+		rel_bytes = access_addr - (object_addr + obj_size);
 	} else {
 		rel_type = "inside";
 		rel_bytes = access_addr - object_addr;
 	}
 
+	if (strcmp(bug_type, "slab-out-of-bounds") == 0)
+		slab_oob = true;
+
 	pr_err("The buggy address is located %d bytes %s of\n"
-	       " %d-byte region [%px, %px)\n",
-		rel_bytes, rel_type, cache->object_size, (void *)object_addr,
-		(void *)(object_addr + cache->object_size));
+	       " %s%d-byte region [%px, %px)\n",
+	       rel_bytes, rel_type, slab_oob ? "allocated " : "",
+	       obj_size, (void *)object_addr,
+	       (void *)(object_addr + obj_size));
 }
 
 static void describe_object_stacks(struct kasan_report_info *info)
@@ -257,7 +262,8 @@ static void describe_object(const void *addr, struct kasan_report_info *info)
 {
 	if (kasan_stack_collection_enabled())
 		describe_object_stacks(info);
-	describe_object_addr(addr, info->cache, info->object);
+	describe_object_addr(addr, info->cache, info->object, info->obj_size,
+			info->bug_type);
 }
 
 static inline bool kernel_or_module_addr(const void *addr)
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 043c94b04605..7b4bec9e6d1a 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -43,6 +43,25 @@ void *kasan_find_first_bad_addr(void *addr, size_t size)
 	return p;
 }
 
+int kasan_get_alloc_size(void *addr, struct kmem_cache *cache)
+{
+	int size = 0;
+	u8 *shadow;
+
+	shadow = (u8 *)kasan_mem_to_shadow(addr);
+	while (size < cache->object_size) {
+		if (*shadow == 0)
+			size += KASAN_GRANULE_SIZE;
+		else if (*shadow >= 1 && *shadow <= KASAN_GRANULE_SIZE - 1)
+			size += *shadow;
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
@@ -149,6 +168,11 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 		memcpy(&info->free_track, &free_meta->free_track,
 		       sizeof(info->free_track));
 	}
+
+	if (strcmp(info->bug_type, "slab-out-of-bounds") == 0)
+		info->obj_size = kasan_get_alloc_size(info->object, info->cache);
+	else
+		info->obj_size = info->cache->object_size;
 }
 
 void kasan_metadata_fetch_row(char *buffer, void *row)
diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
index f3d3be614e4b..e462dd750fe2 100644
--- a/mm/kasan/report_hw_tags.c
+++ b/mm/kasan/report_hw_tags.c
@@ -21,6 +21,24 @@ void *kasan_find_first_bad_addr(void *addr, size_t size)
 	return kasan_reset_tag(addr);
 }
 
+int kasan_get_alloc_size(void *addr, struct kmem_cache *cache)
+{
+	int size = 0, i = 0;
+	u8 memory_tag;
+
+	while (size < cache->object_size) {
+		memory_tag = hw_get_mem_tag(addr + i * KASAN_GRANULE_SIZE);
+
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
index 7a26397297ed..d50caefd7fd5 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -45,6 +45,23 @@ void *kasan_find_first_bad_addr(void *addr, size_t size)
 	return p;
 }
 
+int kasan_get_alloc_size(void *addr, struct kmem_cache *cache)
+{
+	int size = 0;
+	u8 *shadow;
+
+	shadow = (u8 *)kasan_mem_to_shadow(addr);
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
index ecede06ef374..b349a0ae1b83 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -7,6 +7,7 @@
 #include <linux/atomic.h>
 
 #include "kasan.h"
+#include "../slab.h"
 
 extern struct kasan_stack_ring stack_ring;
 
@@ -113,4 +114,11 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 	/* Assign the common bug type if no entries were found. */
 	if (!info->bug_type)
 		info->bug_type = get_common_bug_type(info);
+
+	if (info->object && info->cache) {
+		if (strcmp(info->bug_type, "slab-out-of-bounds") == 0)
+			info->obj_size = kasan_get_alloc_size(info->object, info->cache);
+		else
+			info->obj_size = info->cache->object_size;
+	}
 }
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230118093832.1945-1-Kuan-Ying.Lee%40mediatek.com.

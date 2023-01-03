Return-Path: <kasan-dev+bncBDY7XDHKR4OBBJ57Z6OQMGQEXI5LK6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id BFA9265BB74
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Jan 2023 08:56:25 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id om16-20020a17090b3a9000b002216006cbffsf20431079pjb.3
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Jan 2023 23:56:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672732584; cv=pass;
        d=google.com; s=arc-20160816;
        b=nwC/QGvSXCMO9wwiwV69tb8YXz2mObd104I0SxfCBx26aSRezOu1N7u6H+tpw8SKXG
         Vi9jtTU3U0lHWQ86h2CnvNq6EpjB/U+hHc8ZCJfbJhaJ5uy1uGDxhi0U9ZhyoCVbMMJP
         IMEwpWImSMZ+L3fosFui72zF1g0NKYx0dZKip95ucJwsrIw+SXjgHMRUE9ibguVCVkEP
         kck9xINfofHgw3jFD8/aRFSkrj9H9WkoYWdhC5q8FdtdRk0uFacAGZcvl+fxJLsM/VS3
         AvfOT/sVXrhK1SGPML1fSWhPfUOCIDoqXJTNyoVxVtapN0AUt4RqhBo/GeqUt0E/Sg+2
         ZeBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=h510QBa99BFlTIXOIFkvA2kRZSGxoi1OzXE8u5VPksA=;
        b=bfwzeW6QtcpwPmEXvwL0WhVsgYhblJj0yY36DvDTB2zxQvN9zGP05VJS3OEYKxo/XN
         2c6RhENLqRbAekb1+qZG9kqxecx37V6PsJhxQcp0/rg9E1kzMWCl8KF4qUZ/aK5ED2z0
         M9Mr84u/OgVMgzCe2tBL2OzGVPUOBVsQHc+QoIiDAqYSx8cL0JXxWOSsMtpuFMKCg2yC
         G12cblWt1PjW9rd22+vsRLMAQ6+mTatwKVoEnLcZq72Oa+ScEB1UfEpqIJiPqMCjJgn7
         kuDytiXX7ucdBYHt5RmRp7POhv8uWclkFJg/zICYuItD4NdKQaoArKIQ0uHHpD9RVyuo
         GDeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=nR+3dsVK;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h510QBa99BFlTIXOIFkvA2kRZSGxoi1OzXE8u5VPksA=;
        b=otQArdXhEm9Exdyojflg511ZzzAtRwAHsIecET4d2SkNGqR3/Iw4tzFikrc9U19fnX
         S0feGi1xTQJ7eCB15sSuCO3HnSEsvEe2qpBrUdGjaKoAjCPNrwtSsR7VsIdQpAJ5CSjO
         JJkTRnWYioLpj13mfBcBdwFvpjaHxvKxIyBmZnXrJJJU8q0KQAenX+/RmJx5tXTV1/8k
         POqVUJOjkuwUC3VB49/QH2wjKN1ukH6iB5+r5lxyFZdu6e2pVfzAec1oyV1hczabeTwV
         3dsP6jZRtLLT7Q9YyYdghAXbN43PeE7cIkXI46H5kulNN2PK9w1gnAfdhtZdUehnfjnW
         O8XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=h510QBa99BFlTIXOIFkvA2kRZSGxoi1OzXE8u5VPksA=;
        b=vCynM/KXWEX/6YiXdKgos5mouzehSkzRWcjaty02FouCg+6ex4dAY8DCv1x+dXaKFM
         /10MQUv0IhfQPHwjXMLXn2ZaX8wzblCnFZXF7UQPO4h6YoD6T4C9hk2oOWkM5iAZtL+y
         UWBMc0Ex4ghCSVWAYuXWAgbkiktXB9a0V60Afy68F6Cn3h1CYwLdppFda7FfddUVMO6x
         gY4o+FD5ftVIkHEZ38eIde4h0ImlHHIFjjMjG+JAp783TDaUdbLzXW0TZ62toiq3iWB0
         uSLYkEshyiQuHNplUYmz7ZnJ0tn7a+a2LwWTA4uK43MSgI79kG27qqw+qbyy1TEFgoHF
         PCOg==
X-Gm-Message-State: AFqh2kr8UaJ9pvo1Nsl4wP68YNaQ16w37qx17U+hkBL7Y7INSOgs1xZk
	2lHatMCxZxRWL/o8VhH9jnk=
X-Google-Smtp-Source: AMrXdXubM8O5ZUTSZ79A+Y+CtR0nAbUH2ENXL2q5Vj6A34AK5f6m+ZTO1Oco5ygUQjtSaUJVgKwKng==
X-Received: by 2002:a63:1f44:0:b0:47c:ab44:bcf2 with SMTP id q4-20020a631f44000000b0047cab44bcf2mr2993860pgm.486.1672732583986;
        Mon, 02 Jan 2023 23:56:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a015:b0:210:6f33:e22d with SMTP id
 q21-20020a17090aa01500b002106f33e22dls32774572pjp.2.-pod-control-gmail; Mon,
 02 Jan 2023 23:56:23 -0800 (PST)
X-Received: by 2002:a17:902:eb91:b0:18f:b812:5df7 with SMTP id q17-20020a170902eb9100b0018fb8125df7mr51369854plg.28.1672732583238;
        Mon, 02 Jan 2023 23:56:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672732583; cv=none;
        d=google.com; s=arc-20160816;
        b=SqNnyYr1d2vR+LRx6vGMpiuuvyv1V474f/gfRGCLEvstryc7Ar0VXY+zrJvLw6uZPn
         l3anGrAD8SnobDJ2QnM+Uyyit9HVtvxMSBvKPRGfglxafKvVmmbd+IZlEd+vGAloLbUo
         wRuSV9GlYJLYHUHeIvDXxTSUgwiNYbgKnpSHABcwlnhketMPWh30eYtIJ3BG2jnwexH9
         k5ZQNOwoL65IGP/6fxRQlip5mmPsyzAy8FG73ao8gBpIecbyAkaQdoo+kSU/Y808DCEy
         JUYhtANgcQ/Ex2EyHbiHaDwu+MpDBODNGeZwe1vCqpG83OSevo2H5BrEFiHQQzBdZZet
         UOrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=NZ9NhCNssNEj8jHwgbBdhsDJ/+YeWKw4bYC90Z9LVjk=;
        b=FQHld2i7ivmZG9mwawFCVC4B9xiKr++mUIN+xYmHHaEhDZbU7eH9+Nb/u9LtogvfrO
         EwlIm5PMizjW1N0hVx7E7lLq6p9XBplflX+xmSKE6/zQDZlh8XlAUNE1xR1LT6k+H03q
         m0Ykw/0v+z0aC+TORO+UGOJwLCwQMsGsDy1d3k1QziWAutYji5YepjhONpnnEwfiWk4W
         IZM82cZLEYkkdc13BhCOgYU2q+xthESGVpOBxE/KHDz+PI5pFQlI0uw+zMQ/2QW+PpzT
         XttK1UqLsVR1e6DPEe5oxs+YcXexm5mbLr6BbdnCYLYZmFlYxyVy9pxb4qqyuCMr5tFf
         Nb7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=nR+3dsVK;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id t9-20020a170902e84900b00178112d1196si2083154plg.4.2023.01.02.23.56.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 02 Jan 2023 23:56:23 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: aa2a2e6b3e0e4000b97ef770b4a1a713-20230103
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.16,REQID:6b61d3a4-de50-4fd9-9abd-1247832a57ff,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:09771b1,CLOUDID:9bb5a3f4-ff42-4fb0-b929-626456a83c14,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0
X-CID-BVR: 0
X-UUID: aa2a2e6b3e0e4000b97ef770b4a1a713-20230103
Received: from mtkmbs13n2.mediatek.inc [(172.21.101.108)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 500920781; Tue, 03 Jan 2023 15:56:19 +0800
Received: from mtkmbs11n2.mediatek.inc (172.21.101.187) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.792.3;
 Tue, 3 Jan 2023 15:56:18 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by
 mtkmbs11n2.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.792.15 via Frontend Transport; Tue, 3 Jan 2023 15:56:18 +0800
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
Subject: [PATCH] kasan: infer the requested size by scanning shadow memory
Date: Tue, 3 Jan 2023 15:55:58 +0800
Message-ID: <20230103075603.12294-1-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=nR+3dsVK;       spf=pass
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

This patch will fix the confusing generic kasan report like below. [1]
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

After this patch, report will show "cache kmalloc-192 of size 184".

Link: https://bugzilla.kernel.org/show_bug.cgi?id=216457 [1]

Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
---
 mm/kasan/kasan.h          |  5 +++++
 mm/kasan/report.c         |  3 ++-
 mm/kasan/report_generic.c | 18 ++++++++++++++++++
 3 files changed, 25 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 32413f22aa82..7bb627d21580 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -340,8 +340,13 @@ static inline void kasan_print_address_stack_frame(const void *addr) { }
 
 #ifdef CONFIG_KASAN_GENERIC
 void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object);
+int kasan_get_alloc_size(void *object_addr, struct kmem_cache *cache);
 #else
 static inline void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object) { }
+static inline int kasan_get_alloc_size(void *object_addr, struct kmem_cache *cache)
+{
+	return cache->object_size;
+}
 #endif
 
 bool kasan_report(unsigned long addr, size_t size,
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 1d02757e90a3..6de454bb2cad 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -236,12 +236,13 @@ static void describe_object_addr(const void *addr, struct kmem_cache *cache,
 {
 	unsigned long access_addr = (unsigned long)addr;
 	unsigned long object_addr = (unsigned long)object;
+	int real_size = kasan_get_alloc_size((void *)object_addr, cache);
 	const char *rel_type;
 	int rel_bytes;
 
 	pr_err("The buggy address belongs to the object at %px\n"
 	       " which belongs to the cache %s of size %d\n",
-		object, cache->name, cache->object_size);
+		object, cache->name, real_size);
 
 	if (access_addr < object_addr) {
 		rel_type = "to the left";
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 043c94b04605..01b38e459352 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -43,6 +43,24 @@ void *kasan_find_first_bad_addr(void *addr, size_t size)
 	return p;
 }
 
+int kasan_get_alloc_size(void *addr, struct kmem_cache *cache)
+{
+	int size = 0;
+	u8 *shadow = (u8 *)kasan_mem_to_shadow(addr);
+
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
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230103075603.12294-1-Kuan-Ying.Lee%40mediatek.com.

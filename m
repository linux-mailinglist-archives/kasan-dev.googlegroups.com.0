Return-Path: <kasan-dev+bncBAABB7N5XXVQKGQEYEFMNAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7797DA7C04
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2019 08:51:43 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id i2sf15977901pfe.1
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2019 23:51:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567579901; cv=pass;
        d=google.com; s=arc-20160816;
        b=CU8Je5QmqYPmvFWGqzT1BlP8kwiWOjIhWQFbIbpW69UwJYB6qloNaJlwlbM+aDePfx
         VVEEFoVUvNdpOBhyfH9ksb+i0m6TUiimKLdSfLLvv6AFyQp1kSl1p0EqlYQNW5yB3omp
         msqEAsmlzkldRUJ4C4yMk0C30yUg5taZ+s0JruY9dyr5/rHTb/s0G2DanqV/XVMCombV
         mllZPlM5VG8t/fANyYyJm9uBp1cYpCrjLbM1TqhwfufISf1IaBfIahwgsOWcR5/uwidX
         w8/GCAUFOaXhzMhuycfQrql5zpgINC/NfUbZCF80ZMAgie2LfOc84PWAFijomLYZsHrf
         J0dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=bIONd5JVK9AI4bX8HuqxByaqrGwBPihJHnr4MagUB1A=;
        b=lo82MydcUhBSast7H/XvhWV1Cl116ggsqEmTXTl19sYMqdiHlhNCPMYTQQOhMl54ZO
         JzDOQtODZfU66z9Jx1wGPxiWCWb4HjZlPf0vdqsNMoGDT65BR0lEVdVZzqZUXGtkO2d6
         LyHb9TL2bl4HxRYP214y6gWHjT5OGvhMi3D9fyIZWkyfqH6rWgqV5TybWzoGbzL5IMM0
         i+JH8zDnU0ZkjQ8IXEfTYcRohdXx3j5c7tfE2OLyE4u3JdmUerOFtm6PVOyF3UBwxneR
         l2c1pC9iLr155uZ1K1OfHaJoKKMUfiwPR7n7XocX/aniAQeeKsOyQYgvRrjHqnpKQ8+S
         EdFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bIONd5JVK9AI4bX8HuqxByaqrGwBPihJHnr4MagUB1A=;
        b=XjxA2PgrBVtrcL7cbHTZnKgu8U2/0DddkMi81Rkp3Lx25CMpJxVl2l3P8pr//TcV08
         Z0jlcM5ZUjSgw1FAPNp3zl8CF0s4XK4tTdZlpRgtcUoLFxOJvghAs0dVJL5Y+Z31uNHu
         dacscNBF4FZyVYwI/DguaKicv40aZ5NQ5ZimP1+hHtSDM19l5zNEBROHMQNjz9UUiOEG
         0z0W0Md8iPVRdI372X4lqgtUu/yR751cAs44zSWQKZw5zl+tZXJicdOw0RF8IQV/8Eep
         GwDVlVWl6OX+kmHHQcjqcvVHYaq8YurGyJoGi1zSCukWR5n8D1Za2ct8bbjzNqvo4GoB
         Emkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bIONd5JVK9AI4bX8HuqxByaqrGwBPihJHnr4MagUB1A=;
        b=KsoYrZDlHSnHAuL1HGkR0I8jOQEXLghOEmRTdD40bDeDHyRbAnn0yoyhtEFayd9OnN
         DI/zB3GOtCtlZeC6wKv8WmkIdfZqTITHIB/IZr1RohYDqOqS7P+WUqEmPOEWEmxnONN8
         o/S42VUzeui9ZpA1lVc2mhPnM9XkgmfSyHu9rKVMabeqBmDcFE0EBQpvyc9OXpHoC+6y
         +xmvAft63HTcasoLjW5YD4rMgOb5FAa4+gL0A6uz9z4MHakWnWvKLj+g8nq/4ZixxZc3
         tCRMraKecDlRyW5aJOXUfhTOQINz1xwSsPioHSq6kx58Bj+Nk6y6y+mDkSftb8SrlB3e
         s43A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWypZnza5SAJHTakZ4NeO8cU7fYxEXhFJgZVH6VC5K0itDtgvIy
	4suZQBso28sghzQx3LoKY/M=
X-Google-Smtp-Source: APXvYqzurWftYDIsP17UsxA9s2uR+fGnmX4Ujkqpe4vez4lkWwaChLU91X10iXlJ8SUzOCgYRw5lRQ==
X-Received: by 2002:a17:90a:d0c6:: with SMTP id y6mr3357480pjw.80.1567579901840;
        Tue, 03 Sep 2019 23:51:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:76d1:: with SMTP id r200ls5241390pfc.3.gmail; Tue, 03
 Sep 2019 23:51:41 -0700 (PDT)
X-Received: by 2002:aa7:9591:: with SMTP id z17mr44988662pfj.215.1567579901617;
        Tue, 03 Sep 2019 23:51:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567579901; cv=none;
        d=google.com; s=arc-20160816;
        b=in6wXPd6EpJjXebFAgJGERcznONERtKxwNk87IyyHYUM3oHEfJdkgrfJ9hZ1ooN/2s
         utQlcVG/hxXxZEKnluZoEMwZw58NNdLyxNJk+kcFgGKGUB9VA2QjKamftxK9mmneBXpM
         iIcCkVHH5S9c15IDR1zQJq/mTCBoRdFsJ6yGqqLR6apbQSP7HR2FM+Q+6Ux2wyVDaHdi
         LY1jr1e+UbQKKqIKNa1P8Nvs7RCJOeQjU1O99JnOv2gzuH2JZeZSgMWUhEe6PpFocjPV
         k2CBNIYcfJJ61OGBoZNGgSMHayAApVuarhiWtio1taHe6lhxNS+CL/hlyW84jGPBMWyl
         iSLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=mCrWLrvxNNwo0KPUL54vUucBEotR+pBRYrc2zuw/3wM=;
        b=PTut0DgoPArBLxLeYkIyv2YIe0DlaOtnw4uh58rqgH+xz6aPoIpsgemOX82mfv0zwh
         wqroR2uuF/HsoJ3SY+Sr7qdS/ihlS50M4UwdwJw2ZZPcItMQ8tqsDpEI006MnDV5DunC
         0SlO4f25pjjSNoDlNgB+99Uz+j/L8+CF5SirMk715nHDdXU4iUu6ey+udOYwfy6d/78v
         Ol4zV4xVpKhEqaocY/r5zQZ+OymNJo/UDrWZ6j8pQHR3/4mRuEkt5X7y9jn3IjCkag06
         xOqBTkwhDFKLevJhyj1iUeS3zujq84wuMIXVDq5OgtzQUvPIKuvHBwBS25T1KLUUwm9Q
         Sqfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id f125si1067103pgc.4.2019.09.03.23.51.41
        for <kasan-dev@googlegroups.com>;
        Tue, 03 Sep 2019 23:51:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: d6949eddd6d848458f0e91f382beab44-20190904
X-UUID: d6949eddd6d848458f0e91f382beab44-20190904
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 4046662; Wed, 04 Sep 2019 14:51:38 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Wed, 4 Sep 2019 14:51:35 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Wed, 4 Sep 2019 14:51:35 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, Martin
 Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH 1/2] mm/kasan: dump alloc/free stack for page allocator
Date: Wed, 4 Sep 2019 14:51:33 +0800
Message-ID: <20190904065133.20268-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: E693BB34C42D4B73B3B2B12EEB54C8F30BF059021EA46B52BEF177F393CF9F522000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

This patch is KASAN report adds the alloc/free stacks for page allocator
in order to help programmer to see memory corruption caused by page.

By default, KASAN doesn't record alloc/free stack for page allocator.
It is difficult to fix up page use-after-free issue.

This feature depends on page owner to record the last stack of pages.
It is very helpful for solving the page use-after-free or out-of-bound.

KASAN report will show the last stack of page, it may be:
a) If page is in-use state, then it prints alloc stack.
   It is useful to fix up page out-of-bound issue.

BUG: KASAN: slab-out-of-bounds in kmalloc_pagealloc_oob_right+0x88/0x90
Write of size 1 at addr ffffffc0d64ea00a by task cat/115
...
Allocation stack of page:
 prep_new_page+0x1a0/0x1d8
 get_page_from_freelist+0xd78/0x2748
 __alloc_pages_nodemask+0x1d4/0x1978
 kmalloc_order+0x28/0x58
 kmalloc_order_trace+0x28/0xe0
 kmalloc_pagealloc_oob_right+0x2c/0x90

b) If page is freed state, then it prints free stack.
   It is useful to fix up page use-after-free issue.

BUG: KASAN: use-after-free in kmalloc_pagealloc_uaf+0x70/0x80
Write of size 1 at addr ffffffc0d651c000 by task cat/115
...
Free stack of page:
 kasan_free_pages+0x68/0x70
 __free_pages_ok+0x3c0/0x1328
 __free_pages+0x50/0x78
 kfree+0x1c4/0x250
 kmalloc_pagealloc_uaf+0x38/0x80


This has been discussed, please refer below link.
https://bugzilla.kernel.org/show_bug.cgi?id=203967

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
---
 lib/Kconfig.kasan | 9 +++++++++
 mm/kasan/common.c | 6 ++++++
 2 files changed, 15 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 4fafba1a923b..ba17f706b5f8 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -135,6 +135,15 @@ config KASAN_S390_4_LEVEL_PAGING
 	  to 3TB of RAM with KASan enabled). This options allows to force
 	  4-level paging instead.
 
+config KASAN_DUMP_PAGE
+	bool "Dump the page last stack information"
+	depends on KASAN && PAGE_OWNER
+	help
+	  By default, KASAN doesn't record alloc/free stack for page allocator.
+	  It is difficult to fix up page use-after-free issue.
+	  This feature depends on page owner to record the last stack of page.
+	  It is very helpful for solving the page use-after-free or out-of-bound.
+
 config TEST_KASAN
 	tristate "Module for testing KASAN for bug detection"
 	depends on m && KASAN
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2277b82902d8..2a32474efa74 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -35,6 +35,7 @@
 #include <linux/vmalloc.h>
 #include <linux/bug.h>
 #include <linux/uaccess.h>
+#include <linux/page_owner.h>
 
 #include "kasan.h"
 #include "../slab.h"
@@ -227,6 +228,11 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
 
 void kasan_free_pages(struct page *page, unsigned int order)
 {
+#ifdef CONFIG_KASAN_DUMP_PAGE
+	gfp_t gfp_flags = GFP_KERNEL;
+
+	set_page_owner(page, order, gfp_flags);
+#endif
 	if (likely(!PageHighMem(page)))
 		kasan_poison_shadow(page_address(page),
 				PAGE_SIZE << order,
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190904065133.20268-1-walter-zh.wu%40mediatek.com.

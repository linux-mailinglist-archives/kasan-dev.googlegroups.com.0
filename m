Return-Path: <kasan-dev+bncBAABBTPA4PVQKGQEDPDQUBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id E0218AFD4A
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2019 15:02:06 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id c2sf12604105otn.8
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2019 06:02:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568206925; cv=pass;
        d=google.com; s=arc-20160816;
        b=YrpCs9/l4fNGEaKDbyK5p9Jm3PRgryssWag0xee8qp3dBrWezXgSgnEru7BV1OfQIX
         vD8GVJUrvAN7kSQIWaIrm9b5vYmIOtQd/k6HCYZ5EpxmoYWgfXgJHwUXr2Gm+wAfuXDZ
         uXMPcmPctkqfKx6Ibqhg/COpuNXRxMmTlyQG4FDjf6kGZDO1Qbu5r7R3SJdq4KGgEwhW
         ZT0o9iGadOoRfBil0gmgUY0VmPoz1MV9IGlpjldO6taYqEGJUVLJh22F8yzEBxkM1yoQ
         249jXKcC3LH1kfr6B/D1VunQpwCzJ1TldkujfAeuGR6M2yXDT0akrzXACSxcvVmwgEdt
         lS9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=f+nXK8/PY2eTq72GBYs0KanqrcxI0iId2H0CaUWMYhQ=;
        b=UHsuuy293BDoEwNsZCxw4haNUxOPO9eYfCosHxYSuabH4t/RjCaS52381mPp+hXbTP
         7m/suxqjvGaqe8Ljt997Q9vBFOOy95pzKU1yZ3qgNKdr4jpN0bBdz0xl9tt36FdRTfjz
         nVA06dumuCLO+UvlyP9IrVGlY2ZUNdmT+1NjPCSqn0sKOh5wNm7nGHOC7DSn4w1BSGlP
         fSQ34bFx9W1m/y8+jDPFDUiwT1NVwztO35qhgIMhmXj0h5awpCbLSnImwpROHSmjmQtb
         Csg1htExq4tigGEb8B+DGv8EGq71FbCe47YCxzM8ZyWVbWjvJbgFOaw8jx+YQa6gken8
         +AaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f+nXK8/PY2eTq72GBYs0KanqrcxI0iId2H0CaUWMYhQ=;
        b=U3EH3eM22daD9rpFSSB3yU4u7Dy669+R4BLc8SVK4eK/+YF/IC/xGENX95ybuRcPTe
         SMyt89C6QVj3uyUl2mzABjghtqvHcXWRufxeMbCUtQCWD2oEcGNZLdiRyV7IRheoxYrf
         G8hUPA5WFiCZKmySwmDdVnByDeG5lHCnWjVM/vQvFvpT9x3U/MQEG1DtIZRQ91eUgYUV
         /bTcr+eJ79/rmyzmK3GWzkAf7QUPjjdmojMDkCy8T11JSDaxHuGs8Le/fA9SgA/aSdAL
         SkEw40W5JIOECv/xbEf0b54TdWy4ShlMtZhILNRSLF3BpBy56uc+AGYgcaeoZPXCfRRg
         qMVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=f+nXK8/PY2eTq72GBYs0KanqrcxI0iId2H0CaUWMYhQ=;
        b=ikyp5wmVPD5Su/II+9HYewjxeYgBg/noorftOCRU1hkEjoX58vwkP23nPx07c6UkFc
         yXQ+PnRojSpCqQAiRKlhqSHi8FAW9aHRRGKMHGcRmHqWnznbHoqu9mS6E7HD7K2NTLbK
         BRfhSspVcoFrPoAXdmxDRyNSJhQMcsinJv3EnmoafsDE1ItBZfZDC269GIc2PXiVe4Uz
         eT76K/Nv7nwGEPrdZ4vEZjEO7jyTEqPNRB3SWRriVaRkpuAuA8HQAQxk8yS8mvfL0e4N
         mjzwS6Lru0hx8w0wFPwKNGqtRnfXxu87onteSZ4Fus+MH401irzAySPS4o4OzlJcpMKC
         aiYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX/0yz74O3RNw3xFED3LwqLdqP+sz9auKZPD3QQExPdDwOCzUIQ
	jcbyB4b8KYpZiRXst2l+UXw=
X-Google-Smtp-Source: APXvYqwP4vwu7GlXWOv4g++7GAn4sAqEPWENrzepC2tDbI8gKDxkdZBSDnhqw5SI1pkYGLQSVX9tEg==
X-Received: by 2002:a9d:7389:: with SMTP id j9mr6363285otk.269.1568206925447;
        Wed, 11 Sep 2019 06:02:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:481:: with SMTP id z1ls3088089oid.11.gmail; Wed, 11
 Sep 2019 06:02:05 -0700 (PDT)
X-Received: by 2002:aca:53c7:: with SMTP id h190mr3962660oib.35.1568206925060;
        Wed, 11 Sep 2019 06:02:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568206925; cv=none;
        d=google.com; s=arc-20160816;
        b=a+W0clkuNounr+EApvnlwPmaMjZ2uIj5O9hCcJQSfkvQYHJlo+uqFIa6f7jxxJSx6X
         XFpce2BWoej8lbLUcWJ0Jy5T39aSGKaCnOlj4K5h4VZXHZjuufUGe3QBQtsLwEsFU6oI
         dcZYaUAYMCaKekA8cDlY3dOUQCFZ8IB0VLZ7wjYE8YIOoNrONBWyavHDsDllsrdiswV0
         ZwoDNv1ashwuBGNHb6qG0G3051OHZ/9oOjwJIPGtdPWLJbYRnaty6WZO4fmNCqrFP9uY
         MahjBcwURDNtvEMpiyRm/vDdtmaVGDLFO0P5LU8xjYjaDWqYrSzr0NqITZCgmVvwQ+TZ
         3lPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=oIVbbJqRkDE/eNyd9GZNdppqWHsKj44BIopnURfqM0o=;
        b=JoB/E7IkU2NDeWCU8nmcEo2TvuGDjt3LxOhD1mwEPRZweuwqSLsIOY4GLR7i4m6Etm
         PkAucai7+OyvkxSZbYki2hkfthQy05LQY67rdvthhmcieKWM+3A6FhI/ciu/dH4M8C4t
         dKlnG5eb0/p1VFPsMqLvQ/A48THyl8K4/ZgKlSWZBf21PHRvCwkm1bpEsuInkGTFsbav
         cqD1+3GSl+lV9Rh8BS4c/kixE8/wRbEMl0shcrN3pcc39p+zDwGXdcJpiBo9WNLbTUF7
         h09aQBOX+Gxum+MJIadlSXzLY34hbOtKsE9A3je8lwOokPyVdNcNwGYB3zxxZihwIclo
         GzEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id p20si989638oip.5.2019.09.11.06.02.04
        for <kasan-dev@googlegroups.com>;
        Wed, 11 Sep 2019 06:02:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: e7bb7d6d9123418ab85de4128f4f1d7a-20190911
X-UUID: e7bb7d6d9123418ab85de4128f4f1d7a-20190911
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1948053234; Wed, 11 Sep 2019 21:02:00 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Wed, 11 Sep 2019 21:01:58 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Wed, 11 Sep 2019 21:01:58 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, Martin
 Schwidefsky <schwidefsky@de.ibm.com>, Andrey Konovalov
	<andreyknvl@google.com>, Qian Cai <cai@lca.pw>, Vlastimil Babka
	<vbabka@suse.cz>, Arnd Bergmann <arnd@arndb.de>
CC: <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH v4] mm/kasan: dump alloc and free stack for page allocator
Date: Wed, 11 Sep 2019 21:01:56 +0800
Message-ID: <20190911130156.12628-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

This patch is KASAN's report adds the alloc/free stack for page allocator
in order to help programmer to see memory corruption caused by the page.

By default, KASAN doesn't record alloc or free stack for page allocator.
It is difficult to fix up the page use-after-free or double-free issue.

We add the following changing:
1) KASAN enable PAGE_OWNER by default to get the alloc stack of the page.
2) Add new feature option to get the free stack of the page.

The new feature KASAN_DUMP_PAGE depends on DEBUG_PAGEALLOC, it will help
to record free stack of the page, it is very helpful for solving the page
use-after-free or double-free issue.

When KASAN_DUMP_PAGE is enabled then KASAN's report will show the last
alloc and free stack of the page, it should be:

BUG: KASAN: use-after-free in kmalloc_pagealloc_uaf+0x70/0x80
Write of size 1 at addr ffffffc0d60e4000 by task cat/115
...
 prep_new_page+0x1c8/0x218
 get_page_from_freelist+0x1ba0/0x28d0
 __alloc_pages_nodemask+0x1d4/0x1978
 kmalloc_order+0x28/0x58
 kmalloc_order_trace+0x28/0xe0
 kmalloc_pagealloc_uaf+0x2c/0x80
page last free stack trace:
 __free_pages_ok+0x116c/0x1630
 __free_pages+0x50/0x78
 kfree+0x1c4/0x250
 kmalloc_pagealloc_uaf+0x38/0x80

Changes since v1:
- slim page_owner and move it into kasan
- enable the feature by default

Changes since v2:
- enable PAGE_OWNER by default
- use DEBUG_PAGEALLOC to get page information

Changes since v3:
- correct typo

cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
cc: Vlastimil Babka <vbabka@suse.cz>
cc: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
---
 lib/Kconfig.kasan | 15 +++++++++++++++
 1 file changed, 15 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 4fafba1a923b..a3683e952b10 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -41,6 +41,7 @@ config KASAN_GENERIC
 	select SLUB_DEBUG if SLUB
 	select CONSTRUCTORS
 	select STACKDEPOT
+	select PAGE_OWNER
 	help
 	  Enables generic KASAN mode.
 	  Supported in both GCC and Clang. With GCC it requires version 4.9.2
@@ -63,6 +64,7 @@ config KASAN_SW_TAGS
 	select SLUB_DEBUG if SLUB
 	select CONSTRUCTORS
 	select STACKDEPOT
+	select PAGE_OWNER
 	help
 	  Enables software tag-based KASAN mode.
 	  This mode requires Top Byte Ignore support by the CPU and therefore
@@ -135,6 +137,19 @@ config KASAN_S390_4_LEVEL_PAGING
 	  to 3TB of RAM with KASan enabled). This options allows to force
 	  4-level paging instead.
 
+config KASAN_DUMP_PAGE
+	bool "Dump the last allocation and freeing stack of the page"
+	depends on KASAN
+	select DEBUG_PAGEALLOC
+	help
+	  By default, KASAN enable PAGE_OWNER only to record alloc stack
+	  for page allocator. It is difficult to fix up page use-after-free
+	  or double-free issue.
+	  The feature depends on DEBUG_PAGEALLOC, it will extra record
+	  free stack of the page. It is very helpful for solving the page
+	  use-after-free or double-free issue.
+	  The feature will have a small memory overhead.
+
 config TEST_KASAN
 	tristate "Module for testing KASAN for bug detection"
 	depends on m && KASAN
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190911130156.12628-1-walter-zh.wu%40mediatek.com.

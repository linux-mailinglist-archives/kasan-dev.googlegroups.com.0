Return-Path: <kasan-dev+bncBAABBQ7F4LVQKGQE2CSL45I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id ACFBDAF81D
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2019 10:39:32 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id n8sf416795ioh.23
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2019 01:39:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568191171; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q3OsCdi6Zlhktyduxe0lfdWPjAYp3/jxAJnDj3xu3Gc0o2dj3BJeKzTDJ5ecLoihuN
         t2cAldgGy5llTGNZYfc42ebzVw+pvlBJo02/+Fbjjux8rCGWJalJr+8XH/Ue+hACvqsD
         nRPuDKK9eDCiJ+yYq6cusYMHCm3HsW5kdjXJ97WvBz2jv2H+JffrERSUdA404WGsYVbk
         UcmvxOj2Om1Jed3wy3WATCcqwnp8QX4lHFoGUct1pa5ybw7i354J1IkFyWw5J01CO3CZ
         gx4E8f80Rv2NKgP9dUvucNy9r5jUORkzLFOw5l7ta659EoJKiY4LCPePbt7cqG7rSLYm
         A4dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=XWnbpSVS+XyXwsGWN7EZSDSa8r8JIt8U73NoO+QURKM=;
        b=bUJM0kjwW4yj+YxnQ6mll97NrH2As0B1I9jO54nGYeJF6KV6gXcri9xNtQFA04lAOx
         CCAr7EcLqVenPFP0tGc5NelE5Yqgmt4cp5Q/vyw/6DL4psy4Vb1UJYKLd4TkMR5mKvXn
         AOSoolhO7SZolq6EFQh1Y/yZ2NDPVPcRlUilxzfl1Who8zC5ubS3gv1cI3a/XawD12GL
         uPkAOlGD6mXQQOvU6nT6S/+redkhWoSLDF0zrkE7oIaJgBt+SURdb+OFoZX+aY/y4TmX
         o/WKYlZN0oBs2HxwhCD9flxqX7a9J6ZHiX5zSLoNhrMVmmGEoGTO5yag8Hhk2pQGvr64
         5ytA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XWnbpSVS+XyXwsGWN7EZSDSa8r8JIt8U73NoO+QURKM=;
        b=RdXt7bmE+XiJqxNJ/D0lzPdYgAah6sBnZ3E96HjUYp8WqXcCK2gwOPgXJIxUZDc7H0
         vOIE7rMfedwmrKb6sVbQ2m1IVRAqp9g9s9Pzc27nlNvBmtXI3n+L86xvkSxnxd770EmE
         kQa2IPtMUBb0MB96OQneEBvR0jWPwfpZvmhUJ19ugB2X/Wlp+aNCbSbJhbO7BhHYLlPM
         JQqUemWHOa/zzSGy7mwI1zMNVR4lR+o6I6zm3L/GRBi/0EuNfy3IzggGoFe1IWfB+u3s
         eyD+viRoh5GGyZReTKm2UmXVgsba/OYw+TYaQWoBYd7FF1IUMhBz0fdXMDjvMMhRxXmx
         cL4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XWnbpSVS+XyXwsGWN7EZSDSa8r8JIt8U73NoO+QURKM=;
        b=dwPypdK909VLfYcQXe2XB6wVeIZh3IM8fXwJVtfJMhKgT2xehf7eS2w5NWg93Vmtha
         ao8LkEDcPqaRQGR1lTI9X2EvQlF3pOonwj44/LoJlg/9/m8QThDWOFGyVy7xCmxjlZ6w
         OzPaYPcb/sxl3E/14Kncnn+8RmIcCyfWQYRAuNCi+JoSGO+QD0+cimdtFP6KtzQvhZpS
         wpfoVy/3+PzjD9S/SEwZZd8G67m7ucqStbRhW3v6ouFBguhX7YK9JakkxZvXFT2q83+f
         ciTQNxM4Md17nX6nQcyX5vIkHwDyreZq8Gitg196vlntajdVu+qw4oTzEi+gW2ZcWphU
         TIPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUDjHcrC+JXddYIntFtR9NOrhvpet19xQDj/KFWI1KRnjxKPnFi
	wWHW1OmdXgFJ++aqBDH+O/E=
X-Google-Smtp-Source: APXvYqy0J0hA7TNkj311rdxDSvaXycOjSE29UR95jKkHuen2Zojxx8LoAWvfiYQQfb8JDInmEtKJZg==
X-Received: by 2002:a5e:8407:: with SMTP id h7mr1991082ioj.47.1568191171377;
        Wed, 11 Sep 2019 01:39:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:f211:: with SMTP id q17ls2779929ioh.1.gmail; Wed, 11 Sep
 2019 01:39:31 -0700 (PDT)
X-Received: by 2002:a5d:80c8:: with SMTP id h8mr3656107ior.188.1568191171113;
        Wed, 11 Sep 2019 01:39:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568191171; cv=none;
        d=google.com; s=arc-20160816;
        b=RcowN/aCpCpuFg1+jSEs14LoLGVv5da3L+U13oa/EALzPYUVFoU9/wDg49V3e4PLme
         qEi0sEEcnudFkETgo5cG7+uK1AjcFHnE0r5xO0uwncb/yv1xk6pFbxFlno2Xzcumicwa
         S1PKHQSXtQIGI2XWgu4F9zDA9Mnk2AM5yGEx9TRsBAUAKp1u+zpH2AFMwl1XIN5rmTG2
         HjsaNPHWxflwUxXoTJJ6E53P8V76jnc6Knwp6ZhvaRVkst1GmTFFvOs3uYd0yMbbKrL7
         xW8UPD83V9dreIxKM3bKhFSYXVrsbeIF1rfYtCIxY8Gq3QGry7X/pU8Cc2ZBE6j4pdhf
         6OhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=oEwgkR/PRrG/9+OW9dqUCnzX4SQ2QJ3BYTaiDaZVP9M=;
        b=QtLmFtgRbgYBCXTLygIGaWvwQNRroKqSzR/d8I68aBdGYBHW6hTuPOK1ylV9/2pytE
         9stSRUXwGdzmHgTy8ZwI0aHfL5eI4jmsSDKF8/MtHQ2fosaW7MQkOqRlXUaFjqNhSp+O
         fFTHaIcTic+vw1KhRNLz1zjs59fF22kUYJ38DRSauJbLQyw5CSQandqywacBys08RJQW
         bEn71BJPehTOdSgbwCmtzrrYjVJ4rzSbQzoCXC+FjVy7nqHojDgN+BdmGOkeb3ZYAPPw
         cVal3SQDD3UEKl2U6o4i2foayFB3LUS8CQrSiGF4oq3cLU6TztEdEet2oOj3uLYMqVik
         n4Aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id b5si997587iob.4.2019.09.11.01.39.30
        for <kasan-dev@googlegroups.com>;
        Wed, 11 Sep 2019 01:39:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 1da5aa5210c14e98850fc278477b392b-20190911
X-UUID: 1da5aa5210c14e98850fc278477b392b-20190911
Received: from mtkcas09.mediatek.inc [(172.21.101.178)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1427945322; Wed, 11 Sep 2019 16:39:24 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Wed, 11 Sep 2019 16:39:23 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Wed, 11 Sep 2019 16:39:23 +0800
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
Subject: [PATCH v3] mm/kasan: dump alloc and free stack for page allocator
Date: Wed, 11 Sep 2019 16:39:21 +0800
Message-ID: <20190911083921.4158-1-walter-zh.wu@mediatek.com>
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

cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
cc: Vlastimil Babka <vbabka@suse.cz>
cc: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
---
 lib/Kconfig.kasan | 15 +++++++++++++++
 1 file changed, 15 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 4fafba1a923b..4d59458c0c5a 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -41,6 +41,7 @@ config KASAN_GENERIC
 	select SLUB_DEBUG if SLUB
 	select CONSTRUCTORS
 	select STACKDEPOT
+	select PAGER_OWNER
 	help
 	  Enables generic KASAN mode.
 	  Supported in both GCC and Clang. With GCC it requires version 4.9.2
@@ -63,6 +64,7 @@ config KASAN_SW_TAGS
 	select SLUB_DEBUG if SLUB
 	select CONSTRUCTORS
 	select STACKDEPOT
+	select PAGER_OWNER
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
+	  This feature depends on DEBUG_PAGEALLOC, it will extra record
+	  free stack of page. It is very helpful for solving the page
+	  use-after-free or double-free issue.
+	  This option will have a small memory overhead.
+
 config TEST_KASAN
 	tristate "Module for testing KASAN for bug detection"
 	depends on m && KASAN
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190911083921.4158-1-walter-zh.wu%40mediatek.com.

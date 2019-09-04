Return-Path: <kasan-dev+bncBAABBZOAXXVQKGQE3RIUKWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 13983A7C1F
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2019 08:57:43 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id n9sf12591450pgq.4
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2019 23:57:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567580261; cv=pass;
        d=google.com; s=arc-20160816;
        b=HF1+79kafER6ug/xnlKUZwXBYZNpGZ/p1OTbwGCCu8f5ua+JcRWnKugcrtAWCKKTuW
         0QgRNUuqkQd5CXhDx3K3xvJZt36gwpP58ZK74WxLKaty4hgFo10hBLpACRf0mKOvdWb1
         d+eWSFuB1VvlKqHX2t0KUhePa1MB64wya8NprHYZKEVJGPYfqHDfCGggSzDh8qycSMVI
         Zn0E9n5hNZqtPzeOssG4gcCARetfptSwB0MZRrgUJSWijQBT6K4Yu91wjMfiv0EjhHkK
         8u7Ra6w7m76PB7Zu+5EvLD7gjGCmO+uKas4H6hoX9ZBzewYnYA2qzsaJccKMgQXazHno
         QrfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ntQpJSGdwrkJ+L3r6HjyGr9Tww/9CcwH9yfOQ6ub018=;
        b=p5359mfDOu7OIzv/U8/SbZeCb1AyxVB0k9kcXBx07JgnNJ8GojDbdbD4sSjsnCpI/8
         ks+VE2Wup+pnyR9hRuRGQ6+Cg0p+26HlWCmKKI/EfRa+YjQQIBwCK7wiv/i49ME7ZJFY
         wwv0Ck4SDmUv2pFYP2tiDcOye/OlT3bh/scj1CYqVOlOiHQfKZxA839o5tnVBgVblL0A
         4TqZBCSheLiG0EaUTZ6I1TS1+q5962Av1B2bOFPpnl8WyOZPGP36qh1YhfhH46FyTFC3
         vBvAiGfift8TXdojpvSqT+ADaI8CDxRkzXtSP53vKnUixk1ojGl8f5B+YyS2YwHdq6dm
         81+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ntQpJSGdwrkJ+L3r6HjyGr9Tww/9CcwH9yfOQ6ub018=;
        b=Ykmmht/BhDKmLqXHwj48kBwsLQDfN/DyBI90Vwl2EUacO2c4ED0OlKMr9NAvHBpVKp
         cy6B76t+ybsyehc1eGZI9fuTL6DA5NFZKDrGS7a1dr0Zg52/HRfo1xN0U9Ol/elIxNuU
         fMjvmPwgxogD9D2Ort5GQO6+uM8TadjWrgMZMk/9Mq8EWuksz0e+HkQ3ykmY+wa/CQWp
         Tvcq03+fkADyM4TntF8rK+xAK0cqEhQhlRwfr97NublHzMxuEQWKLhC/l08t5XFJK1tS
         dW2+HbglzdnLeX/O3czw/q9etiboXBi4ETfDVhJMuqBTsLZ73HkCuNckPug5hMhX3x6m
         YHYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ntQpJSGdwrkJ+L3r6HjyGr9Tww/9CcwH9yfOQ6ub018=;
        b=KfZ2I0FidhrezFcncCmwNo/Lt1N+9XwMvZ2cP3HWqfQ9aKSSJ652nFexO32Pp0MLuw
         s3hT/63MWf/TbyQwyDqpcI+tpv3Urw/qZchKdkYmEa5DZQRhalUr/8J+MfhjTOSJo+3+
         mi8wDs9YojUZb/zbMUWDXLzlmDihiBh2V8vvSvP2UQ53Y78YS1drbquQDdvYLF9qsPPi
         4YTS1SiCFtERzc7wIYXA1nUpSLOwBkVAeuK8XbSwzkBViy4Q9pUjNER5lqfuBuOI2zrS
         RJz352702uUBG55Pq4gzyysZ584FSV4rHY62VVLE610kgtWlmjQ7svntqZbM/lecOKiv
         fAjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXoh1NhWa7unR5zSI1Yv0Ykn64cCwIBgf6LzP3xrDPrpTRXtZaL
	6w3OAtEm8j0og+LcxkLcvCU=
X-Google-Smtp-Source: APXvYqz9jeNl3cxNJ056mo0PFXFlTLCezBd7fW3ZdSuk8CwaGuEwKmAcRAkiZtKoNPgGzVKls7OlGA==
X-Received: by 2002:aa7:8481:: with SMTP id u1mr21436550pfn.3.1567580261812;
        Tue, 03 Sep 2019 23:57:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7b84:: with SMTP id w4ls6256363pll.10.gmail; Tue, 03
 Sep 2019 23:57:41 -0700 (PDT)
X-Received: by 2002:a17:902:9b8f:: with SMTP id y15mr41069475plp.194.1567580261607;
        Tue, 03 Sep 2019 23:57:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567580261; cv=none;
        d=google.com; s=arc-20160816;
        b=x1a1p2CcjQtn3P/ym8TtRiFEgCEkXxXxCgiU8ndKOaFNcQr/OlgnOI5xp73s1wY68z
         8F967HSgBvc5pY3gbZUt6b948CgEQa4wH96bPP5deAkMo3wA5gJ0nGkbIinCYwyhPR2S
         J9anZOfesmcdgEVGMiFNg7Q50MNiGy7gT5HltN9L5GGse6qMisPA3O1UWtPUMTP2m8Pw
         7PFLwOt56XxJGmvD1uekLB/7J2BMQDfbALWxF4RKcXipr/5lavDp+6UmsBCOLqeL7DFV
         uP0ew/brKuRfbgTJBZ2ymTd2aMOKi/lLpg5aTp4lZbHhKdoE5X24ioC71GZNZIs+5PZ8
         6svA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=tfv+2Du+NiK3fQwB26hEaviCGnYN7i8DA5Vx/xbsEbk=;
        b=o+yu+k4FaLb9XB2K/vZTjrcSTZhX2Me5NA3N52R/3chUgL5OgApCwT9dIee1IcHSrr
         Hr+TvfPaelUq4uFzsmyL6JjpUnFMgYLJlFGoPsqUFdofkYwniPU2d6HBwTYKvtW9q8e+
         YsWCraLjuMUinqgnXNucGerDEC2qdfr/cA3kNC0UkrYR74zRc+ivDgEspj06z8xGGTli
         rz0naLtWCAmuRhHkbdLC80hEHXXiWEP3Yz1A37GiIE6EzQChbDa3cVwBf1aScMHG8l3g
         ORJtEzo+KhsUdhGZP7iRfQ7vBxTXS+NU7HlPX5fXhISfoBLX+T64WzxdaH4NH4PgmKjF
         eIcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id 91si355156plf.0.2019.09.03.23.57.41
        for <kasan-dev@googlegroups.com>;
        Tue, 03 Sep 2019 23:57:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 0f275d29c86d4783ab7c06ab9ad722f7-20190904
X-UUID: 0f275d29c86d4783ab7c06ab9ad722f7-20190904
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 879257244; Wed, 04 Sep 2019 14:57:38 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs08n1.mediatek.inc (172.21.101.55) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Wed, 4 Sep 2019 14:57:36 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Wed, 4 Sep 2019 14:57:36 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, Thomas
 Gleixner <tglx@linutronix.de>, Michal Hocko <mhocko@suse.com>, Josh Poimboeuf
	<jpoimboe@redhat.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
CC: <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH 2/2] mm/page_owner: determine the last stack state of page with CONFIG_KASAN_DUMP_PAGE=y
Date: Wed, 4 Sep 2019 14:57:36 +0800
Message-ID: <20190904065736.20736-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
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

When enable CONFIG_KASAN_DUMP_PAGE, then page_owner will record last stack,
So we need to know the last stack is allocation or free state.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
---
 mm/page_owner.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/page_owner.c b/mm/page_owner.c
index addcbb2ae4e4..2756adca250e 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -418,6 +418,12 @@ void __dump_page_owner(struct page *page)
 	nr_entries = stack_depot_fetch(handle, &entries);
 	pr_alert("page allocated via order %u, migratetype %s, gfp_mask %#x(%pGg)\n",
 		 page_owner->order, migratetype_names[mt], gfp_mask, &gfp_mask);
+#ifdef CONFIG_KASAN_DUMP_PAGE
+	if ((unsigned long)page->flags & PAGE_FLAGS_CHECK_AT_PREP)
+		pr_info("Allocation stack of page:\n");
+	else
+		pr_info("Free stack of page:\n");
+#endif
 	stack_trace_print(entries, nr_entries, 0);
 
 	if (page_owner->last_migrate_reason != -1)
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190904065736.20736-1-walter-zh.wu%40mediatek.com.

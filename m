Return-Path: <kasan-dev+bncBDGPTM5BQUDRB5HASH5AKGQEXU47F4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DBDF250E74
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Aug 2020 03:59:18 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id b76sf2352115qkg.8
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 18:59:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598320757; cv=pass;
        d=google.com; s=arc-20160816;
        b=X8y8cizElGTd5kzLmind6CCkKTrjCFRDYuhetIeFQfluaiv1fP3vbkMNB83vUOrLNJ
         fWdwFge3RtkBqExufdiRwGWdlOuJfksQ9+8WIbeob/See+EojuWY/RwaQtTKFmXTiqSk
         dLbMJYNclDfH4b0Lfrux7JKG5y4aW+43wo0fEFaBzdU/zo8lm2fmJoVn9/VQwR5hjiyh
         OSHmKz7w5BT/g+N+hIzM/u7mLif5MYRew4OV2rS+Mm8eMSD5LoQE/ASfO9OfowAjcqst
         Hlgh/TvPb95UB+mZ5+w9/k7pRaqERQB2cBpbaRazSLl3hLdGXGD64dMgtN3PgF2B0mWw
         ZejA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=3Fs4bM4mUzPRz/Va81sRszsD/pHPJVuyz/1twywCq+Q=;
        b=irFGlCuQPQ0b8cNOpDFvvTPAlyTIETT7RuJl6AG5/65cOHuaK/BtV78q3U3oss0qTm
         tz2223XtnD7xSUWNY8AgIiHBdgaK/xVxo5Y625twMqPGfqKZw6O+0Y/p6luob6ISIPWn
         0XrVtc17pCY9SFHAdS/Jv8O02Y1kfpBeljSDYzIx/U+TcVMyPltXUFNOkIdVS0oLEaZa
         IBPOXtAGS8xItMdZkuhRYBJ6CVczr1ue1zry95s8x09nHAtNTUGjIOkE7A7rrSIfZ237
         RB9U5lrSv/HXaWPtrDvLOOllOxRgvtht33FzNgbvZqb7K15RNNqV2j/0leFNbLgXqNFT
         gTsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=CkY8+fD9;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3Fs4bM4mUzPRz/Va81sRszsD/pHPJVuyz/1twywCq+Q=;
        b=dBMcGmEwDpUdCyuz5jKDMk3cfbbcnYgRGZU5WfFQA0QmyHQulIjlXG+gQoXCzFwixj
         lCaIGAAUD6iHgaqwV60TJOcwVZu7xVzHMi9PzFoKzuzbcWz3UOFkM3jQThXeA+fIGw5P
         Nmm0dMFG1kj9mFy3MeXqaNssCiX0ObUTEJ1RA+SdA7i74rzy0nm3P/nPtq48fkiA/1Fq
         YZf+wEpms9d3dvRWICAIFxice/fcg7yZdT9QS9GrjqNf5LdVylxhNUBhymrHMmxx3Vv5
         jQda0UGmrpiF7nqEl4DZHE7byHzgd7UFZH/Dk1dw4k57oNhgKbMXYuWZ/X8DMQOFchLv
         Gfyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3Fs4bM4mUzPRz/Va81sRszsD/pHPJVuyz/1twywCq+Q=;
        b=HgGTTHUtfNRg4KGNUaClzJTlc/9QbWL2SiCRF4fx5cJcs+mvNULgi3/ZZgZFyF/cm7
         MdF7FB1KiS4ACJEl5lvAzGCLBkPtf/vg4xZ5X8/B4OoXoewkNReZd/NfdPLoOL6Rp+hK
         DYsSPJ+U40VS8civ4j8TW+qtVnzNqJ8/M0LEKtUlXhDBL3p4WCtFtk3rngdbkqnEbRh8
         Vmeg4jQ5ENXDTxxgCFMnQh20KBXLEvJF9yOEoUH7lIeqG2yU6tjnPcLWGCZgd/qEoL99
         OXTqOUAwLR30ud2p/tQUg+Tnqe+QE2QKpyA5SRmB2uW+5VbIHgVEzxzFXoMu0xyLQ+yn
         tZfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530k4AQwvF/gCTsfcO/uCVp8DyrWPi1UXXQx5TjR8LEndEoGrlZW
	dScO7IfkIIojEbQvDdDBEQg=
X-Google-Smtp-Source: ABdhPJzbsMryoXAQ86MMXv6uDax2pH6KkxRr4J00k19fLU+i68Yo5NByEDRrp+4/j9G88OD+GBUwjA==
X-Received: by 2002:a05:620a:2154:: with SMTP id m20mr7430202qkm.305.1598320756941;
        Mon, 24 Aug 2020 18:59:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:e409:: with SMTP id y9ls2759636qkf.11.gmail; Mon, 24 Aug
 2020 18:59:16 -0700 (PDT)
X-Received: by 2002:ae9:e301:: with SMTP id v1mr7166243qkf.344.1598320756574;
        Mon, 24 Aug 2020 18:59:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598320756; cv=none;
        d=google.com; s=arc-20160816;
        b=ptEJG+8D0WO00yo74gDt+py3isIzib9iecvk4uyw+kQ8JsWvUIT4ixgIgQ8ksbZWHu
         /La5+lzK5EeflVInvFe9pquDRz8t+olOTHdrIiZNBHmztAz0PCKro+lcovf0Og3X8Ait
         q9QYxgFcX30qT3KoU+I1s9ZCC9gJBYDDR/0vrN9UixDO3PNnb0DV+K3yrIQaP/MNJMtY
         jHPXHZ/7s15lDQR//w+HyWpzxPGqugYSxIF+Ic/lHvyRoU4cM7oZLbIo/M9C1o2dsdrU
         rBkG3lcX2nN0NXzNbxx0RYsXkRFTuCeGO05D4Ab7z3rWGWTm/K4zg1vS+5G+Jm1IAnhH
         i5tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=HDzXMXMz+Dzcg9DxfMTu2qwgwLYa3ujPve0aUqFM/KA=;
        b=t6Qh19p0ZxKW0wig7U3QtJvr5ANRzWBcWtCueBKDI76wXxSIhjbGkr1+G5kzpONM4Y
         HBzzTpUqC12DW8WVkTNiOmcyQAIQKuRksrbtKJEWwpio7zXXevK8aiGV+2kPhliaLsH+
         ZeFVrZAh9RqjqEYeILZPhAwBYfseSIzPDng2u+2H2+HubM/dXdTUpz3D5aI9+ZM60EBy
         zuAwfIczvWIOdHU7tKW7evuV/CdYFLYRzhfQ5G2tno7wvkUEvrdE02mWCrTeVz0QIc9i
         Z8lTFaKb2MZml5FGzLsynzTvcI0kNMOi5rrlIWp8TWoz1YXl1FNGWVsGzE2es7TWoked
         xWAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=CkY8+fD9;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id j6si55388qko.1.2020.08.24.18.59.14
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Aug 2020 18:59:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 21ea5009868a412fbc725ab180ae487e-20200825
X-UUID: 21ea5009868a412fbc725ab180ae487e-20200825
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1002895838; Tue, 25 Aug 2020 09:59:09 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 25 Aug 2020 09:59:03 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 25 Aug 2020 09:59:04 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Marco Elver <elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v3 3/6] kasan: print timer and workqueue stack
Date: Tue, 25 Aug 2020 09:59:02 +0800
Message-ID: <20200825015902.27951-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=CkY8+fD9;       spf=pass
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

The aux_stack[2] is reused to record the call_rcu() call stack,
timer init call stack, and enqueuing work call stacks. So that
we need to change the auxiliary stack title for common title,
print them in KASAN report.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
---

v2:
- Thanks for Marco suggestion.
- We modify aux stack title name in KASAN report
  in order to print call_rcu()/timer/workqueue stack.

---
 mm/kasan/report.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 4f49fa6cd1aa..886809d0a8dd 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -183,12 +183,12 @@ static void describe_object(struct kmem_cache *cache, void *object,
 
 #ifdef CONFIG_KASAN_GENERIC
 		if (alloc_info->aux_stack[0]) {
-			pr_err("Last call_rcu():\n");
+			pr_err("Last potentially related work creation:\n");
 			print_stack(alloc_info->aux_stack[0]);
 			pr_err("\n");
 		}
 		if (alloc_info->aux_stack[1]) {
-			pr_err("Second to last call_rcu():\n");
+			pr_err("Second to last potentially related work creation:\n");
 			print_stack(alloc_info->aux_stack[1]);
 			pr_err("\n");
 		}
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200825015902.27951-1-walter-zh.wu%40mediatek.com.

Return-Path: <kasan-dev+bncBDGPTM5BQUDRBCM2UH7AKGQELMWIW2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BCAF2CCC96
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 03:27:23 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id t8sf391932pfl.17
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Dec 2020 18:27:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606962442; cv=pass;
        d=google.com; s=arc-20160816;
        b=SyAikDGgMTwGmpFjDvdWcOwmEQ4CwIdWEU3mhv8OzHmEnwXstmCR/I/I1FFisiu/J/
         N7l7CmSNlEqPR6y1x5UbtSQPs6kxQB3a6KzhVaHU12VLxAuZSzj2ETzi/e1MQY668V1H
         ZDTQrwH9qR0pAZsesFG76NrucSdoTPl5nhd+txW1vnwfln+l1vgVdEmf8FjXCnWjQX/K
         eP1oVvgxGwZxMQcv5wxOlZhVta2ALB/mO751VQaRy3EEgbJm+kIuTiQ2COT+N1eh6QfG
         9z52oCCS+XDa+Je61KKBbnYRdPCxJcTXK5TGKq3oip4NcOb1oD1i0Yc21quPIW6Nv4j2
         VWFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=mIG1sEMnD3QGtn3pml40Ah3/cRzTm+sCUvdYnFMMFxE=;
        b=04ARjMqnzqEoMddaPqlJJTalkNU1wFq54E0wK3x0xtTxDYvFSsKV/05tFQ78TPweAZ
         wTpxtkknjar2tolzycWUKlTmEZuBxvTk1TV+/ygGx91PynhZ8WfmVpC/LSoKsb2BvpcF
         sVsnDilTa2L3CUutopMnyyo3Fp9g3CyuY7O9QEj3hH98EVoQo2IUP6exrda34yr9qpCE
         6AKBNTIF6orJLl92HKeAnuQJuiKUv7tu4Y/Pj3Bo7dlpcG+RWpRhDcOQcMW7iCx5nfuc
         HV2kigUKpCSfoaUFrGBCUK/qFdU8zGhIGIeBnh7GN3jpEpewfsG4SAqNcZYdOqOIC3RX
         D1HQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mIG1sEMnD3QGtn3pml40Ah3/cRzTm+sCUvdYnFMMFxE=;
        b=PZkNBZmSRRbf7FtqVzOvyOvP4GTGk/b5nNKPKqFH6Y3iOoKxl5x4QQ8U+EcHRy2izx
         tDwpmyBB8dre+DQjaLGpbN4o/uL8q162h6g9Cn8n5S3r3amQ48E7TpEdjmBmHwC+VYNx
         TKkttCGTStK62XxxS6wh29qZyGdlKkCSGfSFIL9nIAx9lKe7ugkHVTM/+mDzNc9rkhu0
         MOewE8XQ9ChTHVL+cEJ/Vv+amFtM0PXm7FouFTZFjOyLCsJGnewqeUMG8x47qHIeJB8J
         P32ScS1gaVeqoac5197NdieM40kJdXNQcIgYmp9oGCqoF0l586XxmI/qt+/gFrsjTfz1
         l3sQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mIG1sEMnD3QGtn3pml40Ah3/cRzTm+sCUvdYnFMMFxE=;
        b=tzvwOfnavrzKTowDWIrOT0LOEKZX+HApgxGe/AimsuP6O36RIgPn8rLeW1edYuJKlw
         ZASxO0VoIDxIqt/JijRNzA7FBLQtGAWx0/BhpK2jOPqi19mjcE+ygiC6BU0DVDVLpl+N
         mJHtHGiMEYUFxiROb56rfx6wra5z6h2gCELTPSOpbms6hcT5CPR3wgY/0UK4uuGc6sLj
         QiMJ2Oc6S+EgdcIWiN2yFzBQ0ekpLa4jgcSSDWmEJNtCriQ1SGEY+NsxIOxtculk2OgJ
         LyE78KTylhz/EtwLCCKDIkDpW5Jz60g66xnvyrf9bMP+gDR9vYzlWZvp0f4WGek5ARnt
         gsdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532POkrZmmsGIWGXIbVBqbMH+utvy46DWtSXxXAyvp3WeYGkm7Tw
	N8LwaowfnEcsvKnFnpiOK/w=
X-Google-Smtp-Source: ABdhPJwF6D0tBPzLcwLQpK+ZrFvg5GAParG4nDxBzNmN/pGfBVkDT65iGa5QECtW5DXF5SlZV9M2JA==
X-Received: by 2002:a17:902:123:b029:da:420e:aab0 with SMTP id 32-20020a1709020123b02900da420eaab0mr1033751plb.30.1606962442049;
        Wed, 02 Dec 2020 18:27:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b187:: with SMTP id s7ls1851559plr.3.gmail; Wed, 02
 Dec 2020 18:27:21 -0800 (PST)
X-Received: by 2002:a17:90b:f8f:: with SMTP id ft15mr934232pjb.210.1606962441466;
        Wed, 02 Dec 2020 18:27:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606962441; cv=none;
        d=google.com; s=arc-20160816;
        b=Sj0eW2+xxPjumFdgvghGMLbeKhJYFgiM++Uq3x+omXmrOoP1CWtcp3K5mht9cX5rMN
         lQKPtu2Kt/lzouqyV9ZJWZPxvA7ZUX/LUs9qiN44IsyPcd3xunq+2NaAL4+95GdofgRF
         ujJalhobrfBdFwjIPpdrDR5RKtybMVkCwMAWCnLQVb5ICsa8C/vgiR9eaku0XmccAjb6
         qaBIWXyHohji0x59YiWWijZ3k7juzqV+LzJ89Vzc4h5Coa+lG0z3VuleIFwp4tsxsIpE
         HEya4eRI1OOcYUbMWt8hbER/z+UlyssSqpH1t6OuIHnjpTiJLM/4/Nar2cZmExNL3PNh
         94Sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=171N5Uto2KYOtvQkhDqPBRN0l2zUStaD7xgAh1228Ag=;
        b=zqpyFqgywboPoxokuJAY5jO9HU4HuOES8xtUDUU7tb7ga/ddypQYRonWihOFJs6YZ6
         jb6RynT9/m3ONYYmPc9A27yymDsnLi+oXC080TjtOl2NCTrEyjHEzAhmIoBx5wx1ZKYb
         hqqTro7XaueDB9+9TlqR53kBWwy/hLKAREABWfG4vj6toaXo8GwD7JhWuiVdYD3Z8dwu
         B1B+xOrWuCxhShV4SWskOo1M8Rpvr+0WToRxpEvOKZd26OV6NPxItlUMVLMBuSlgLZc3
         PsAt8KM6rc7iwoWo0le2ynz6pyjsLZOWLeywDZjklnGJ8mtg5zVZpyipR7COX4yu++9n
         lh1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id z14si26641pjr.3.2020.12.02.18.27.21
        for <kasan-dev@googlegroups.com>;
        Wed, 02 Dec 2020 18:27:21 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 2e83c8b16f4848a2bcd0ffe203b07faa-20201203
X-UUID: 2e83c8b16f4848a2bcd0ffe203b07faa-20201203
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1392044509; Thu, 03 Dec 2020 10:27:18 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 3 Dec 2020 10:27:17 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 3 Dec 2020 10:27:16 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
	<andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v5 2/4] kasan: print workqueue stack
Date: Thu, 3 Dec 2020 10:27:15 +0800
Message-ID: <20201203022715.30635-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 02036FC500E99B99F6C523F3F2DFF607ACC4B5DC0C67FC4EA24112FB0A729D982000:8
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

The aux_stack[2] is reused to record the call_rcu() call stack
and enqueuing work call stacks. So that we need to change the
auxiliary stack title for common title, print them in KASAN report.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Acked-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
---

v4:
- remove a mention of call_rcu() at kasan_record_aux_stack()
  Thanks for Alexander reminder.

v2:
- Thanks for Marco suggestion.
- We modify aux stack title name in KASAN report
  in order to print call_rcu()/timer/workqueue stack.

---
 mm/kasan/generic.c | 3 ---
 mm/kasan/report.c  | 4 ++--
 2 files changed, 2 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 248264b9cb76..30c0a5038b5c 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -339,9 +339,6 @@ void kasan_record_aux_stack(void *addr)
 	object = nearest_obj(cache, page, addr);
 	alloc_info = get_alloc_info(cache, object);
 
-	/*
-	 * record the last two call_rcu() call stacks.
-	 */
 	alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
 	alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
 }
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 00a53f1355ae..5a0102f37171 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -185,12 +185,12 @@ static void describe_object(struct kmem_cache *cache, void *object,
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201203022715.30635-1-walter-zh.wu%40mediatek.com.

Return-Path: <kasan-dev+bncBDGPTM5BQUDRBANWWD5QKGQE7PUTZOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id AA4AA27677E
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 06:05:22 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id w17sf466420uaj.0
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Sep 2020 21:05:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600920321; cv=pass;
        d=google.com; s=arc-20160816;
        b=AIiSikjUZHUGuWVeqNytiklBDR8Oms08KtEVved1M3zwBQJkg4O+KtbhxA221UEFsM
         28ZCVV4Ceb+0vEkWEdxairukUReKNWiG8NqISfeuJhMaYOH6b4FRKXrmS54r7PLyEuQB
         o5BcH2MwaUJ2vIs1QZjZ/IzwqiN1nV9mIoCzzxxlNsxXiOX2owyYSg0+8WjJWmchwNjP
         HD55sK1bDKr5A3+9idDZ0ZR/b3Yzr8n67tJ11Cj9CmOFVL2vKYPL48pRHuxhCu2aHQNh
         R32X/vs2PMc7jucgErrYmSCAXt5lAt2vaCC53AR+K2pwEi6FaG/O+CQ1HOTEvW9Pkuzu
         y04g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=OfLZ6FM+IUYjq0SZmmemPueMGoCYl8k+3jh0AD4JMOo=;
        b=eAboYc4o8BA4lxrrBrvj5ZQgs9kNavadPzIHd2SOJuKw4lP9XPgscRm2riBuWafY4O
         eod7+wc5qdZ334v8hOBpqWud7nPio9ASV/S6pHTbTsNxabqo+e8QUga1nWTKrl/NjF/I
         Flin7jw7EpjzKC15rzy4S3ouoYptcTxsgk3JNVMCqezBfKg2V2fRCRDBKz2gkCQf89OC
         NNoh7gsGA7z7uLKWRjyXW07/xRZLGKvj0fByUzN20mZMUp1+NEDUtB3o9O52nSMdY95/
         SiWmeFOPwWKohYcHFODp+lKSxyotKaaEiXzZBvEmupr9IszwtTWiItwu4uoxXrAIQAH+
         kUVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Tvu1auoU;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OfLZ6FM+IUYjq0SZmmemPueMGoCYl8k+3jh0AD4JMOo=;
        b=U7qsvI8SPDdnA0FzObmwMLiKLkUHgtsWZudrYeFSWGS0DCVUfXFzGABy2jan8XVnc4
         WR70EStUMlPQE4/MH9BYLXns5S3V9brjW0F3Qb/QUqPYDC1IoSrwdSXUz/I62We6xRUr
         2jqkMFg4FoTRNQvv7c5GHw0BXA58YU7kOF3JZYzOVdpjOVPyhp6bMW4DKfYrzsijsymc
         qvCixq/KRQDCeUavr9KmiuNML40WqvV+WNn3/ANiV/YiCYiCuhlWXdZHogSmmqTNe4JI
         gF1nNGerR8YUXgEN+HUdLx8MYrWR//zg+VI9QT9QX/u23h+Thiv3q1ko0fa0OyARbQPh
         9smA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OfLZ6FM+IUYjq0SZmmemPueMGoCYl8k+3jh0AD4JMOo=;
        b=Bclos+QK7z7ztOZC+iJAxWoIxtxYO1lcn0eezjdnyY+JfneUeGejag4U1QhjZ7iJpp
         DueIbtN0t7Wod9YX17x4sx7kS6/Cvla4wG4/edM6uekYru9rAssY5pioiMYyyyQOC5jS
         +TCkhJ9MnNJ748e6do8Z2EjoQA0ejK0qpXDKM4nCIEahKR2zYbPHJr8klPQmzscsfbVb
         m1YPRoGxd9/nA3klYNtsqQXf+easfdO/ns0+NY0Upd8kIAPgTW09XzIGF2l1q6jabz/I
         SiHQBOxy9BYoFNwUuYs0gqvUJoyUS/AeI7uigW3/kkRnbiHLsE+UUv1uIPb9cjEttq+v
         xjnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531nRhzkt4mKi9X75OV4fYdN/VvfraHlAtB+2P002jWy8L85QSLr
	3vLL7ucGQxJVHcAFcBKmFDg=
X-Google-Smtp-Source: ABdhPJykTDivxyJ3x56FPQR6iB3YyEfEfIhCsOL7/W2yvD/s27dJklTyVZK7mO9O2EqC12kCcoBjjw==
X-Received: by 2002:a05:6102:52a:: with SMTP id m10mr2638481vsa.53.1600920321530;
        Wed, 23 Sep 2020 21:05:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3d1:: with SMTP id n17ls316927vsq.2.gmail; Wed, 23
 Sep 2020 21:05:21 -0700 (PDT)
X-Received: by 2002:a67:ec9a:: with SMTP id h26mr2639985vsp.34.1600920320967;
        Wed, 23 Sep 2020 21:05:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600920320; cv=none;
        d=google.com; s=arc-20160816;
        b=CtD3R08NmIRFyeddikcu3NiFGLm+JS91Rw+2BtSYsnEmpHOb/2j2a5b5H7OZuCz//p
         qFhQDMxGxRW8qkKUd16PaT61iBhiPuaUvWpUiivzMRxvz70Z/7PKUTDBORwQJsZhT7rH
         aTQ3IVYSz56MmTwmLdx5H5/YKgxzAbgdAzosjDIgbT2sD09h1SjyCOsLiul68cCP2mLh
         mwkgyZ09gM1tsQrvwFnF7rRTCLyy5u/CNen5whL79UNOxnMYDEPT4A2W47besi0t2wrP
         S5Dh4OBY9fYFQiPouwZW07i29G0kvaazTv5uzuCtftQGckdekOj6lfeXvbyYSHrsRBVg
         ceiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=jERA97XeyBTxK9uRT3LHVudEGcqfyQoFzaVX3v1wRNo=;
        b=uyZ7nlf+27AtgpHbipQ7ctq9JZgoSvLhEq+FdLtXOzbb2mGo/1ONpxZCEcKfB2ZvoB
         IbTi9lPYyr69kPEml2s1H0G1BiJhzzScQ4t7QX5A4wN8yJHUJTy13wBGW9klZSjxVrD+
         neOdz+dTHsYZgQTtp1gk7ygvtyjeCDqPGeStQN5WzR8vW0RGGz6yqL4Pho584knKEt+O
         uZRNjBqHYPcymm1hlQgluz/XrmwrT/Fc407MAwEZJN1Jhs6cRGpdq4jYmhkYulRl3X69
         yoktWNj088/Vgqhc4Emy8dxboY6m5ca4zrDiQsN5CGWJk97GGe7CV+zlzeb5LCVPSPya
         vXjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Tvu1auoU;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id u19si135048vsl.0.2020.09.23.21.05.19
        for <kasan-dev@googlegroups.com>;
        Wed, 23 Sep 2020 21:05:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: fa50f555e6b14c81bb6e9d5d0fea0074-20200924
X-UUID: fa50f555e6b14c81bb6e9d5d0fea0074-20200924
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 221699063; Thu, 24 Sep 2020 12:05:16 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 24 Sep 2020 12:05:13 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 24 Sep 2020 12:05:13 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
	<andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v4 3/6] kasan: print timer and workqueue stack
Date: Thu, 24 Sep 2020 12:05:13 +0800
Message-ID: <20200924040513.31051-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=Tvu1auoU;       spf=pass
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
Acked-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200924040513.31051-1-walter-zh.wu%40mediatek.com.

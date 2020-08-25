Return-Path: <kasan-dev+bncBDGPTM5BQUDRBJ7ASH5AKGQEDU3TSVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D517250E70
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Aug 2020 03:58:00 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id 73sf3405391pfz.13
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 18:58:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598320679; cv=pass;
        d=google.com; s=arc-20160816;
        b=S2t76XysM6LPyJC5etNcYk1Q3011y3N70jU491YXNX7/nMWxQbWj7lkhLk3O0seozN
         5BcwyakmRxvQZE6T60Phpt6LlviQPoivbw4VebbYRh4tH4QlCor4n9Pba9lqr5+OogYO
         3h7KzN61c16pI3CsnqWmFHCbQ27UfwxVXRXTobjve5hRclNhsy/lmmh3TlB5XqJYYuoQ
         xSKyNL4Q2deTBO+ILcRt+sKgs0wDyikQMeDvmicu6ImgkeL4gRhQO7b3YWKa0hVA3ZPw
         BRySN8QglKIJVcO7QcmBXhWFQ3/xgJVBfJ053IlaX0iK7/ouRaycdVhC0+awDNNBqKgo
         3dZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=n5dupBlmq4oWRTXsitwNdPAiJk/K/CKtEhW3QKJfQtU=;
        b=YrNJLEWpFOr1f06CXHhbj1kDuxITN1C0q4Ss03BtsfWXQVJ94Wg/qkRnRsqjaAHD+3
         sA9amU5NBFN6anRz5NZmhWhRpxwiNQ1W2qy+Tg6fwGnEfURGPy2WoEvpkKdjegl3yiC0
         81ghuuW9xylx8l12ecNCFQ0nBG4DCUh8zJ6xhaUhD0jE8VYa6LZiRf5jylbONAiCl9kv
         JAZGitxoDHB4ZTplcG7EIFdHbRdzuLkJu2IbzVbEIomnrWVe5aJG6UV4h4kMUH49MzBc
         rNUN7PHjQ3t97gxhFv1iXhx+TqFIj0CK1+oQlong68fQ4mUlRLvFT8cO3ARmr24zCzGb
         Q4Sg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=LYPsrwgh;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n5dupBlmq4oWRTXsitwNdPAiJk/K/CKtEhW3QKJfQtU=;
        b=C6EQDkATp8kuaum8XKpETbpRIqhtUrfUsW6bNHiRwI++AWExhf8vP2b76s6QyEaDYz
         q6fhFv+lgab+JcjhMnqRl5Kd4jWYaKNpZ3xRLdIIRj00QCxDNIRBig3thel70ojtoAfq
         S2ZwwrYKl5nW10s7R3PXsk4BcX9edp5VkYIicQKcMpp2gg7quv75O6wsZZHVePOtL7QF
         nHfkLsvfxxUqBKc6sLn47qPL++H0y+KOhyu/JO0nJZAISG4nSId5HX/yf+wOh+D6TV2a
         y36GFMnJCtYRgcgmPjJh6BA1lPr1O+gI9uK600cR/NpPh0dnvppXQw/9jOJ+kMmXpQU1
         rejg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=n5dupBlmq4oWRTXsitwNdPAiJk/K/CKtEhW3QKJfQtU=;
        b=H4Sf+fV/CY5yYe8q65r4U9zE7gwSPjpMOEKh8C83mPJcHqt3Uf9q4K4vSDL+3f7X3Y
         R3IPFWKBkVmqzQgaVCJoTjxIRXqQ5dZIrMJHUJJhdIjkURdfP8im/Jj1vNMTtrMgcay/
         HtzHTUrFWMH5aft40AlwQhE6azJmPAq7uI6r3TBb5LFxajD57bDcJoQqlBQJCT1OjHVn
         DU4MTOCoWLHIHH4eShxBy3NpmaERwyFiRqkImQ3LczwOKpEttX4+++imPX8+zOTS56Ii
         QjuT3ZJBavDlzW2X7RL/5HljYnuO3mopsCqlsicqhYsmZP8AMAy15OLnS0kTHFxeedDF
         sCSQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XgJ7xwRrQTKgBiQ77Qqf5Wleq0tvgLVYE+vfSRefnJknahLhD
	0DnI0qN+jpyIaDh+4i/kvIw=
X-Google-Smtp-Source: ABdhPJw3URoE+LRSWUp1GKQ6NdTp+u7lRgc3tcDwo+StpiNCmslkp3NI5aXIqbD0g6QhIACkeZxNhg==
X-Received: by 2002:a63:544e:: with SMTP id e14mr5161956pgm.90.1598320679124;
        Mon, 24 Aug 2020 18:57:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2126:: with SMTP id n6ls1718647pfj.5.gmail; Mon, 24
 Aug 2020 18:57:58 -0700 (PDT)
X-Received: by 2002:a62:834e:: with SMTP id h75mr3278456pfe.174.1598320678742;
        Mon, 24 Aug 2020 18:57:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598320678; cv=none;
        d=google.com; s=arc-20160816;
        b=kOQ43hMdt35xf80aeCyxHbvmkdwgM5+aBbnuQ+RcuZn5ycttpRRfWB/wgIf9rKQ1BT
         wfNTTbN3MXOcr0tZAobq46+hj1be7FKLRDhPEql7DWJhJoB3oZ++dTa677WZOHihyG/A
         iCh6AbfLXW7zi4o673xG0aIv0aIu6rmWDEh24Ulh9SuLn3cnBoKj3e4mbDMyEAZJVjQL
         4fJN5KXR5PXp2ivQXPip7MyOacE7dr4qZdppXYCaRP18t/Gm1UXF3F3EtOVXE/ulKX7B
         e+F9W+Jo9DDaN3HHgHTm35R8TIf1z7H/j2hVsF0dNtbnSHxg1VJY8v4Asi4TZTSW8mkO
         34tA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=r0Oq0tBfZ8jFMLMVK7p67PPtKlTRIAQp8x2ll2ZCeYU=;
        b=ltsLx+dWYf6ZJ5CT0o9u2AgUDNbZ/1vNnZ5BpDO6g6RjCwvnFX1+W4e9vArltru8Tl
         OB4IpVpeyTmmwvIUAxN6srgHVWsNlvuvzkBFEqdhnuyEc0u8VvCdmNkfu0TyDjcHbEDR
         MlcJXlFBaYnJ5RM4GWzFkC2axgPcyk7x9nDRxQ6kyNe/opvFHOJg0+OoBoasYFsMitYg
         UizaXMr7emAaA/U+tGAj3Hw3N+TneGKieBA5hG/SHdX6KKaN6ocdTF+1LkcShG8anLdR
         1Gzs0Cktws4+yWu7p1riN8bUwCFmoDL4tKUKmvjeQ8z3g38eekJolF0TMAAA+rQlL3qF
         IAoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=LYPsrwgh;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id g11si519111plp.3.2020.08.24.18.57.58
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Aug 2020 18:57:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: ec1930a35c604ac492ce8b82d9c0679f-20200825
X-UUID: ec1930a35c604ac492ce8b82d9c0679f-20200825
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 376347103; Tue, 25 Aug 2020 09:57:55 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 25 Aug 2020 09:57:52 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 25 Aug 2020 09:57:53 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Marco Elver <elver@google.com>, Thomas Gleixner <tglx@linutronix.de>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, John Stultz <john.stultz@linaro.org>, Stephen Boyd
	<sboyd@kernel.org>, Andrew Morton <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v3 1/6] timer: kasan: record timer stack
Date: Tue, 25 Aug 2020 09:57:52 +0800
Message-ID: <20200825015752.27841-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=LYPsrwgh;       spf=pass
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

When analyze use-after-free or double-free issue, recording the timer
stacks is helpful to to preserve usage history which potentially gives
a hint about the affected code.

Record the most recent two timer init calls in KASAN which are printed
on failure in the KASAN report.

For timers it has turned out to be useful to record the stack trace
of the timer init call. Because if the UAF root cause is in timer init,
then user can see KASAN report to get where it is registered and find
out the root cause. It don't need to enable DEBUG_OBJECTS_TIMERS,
but they have a chance to find out the root cause.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Suggested-by: Thomas Gleixner <tglx@linutronix.de>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: John Stultz <john.stultz@linaro.org>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Stephen Boyd <sboyd@kernel.org>
---

v2:
- Thanks for Marco and Thomas suggestion.
- Remove unnecessary code and fix commit log
- reuse kasan_record_aux_stack() and aux_stack
  to record timer and workqueue stack.

---
 kernel/time/timer.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/time/timer.c b/kernel/time/timer.c
index a16764b0116e..1ed8f8aca7f5 100644
--- a/kernel/time/timer.c
+++ b/kernel/time/timer.c
@@ -796,6 +796,9 @@ static void do_init_timer(struct timer_list *timer,
 	timer->function = func;
 	timer->flags = flags | raw_smp_processor_id();
 	lockdep_init_map(&timer->lockdep_map, name, key, 0);
+
+	/* record the timer stack in order to print it in KASAN report */
+	kasan_record_aux_stack(timer);
 }
 
 /**
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200825015752.27841-1-walter-zh.wu%40mediatek.com.

Return-Path: <kasan-dev+bncBDGPTM5BQUDRBAHMRX5AKGQEBWC77AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 60EBE24F3A9
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 10:10:41 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id n16sf5603249iop.19
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 01:10:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598256640; cv=pass;
        d=google.com; s=arc-20160816;
        b=GZMWK11jsgaIydIiCeJTlXy8MrwTD+TPM8RvAOMYryedX/btCexNlaD7RNZqVPPlDy
         AgknWHTbP/W0xqjfdsXk346X1wlDfH0wWNyYy+uGYUTxTQuwZMc4rBOX9oDPqjc02jsO
         ynC1K4aIEDl3e9me1irKscYkH2X407itUsbJYgV/mQ3nR+/sfVX7VWg61Hox5NbJ+WGQ
         vOQZ6vnqy8yeaaS/81Gl0H8/Jzx2YJaEi8cIUgK6PBQXpHdjAThXyomtL3mPzAJN3OWq
         U5jnTg/0wM/CUEwpcLsa+MR6X/kXF1OSSFsv6rEy7yH91A4seZgC9r+6wE8SZmodeR91
         t0eQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ZeVn6YhDBPuSc2yGaGLsOcnhVvOXfjzLW6lanb5RJcg=;
        b=KkatKw8+Ia0gttuv9W0azRr/GHcWSHpVBKQj+5N1LMOl++ptHJoEQTYmI+t2bKiVb/
         Hyaas/tRvc2Lt1SkUnDpj8aGnNmulN0q7yN7fslUogaaOtCIH0XBew4TKPxTpIoonQRR
         jKe7KgaD9XFfzG9TujH37rm2YfsbypLJ2MSP1pZezN6EPIiTp4vbHt1iqO6wN8dV0Bzb
         1Hm6HG5674pU+as+TlIcSL5fiVuA5VhVY0nLPpDyffkVcpFdJcWaqIEUP+av9xZ6j0V3
         C52gfKxw8uwDbjoQTzJLgjcoCpVY30r2ViAJaqW49Sx192VWoBp7V/il9g025zfaWQBC
         +f8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="UlZb2/C7";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZeVn6YhDBPuSc2yGaGLsOcnhVvOXfjzLW6lanb5RJcg=;
        b=hLq3pdvmf9nND+kHjwLZeZ9qPCqrEVTGjcUi2Hg7wx1AA6tBF0HFkxXAfu/FnBNHbN
         Jv3yZDw6RBORmRvg44zAGdnI1/mQ+uNTC1w6w+0VURLbZrxMsY73SRocJB6uTsvWhVMm
         tc2X8LHkL6hggloUH72B1NAOHhasHuKypys+pBEDKkQ5ldomv+Hnu3T6bk+AM2Slm024
         2GZ3MWhHdcHVRWcmbAlm4KxQ2+Rp/ac5ea0lhbmNSkG+NQE2sj5gbFIiDaAHzIVS9m6w
         ZhW5sa3cmC3590rdj92o3q9bmis37g5S72oA6dVK2wQxYtNwr3NEUg3INVpQ3qmaeUl6
         kuhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZeVn6YhDBPuSc2yGaGLsOcnhVvOXfjzLW6lanb5RJcg=;
        b=fY5MhnEQM85oti1sc1SW2tfhnLKV+V2x1325FIpkMH/TpdfFD5ANfkDAcLRvgjCepE
         NWHjIimrKEeN5l8tohXcIp6Rp9I3GjRy9n3pPkBMz3dI6JXYuwBgKk3zsL6/1NHGPhd5
         hwyNoCbSjfuISqTAbWq1LZAqn3bquFZjebpnAz1lFCQ0PTBsrxTxOzRM77GHRp0z+Nc7
         Zz1YnUDGFdQsp8JF5b3GBIgl/lvzUvUj/Cn8lnYbCkZRxr6GSTlHj5B4wpQXTj1t/p/w
         P4YAP/s3dYhVO1SWyN2MpZZxoez7u+6TtlGqUCuNLIq9KMs1ZmtzyG/5oD1pkwa3otLo
         R/GQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530cZr2OM7olcEIPk3XP2iTSHA0I6Iihn5RuHHQH6deqSeupuf7E
	0NNe8sy+KWDUE7pRV2QiqIE=
X-Google-Smtp-Source: ABdhPJzbfHq1Z4XAwNbpGs5OEz3GHisYexk2VXgtC+Xj4IYyTVVSJZYcjB3ZUi/HVEbyToUSfvwo8Q==
X-Received: by 2002:a5d:9688:: with SMTP id m8mr3970812ion.152.1598256640369;
        Mon, 24 Aug 2020 01:10:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:3aa:: with SMTP id z10ls1078668jap.1.gmail; Mon, 24
 Aug 2020 01:10:40 -0700 (PDT)
X-Received: by 2002:a02:82c3:: with SMTP id u3mr4523425jag.81.1598256640094;
        Mon, 24 Aug 2020 01:10:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598256640; cv=none;
        d=google.com; s=arc-20160816;
        b=E4D+2niGZrE1LgAXk+AYnsh8wPvvw+zdIQIEtSyKd04cx4qyM58yRNqhKmOs07OLMW
         PWmGsOMrxBk3mIbE4HipQ9BnZmkZOqbDW2ZkQ2MrdZ3GE3n1PfoayXjocZu622pGudy+
         i7ke3K0LqtWF2HEIm745OlmPHQkFYzzk2e0IGhs6t0AqQ4uDBs2bvd6VzuhDK884zDOz
         iyZUnoyID7UTzY/g++6U0NALqKqC7gtfuPzgepRa0muujhNwH+8RB+fZAaMRgvYaPaqN
         twgodriOMKoFgPhzKEJU0YoDrq1Uw65U3qyCIF+xE6jpWTObQFAxR0VnT2pIh9/jUjns
         eGbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=r0Oq0tBfZ8jFMLMVK7p67PPtKlTRIAQp8x2ll2ZCeYU=;
        b=Cc7JoscrPkubLNcXXXMT9na+DLqvtFBAcZ26Jp5JMmCMhYtnIBim1KeSZPHA0qRiqT
         W8OGp/rVFEO5t5ENNvkoevbUlDmZ1l6tH04XOqnwS4xU/oAFB7OE6UThO4aGF2wjpTZ7
         FDZUcrl+0fE9+djo+gdhM+VgRK+DswGp7lxbvnTZl1wE8GIq82Hmkctr86NoGbWJPh0L
         cGrivj3zjtOuwuIqIHPkUqNf4QZ3NYmiyL1FSMnGuj8wzd/QvcbO4JsUpKco9W7+6/Pu
         cPpWfTbLtZuzSOj1ht14jtRv+CzdwJjLeuW1clek3dOkcLesS9yXc6+IJ+kHC+v8WEqC
         UdZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="UlZb2/C7";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id h11si515383ilh.1.2020.08.24.01.10.39
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Aug 2020 01:10:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 8f767e7d6354430589917989e468e817-20200824
X-UUID: 8f767e7d6354430589917989e468e817-20200824
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2023979013; Mon, 24 Aug 2020 16:10:35 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs06n2.mediatek.inc (172.21.101.130) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 24 Aug 2020 16:10:34 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 24 Aug 2020 16:10:33 +0800
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
Subject: [PATCH v2 1/6] timer: kasan: record timer stack
Date: Mon, 24 Aug 2020 16:10:33 +0800
Message-ID: <20200824081033.24786-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 378A0C9A9031AA52783956160D35589390C54B78AF36FD01C7D67ABD9CD1A3072000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="UlZb2/C7";       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200824081033.24786-1-walter-zh.wu%40mediatek.com.

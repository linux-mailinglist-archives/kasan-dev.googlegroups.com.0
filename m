Return-Path: <kasan-dev+bncBDGPTM5BQUDRBV7NYP4QKGQEJ2ABFAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B82724027A
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 09:27:20 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id f17sf1972573vsq.17
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 00:27:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597044439; cv=pass;
        d=google.com; s=arc-20160816;
        b=BfdLkEtFBlUB2ZeuqY/vDIdEJbshd0gG8dNCbT9qSFx0lJQnk47N6phhTW34rb5Z45
         Bt4Yrj4YnZwr3NQOfcv1zAxZrQ271uXfYhKqlL/7BoZw52PTpNNRK00nkhaXM9gv1onQ
         6G0yyRWFIAUnI0inZioq64a+cs5B2KqQTWUN4nZDgimPIms7ukcoXW1E62Fl2gafJ6Zl
         2BI5SKoSsgCeUc5osL2v+T2gSEfi5L5wKwI3xN8ZYGkgjv6Ca7+D9xlhHPWYaZG2nl4l
         gYVh/3bfNCJmtwkalH6HYtTyTjeRIGyrDnoRW+yWqJ2ZOH+J4RTAIkDiUWXSHzcTQmha
         Yw7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ERtJDVFuUmDKYmCEHPd2BKpxAwijS9yuLHHnNgs/Ca4=;
        b=IlKKW4yCfQswqDW7CIf16SrlYMAvRu91aSa9SRzakUr3JKRQfQzb03UEJbDh1t3wUu
         G4iM+ioPZcxH36ntXUvgcF8VExDfkVlb9hpXzfYpA0VOimFr5OwI6pL0OrtExwlCzuWm
         9UtBO5crzmlEPuiA6GZUTGJVubrqlqu8XChRqz8W9FShz0CLpNPDqTYxFewCIRF9M/8G
         dheOiTKCneyISC4WPJDp7a3RRXSpR2bXDtnIJutmZfoBsnDkQY5pRg4+gG7LRFE+NRpj
         JgKmYX8Rtv27sZdYwFE3ztrsvcSZSP1V1VEM/ph4QC+gVu55ygL7d1obAtorOsWV042E
         ohSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="E71a/yQY";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ERtJDVFuUmDKYmCEHPd2BKpxAwijS9yuLHHnNgs/Ca4=;
        b=Tgy86TMdgX5Kn/pBqR6DKRg9ElEWGDd2FRqA4uwwYicHYMNIf6wq8O2/tMkalqThBc
         Ak9+iGPT6O2PxP0gD+OEYRNfn6pEd8RUtu34Aenkm7u1oqscliRcgw+sF26LpdednGZO
         GEP8cC7SffZfSaTlGVe6bNiFb/EoplXv9DtO5uCrEJXNiZHmcvJt39fmPzFw4zwHVJ5+
         9jiAMU3swizfpd3HgZWanHq9ohKxLwQO1YO1O/Ekly82Dt/FDbHtabIZ6NiC5ejOZj6S
         PuVq3pGI9z+wZ8taTtWu/SPNTQY9DFVGO6eKSQTy1Al+QaZM95nbo/Jl7XcNgdyx25WR
         uw3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ERtJDVFuUmDKYmCEHPd2BKpxAwijS9yuLHHnNgs/Ca4=;
        b=LVsj8ugN5jJHZnXh5wBy5sNogJ/teYqrdIFZyCIPPsmf6hG1O0XzYlb4/rbF5/bIQ5
         c2rnfATk9PuqOFVB7N3jtEBu6gYoGiG113+NTr5qqn2wJxBG/LO8lhNogBO3r/2Em0RP
         E1MKBNod/KvD/U5SMUrop+MNw5ruGneXTrcOxZSW4oPzAWXDXzDT3Gquian/j2Wv594k
         hx05L/TSIEido2WMBjTxFIVlNeWno/YvPvPWfOprzGm8w1VAeE4OQ8x4wOlqxyVpIWuk
         DWDgR6sw1YlsKdciGujRSBuv01EZXjM2Ctf1vBKTXZCa+SKuhd/a2N6uaWI1WtzUzm2t
         WS2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533kPT6L1amXhxP6+oCxdStN8v7HezLKTrdbNJOmDtKvqQl//F6L
	J8VHTD0N9BO+R9ZXlHBE/vM=
X-Google-Smtp-Source: ABdhPJzhzvbRGYOvsCZsoLrmLb/BINm89IoD+DEt1ZbTJSHRCqLXj+ijUzgE47sCzvfcSmZC3EQkww==
X-Received: by 2002:a67:c90e:: with SMTP id w14mr16791476vsk.64.1597044439323;
        Mon, 10 Aug 2020 00:27:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:3807:: with SMTP id f7ls44237vka.7.gmail; Mon, 10 Aug
 2020 00:27:19 -0700 (PDT)
X-Received: by 2002:a1f:1c3:: with SMTP id 186mr802155vkb.71.1597044438964;
        Mon, 10 Aug 2020 00:27:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597044438; cv=none;
        d=google.com; s=arc-20160816;
        b=sUdAtPNrXyL2SbEoJnXqibTUzAY+te6J7c0IrUMzmy7HKOT2vIASwGESSLWbJzafGC
         6xxl5Ygsy2WmsgyIuHme+w/4co8KhNpsMQ8xw+SN4dTnxpXuTGXAz+oRdlxNGYouvO7H
         Vkx3hJKfkA/Zjq1TkqGTRHeWMPCCIWM1Bf3ziJIAqA8SM5JIe7RFT61rTChxzL6GxIGO
         A05OdNAT7xPxWPzzQnbccEBa5zrEmk+CBaSF8y1/nQ7GHVqt5SY8mYUb03mbOl1ageO2
         iTSVJB+ClaWwvS9HIwuA/v+2A96dlARdFds0LAH4EiHwp3Q6WoID9ioUPKfUdLbFx+dt
         XAEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=jm5/2VLDnPvpsF4CTFjMyvNKvdSPsuQ1Vi/sP3a85vU=;
        b=iJH3OMvvkiXEQNIENnOAYLaLOzcod9z6E8YoWwcpGm3uBojhuBs9KifOH7/jvO8bKp
         WWlL9ro1dVJMOC2TDKWtzeAjIK5IA2nAt91Wm8F5yJpQ6DWyk4KoCQ22LQG2eJP1RDZR
         ny0q56o2pXUSa3Ifq1bG3n0LzzapyC0S2jHfqIQ7R/+9fY4XueIL1f3OuDZ5dFONvDLW
         MtrD9iFpwvCR+sPjX4DFjwm+AuFqHW3eZnHsWhfIIyDGIA4iDQX9GprIwCIKJE7HkEIt
         ac90dGjSXmUb5rkEiVzvhFcGnoIcx3zTZMDSYJUjV9NvzQ7DAsYKQFVgpuC48zx2f07c
         uhAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="E71a/yQY";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id t72si1000079vkd.5.2020.08.10.00.27.17
        for <kasan-dev@googlegroups.com>;
        Mon, 10 Aug 2020 00:27:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: ce21aa2c3116486aa06a0f860cedb531-20200810
X-UUID: ce21aa2c3116486aa06a0f860cedb531-20200810
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 560984028; Mon, 10 Aug 2020 15:27:12 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 10 Aug 2020 15:27:09 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 10 Aug 2020 15:27:09 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH 4/5] lib/test_kasan.c: add workqueue test case
Date: Mon, 10 Aug 2020 15:27:09 +0800
Message-ID: <20200810072709.827-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="E71a/yQY";       spf=pass
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

Adds a test case to verify workqueue stack recording
and print the last workqueue stack in KASAN report.

The KASAN report was as follows(cleaned up slightly):

 BUG: KASAN: use-after-free in kasan_workqueue_uaf

 Freed by task 54:
  kasan_save_stack+0x24/0x50
  kasan_set_track+0x24/0x38
  kasan_set_free_info+0x20/0x40
  __kasan_slab_free+0x10c/0x170
  kasan_slab_free+0x10/0x18
  kfree+0x98/0x270
  kasan_workqueue_work+0xc/0x18

 Last workqueue stack:
  kasan_save_stack+0x24/0x50
  kasan_record_wq_stack+0xa8/0xb8
  insert_work+0x48/0x288
  __queue_work+0x3e8/0xc40
  queue_work_on+0xf4/0x118
  kasan_workqueue_uaf+0xfc/0x190

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
---
 lib/test_kasan.c | 30 ++++++++++++++++++++++++++++++
 1 file changed, 30 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index c3c6e22ec959..2c6c20cd154b 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -869,6 +869,35 @@ static noinline void __init kasan_timer_uaf(void)
 	((volatile struct timer_list *)timer)->expires;
 }
 
+static noinline void __init kasan_workqueue_work(struct work_struct *work)
+{
+	kfree(work);
+}
+
+static noinline void __init kasan_workqueue_uaf(void)
+{
+	struct workqueue_struct *workqueue;
+	struct work_struct *work;
+
+	workqueue = create_workqueue("kasan_wq_test");
+	if (!workqueue) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+	work = kmalloc(sizeof(struct work_struct), GFP_KERNEL);
+	if (!work) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	INIT_WORK(work, kasan_workqueue_work);
+	queue_work(workqueue, work);
+	destroy_workqueue(workqueue);
+
+	pr_info("use-after-free on workqueue\n");
+	((volatile struct work_struct *)work)->data;
+}
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -918,6 +947,7 @@ static int __init kmalloc_tests_init(void)
 	vmalloc_oob();
 	kasan_rcu_uaf();
 	kasan_timer_uaf();
+	kasan_workqueue_uaf();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200810072709.827-1-walter-zh.wu%40mediatek.com.

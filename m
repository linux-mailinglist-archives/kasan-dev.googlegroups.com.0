Return-Path: <kasan-dev+bncBDGPTM5BQUDRBT7NRX5AKGQECI2YQRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id 3494124F3B6
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 10:14:09 +0200 (CEST)
Received: by mail-vs1-xe37.google.com with SMTP id m4sf2006766vsr.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 01:14:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598256848; cv=pass;
        d=google.com; s=arc-20160816;
        b=k2S7W38joATuz96bvoSPvb4qAXwjo2GZ/lKE0z3ww3jGGqwptV2Br8Kp+ikdwKLJIM
         FswDIUCUrF6eLumps/MVvnTP57hSuFoyhHrjpo2AXGxu/wWgz+MuKx4XVDvxk3Ajm+J4
         pm7QYz0q+AUsTyZqnlZgvazQaf7GWaex2eR14Sa4d4gmpHVJ2OE7bi50fysT7kdwevNp
         PXnCELSyV35F9RJhUc4EGQtcxKkCMf7iWk3vRs5ZBSoddZXAzpxeJ3Iu2YVOwqWQZWbh
         2rm6RE9nhwQ5cwIWV1o4JlFBb7Q66q5gLs+//dUVEpAj/eudE+zhrH8Fcyc3smAbJPEe
         y7Uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=3PAgNeB8D/oscu4vZ3QFUkJi7rsnC6BAH2Oqj1SAD4c=;
        b=Z7ldFsdfYS34wGXSXte8ZsPsEjpFdiy0mSiK4XUsqhmCbafHkAhoF4UXwBsAuiDHO0
         0Fhyol158UAYV1+BhnAhg9NOExENlD3Z6YdLkbaG3ZXhz8tgkp3/EVaGa3WWhm4cZyE+
         k8u7qr2ofOkeDEiAF+d0Q3qv2G128VTrNWCOZ0sk1xzJkq4xveUVYTNDig+IlTvW/QKK
         WDRt0Qlvg4IK+z9V7Dad32YxRW7FoIKqxh8HE515DuL9kimVHVMLApvZWt/gGZ9Rllz4
         sl5pWJtBm6oEaWDIVBrRP+q28W2LJe0btN2vAgLmY55cxkW8aHPZMgK8zHfCOQq9fMRD
         25fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=uJ8vU0ro;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3PAgNeB8D/oscu4vZ3QFUkJi7rsnC6BAH2Oqj1SAD4c=;
        b=oDvZqZ+vMpx/hhkfbB7ZSOhbhWUWd0vY4UoTp7aHGKGJgl1ylIydy3mljA0Le9cMM7
         oSHuqZwHk7b8fHXp4EF/o5qm7FdswTQLHgPQanSoSj3gKQnLZOwUvruYlImqFL6yvoUa
         qyX2wwC3Wd3eUpJ5r43llyDIFPTxrSpEqzMETzjGGvC2StmR8QTD5Gjf7Rj7H5BNiNpl
         AT4faUwnzz9s3BH8nYrgyp8VOYya5Xn+m/GvoruVKvdzb6V42sQFc0I84BLjrXUXXfkg
         b8KSb0Mto+2MObma4G9qNbb3e4VCndQxUTq3k7N8NmdPiXN2EJidpB2aYM8a2su5A8/3
         N7Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3PAgNeB8D/oscu4vZ3QFUkJi7rsnC6BAH2Oqj1SAD4c=;
        b=nPjKhQ6QazymOrbqdkRyUbB/fQN4NC+OTQnu5l3v4nUJUViS8845xApogleAV+49k2
         S0DbofuHafQ8fGFlhT9aCbEGgEjspztZuKJvVzfEDz3UibdcRZSMYW2c7i5PFkn7zR0P
         l/SUemjjnDxCrbKNIPbaIRe/dlOVqs8f3o2KdIGXYMzw69r16NdXnmG9nEa0bhaGDmto
         XF/rQdcy+Q+0q7Y6ifFaK70jfQyAMVYTRmvc95bzP8UYPR2pIH2yVlwv/Q2B5YyC73vG
         ixB0Z61qZgLzo8G3fVG09gae3Tng8OzNgvk9GKO4t1augXlgObnC0soiYM43Brb0y1dX
         yYsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530YkkTi/JEoP29glTv3TYk7ZAQ/SHQXeiEzHwSxcjdd/kpYEi6a
	VAB+YCQwShxSplbOMp8yIKw=
X-Google-Smtp-Source: ABdhPJzxFzaRPsLq9Cri28iFrdrNfH6XW52fgwUuq9pB8C/sKfqp/fVr5eLkzn1JqaYKyYQFvvDIcA==
X-Received: by 2002:ab0:567:: with SMTP id 94mr1665271uax.26.1598256848075;
        Mon, 24 Aug 2020 01:14:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c416:: with SMTP id c22ls954793vsk.4.gmail; Mon, 24 Aug
 2020 01:14:07 -0700 (PDT)
X-Received: by 2002:a67:2f16:: with SMTP id v22mr1023301vsv.127.1598256847564;
        Mon, 24 Aug 2020 01:14:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598256847; cv=none;
        d=google.com; s=arc-20160816;
        b=h6zEfJs4E16HQEQ6ETnCwJ7ojBH4Dc/DUZ/A79e2W2IJfP9G+NbHO8XpKfj5sD0uDy
         DYSaRT8T4jyjzejmDPCz21tlhIGi3lT30E3LetuO6uDA5UVR4d2lo08KR5uivTHG8aF7
         +5NFTLV5R89qO8k+Ttl/ziKLVVMpq9bBGRnrjIel4Sd+K8tDEQBkNvAXi/bGs1FzTUpy
         OURJI4e+yRzFUregWwzksp/pUip4uOywu1GVon1fyCKZoYthcYInnhsfbpjMh4KEJK6D
         QA5D167qNWXg8fHWFt4rkNS/pDvZnBUcYVRoiaVtKLPq6he1ewiRonf8Zpv3OATQT8xU
         yS/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=+uEb+COBoPnYhqxN0aa+Ix9E1vWCkdkDaOsAXwUlrdg=;
        b=TUR+9f9DvWJh5mbeoM4/MpA1MOliYIzDr4/9ImWjwI5NoowkwrD8jjpf2OB8pdJx3G
         VmHhJKZ29h+LnEO2HSVq+AOFALPTFFBVsmqD2s6Tz4220tAuQoC1nfK6GZGOKb5kJiCt
         t/wgtuuuXoi2Nyq9RbiSzJPeRPCHNHeh2NuRG5RLDfNXKRXru23hfkBAU6Ybo7V+b4Tb
         b7X4hi7kx9/UjssHibWlEyGSfu6oYAiFR4vS6v1DYhWB2bRmAF8wBdkh45TBW7LjjhUd
         clargGveRY3Rf9e/cmsIjQmcpCgICD1BS4Pevd8Xco8iu87pJYoJjHN4KfoElgjSW3+8
         9Uqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=uJ8vU0ro;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id p19si544439vsn.2.2020.08.24.01.14.06
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Aug 2020 01:14:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 2ecc87aeceac47838ad5479d78cbd960-20200824
X-UUID: 2ecc87aeceac47838ad5479d78cbd960-20200824
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 581680036; Mon, 24 Aug 2020 16:14:02 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs06n2.mediatek.inc (172.21.101.130) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 24 Aug 2020 16:14:00 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 24 Aug 2020 16:13:53 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 5/6] kasan: add tests for workqueue stack recording
Date: Mon, 24 Aug 2020 16:13:53 +0800
Message-ID: <20200824081353.25148-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: CFFFFCDCAE5D98C607740B946277915AD6F16FFC3CBDE2FE94B34C4765AF670B2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=uJ8vU0ro;       spf=pass
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

Adds a test to verify workqueue stack recording and print it in
KASAN report.

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

 Last potentially related work creation:
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
Cc: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 29 +++++++++++++++++++++++++++++
 1 file changed, 29 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 2bd61674c7a3..7293a55ff51c 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -845,6 +845,34 @@ static noinline void __init kasan_timer_uaf(void)
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
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -894,6 +922,7 @@ static int __init kmalloc_tests_init(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200824081353.25148-1-walter-zh.wu%40mediatek.com.

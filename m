Return-Path: <kasan-dev+bncBDGPTM5BQUDRBMPBSH5AKGQEHDITCJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 205AD250E7A
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Aug 2020 04:00:18 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id x20sf7890239qki.20
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 19:00:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598320817; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZlVliB5mwP6A+oLY2qydr/Jy93cmBT50i2nYImNb4WjJJ7eBcnONVdJK2J9RTj5RN8
         +LbgblnjHipjuDzfXCYiZjIYRGMlqKkMUYcPT69XrZvZLsVEXAsMHGSYI45zcgJ/T89c
         sUHA2pxhpbuppatXgECyLi/J8vMMYB1iSU0mJoOQNNxYgjuPNmaplzcdLRlhdXsJCuBl
         Uiyxf7BY2NVjVWrcUwRT9Cs8yqMhUJh8VHMUJgcP+HNfgQ1Dkuvy1N4yfgIJsKWP59w4
         iTku1XSHxhlw1sWTBIo1dmvBHjQrFYwCPQ+noYdvM/02NAT+80DIxBLvnGPPiG/npYrv
         DRNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=nyXeznrjMz/R2W+B2GnoKwLuVNRxqw0veWgLvINfGLg=;
        b=Hdt+qqO3NRgvCuumxqEmXDQPPDFWgde89uGo2yzSsu6peDNjw/ANu+ZeXAxZD+B8cf
         C4kXEf+JbML16CPXPv/khmm+Z259j0o6DjVXtNvOTkXu5auaak5B+wR5Up1Jmg9zlR8T
         WjXyJ6IYbJiev5y9/YzFT6iSHEfGBCtpGNcNms/x1jd67CVsSe0WJ0633rH/NG15axbC
         5yXgVPo78VthAkAm7rxgUT8KQWhDf9wm7+8mSdm0IoRrbH36cFEAIXfKsjn6DsqZAYg9
         eE/fNxUT12JdowlAzne32RZDzJEmMYxl9PrD/G4m6p71ZEKabc2Yc6YKQbZRAIqsFQ7m
         LcsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=snlOgSvp;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nyXeznrjMz/R2W+B2GnoKwLuVNRxqw0veWgLvINfGLg=;
        b=qtNuOBv+/JTzl1eDNLb1QG2HYhJVDuH4aVswWb4OH8eDsc3ij0cPIPy9G7MBUpzslv
         Eb61WrRieIZc32YpmFB28ppotAnAww5hv5urnq3kRJf/Taltql67f0LlbCSQqtGGfFRz
         utY7st7WdxrdUfvCahuv6lpqdzwrDHeGKJnbKILQbfgkEM2vTNwwz/vRlI4AHGlF2Kb+
         xkAr8kLGGuWmcgDi4iX/CgGBkokQ8zAASwZiPkmb5VOoGseZRjgIkkXKFNGMTI5AgT1P
         jq9qFCH2S9mLwW90XBkcRcPmWTTkVYJBQ6FujVdXpAVPwi8hYRjDdfJX+LSc/4hKoG3v
         0pCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nyXeznrjMz/R2W+B2GnoKwLuVNRxqw0veWgLvINfGLg=;
        b=a76ZkVEd64s91A3PjA7HCpzoPgjw1ct4aGfsJ11jKgkZXs65Dt6LwumHtcdnVZCglp
         Zlpwe8UMWAoEv7KYl3eaKfvyWU7l13Uz0H8l6e5WLc1o2nVAB+ikgmvuF6elZlxzRsLz
         2xqxqnKqWVOoj/vEvWEF2/YWEdl12/NvE/bt6W7wdeJ4w9TCMO2CPAUYHOZ9DpYthpO7
         fXjmKYBmZjiDNz1Tfe7iLGd7auV2/lX3Wo9Es3YzkZFd+rXWO0Z78shm/VTCwodVjVvK
         N8AoIEx1oqENbGPIcFFkHEyQHv5zyZMaUkuRvmDc04iGCeV+ZLSfLqBGyw1g3RDQ4/Fe
         nCeQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zgqvZsvMARHbwQL6hDIVvdMVhlhwEhF9FcwfxvdfsU5JVJ7QC
	Uel1eVlSWhIzR6f2slS+C2I=
X-Google-Smtp-Source: ABdhPJzlP/fq+RgZGa31j0+vty5y1BTs3F13c/q91uSQp1hrzX0oMFpLvQ5Jb/Lqrabk3MddM0hwUQ==
X-Received: by 2002:a37:9287:: with SMTP id u129mr7256185qkd.238.1598320817174;
        Mon, 24 Aug 2020 19:00:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:3405:: with SMTP id u5ls139135qtb.1.gmail; Mon, 24 Aug
 2020 19:00:16 -0700 (PDT)
X-Received: by 2002:aed:3781:: with SMTP id j1mr3576265qtb.337.1598320816837;
        Mon, 24 Aug 2020 19:00:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598320816; cv=none;
        d=google.com; s=arc-20160816;
        b=C9QXDGMG+b3lEbqDYTCZF+EOhUWvt8Qaw76J00xlV9z7D8ybMcA3Mnj6Zuc8yWzb8P
         z7ujT/hfrz5jm0EjMwCg47Ch7G9DDC+Kq4MMI1moVQCbS3Q6xJyRlRm84wTHEQwloJPq
         +Z2Jl/ONrDfkc33OZb05W7cyOuamSAFUVr8hA3D+PVRnOkn6nMA1FEDQh3bYxG8e18mo
         sRjtv4zR3q64vHLm2fmF5vHmcrk3Ww51xT2Lni0mouVTaZU0QQ6Qox4GVst0eOOQ+N2x
         vLqtJoTJcUbUBUH9Remxm41N/xNTHUneEcN2s5OValDUSjjbt/1IHMfNY+Flgmfx8MlU
         bfcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=+uEb+COBoPnYhqxN0aa+Ix9E1vWCkdkDaOsAXwUlrdg=;
        b=UMwZg0VcEoRK5A29E+W21X419rfJdh5DMdZS+L4binfXpt7YTDCukjY/IoHRllQii1
         GaKV3UFOEvai4Ikyr6Httc5pVULccg1525Z5RGA+HTQoeDrh8r6fv7zIyCQE8jQuL7eU
         HyydvKcLjMoEvfklpYf2dvNHelVVKgqPoHTK+rkKPNPRMIXsgv0rQc6rbnP1Ky6VhRYk
         2kTjGUlIf54+Cs/YM+OaCPDWf2KGwFpQncGUlxH5EAXdNmiR8hzIH/j9gkODNsvO2/p4
         1PLNjq+O1e+cpc0qkQzXdLAbE84+p6WSbEc+7NBUbhw3K9mX+imvDhsU2XSyuHCTVdoK
         bM1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=snlOgSvp;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id o24si763500qki.7.2020.08.24.19.00.16
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Aug 2020 19:00:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: da200875e771434fb8ea2e4074119a4e-20200825
X-UUID: da200875e771434fb8ea2e4074119a4e-20200825
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 555672964; Tue, 25 Aug 2020 10:00:12 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs06n2.mediatek.inc (172.21.101.130) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 25 Aug 2020 10:00:11 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 25 Aug 2020 10:00:11 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 5/6] kasan: add tests for workqueue stack recording
Date: Tue, 25 Aug 2020 10:00:08 +0800
Message-ID: <20200825020008.28682-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 6777E2A49D633339955E856E650F8D381A2BE95487C4F41DF024165C8168C8D82000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=snlOgSvp;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200825020008.28682-1-walter-zh.wu%40mediatek.com.

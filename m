Return-Path: <kasan-dev+bncBDGPTM5BQUDRBI7NYP4QKGQELFUOZDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 55C1E240274
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 09:26:29 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id s60sf10410444pjc.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 00:26:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597044387; cv=pass;
        d=google.com; s=arc-20160816;
        b=J/zlek94H2vNmtUEpChxMrfwgB+KC+R/xVvwabLMIGeIwvgPTW+YdQPeKJSDa3Hk8Z
         N6kMU+iuxIue4BAKX2cO44VAcphKw8WWeIp3aNQoXZ89cX+kERORRYaucT7PSU3L2rdI
         3hRLPYOVCDjtrsthKfba48zd/j8/NY907g6tlcb7Rq6Hyk9+QtEY9QkwLTlXcmA8DAUa
         sjCQZ/pvWl8jBgXBCSZMQ+tnpLEYwzAV8UVBiUJcHdsJ6SZPcufB+xot+uQPhQfoHxUv
         ymCG8AKH823HDttpeR2twLOtq3tkA0+J6gKeQyGL2To9hSBq+4NdZ/8GnZP29xfoAhU5
         JpJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=un18wzEDnkuSF5pguqVhvU0JkLA9XRuGr5XNrOtPx54=;
        b=A7N3/Qs+CaXqrpL0EosIVu/wyRbXb8QOaynzpTNQi/wCs/L+O1C966jZfAQgzFCzK+
         T8DSVXn5NX45LfLTodtQ8q4mRukRS7fureAXldNi7/IRHnUz+wJGs/g4c0OldpG0JrvM
         eJQqoKVy2IRC1cciRBCpFVdSNYVTzkLPULTgpjJwC1VyaIzKQU49EvV1spWnsn6q70mH
         j7XvV/ddGucnDIvBbee4Ktr2xW2NPUBtfTFDdeoHslSUvC4vIDZ+pYrM/o9xJ/fGrw4c
         t7B8ezpqKH6J5f9mgWzKk0tleqSw/sBZ9MMwo07F2eHki75CXCHT/WE+SkMseJWMbVAp
         OQnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=GyJWAJ4X;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=un18wzEDnkuSF5pguqVhvU0JkLA9XRuGr5XNrOtPx54=;
        b=IgAy9NPUDZqM7k3hKrMQCf2FoPzwfRt5MjvfkN/OosFeLatkf2q5MzrWLM4uGW2Ajb
         c4atC+5JuMRAfmt2fLo4X+pc2BgZFRm8au2ECk7jfP8tyJBIkXp42kie8qEd6tjytS1x
         fuZCfmBn8nc/k6Z0/+iH9TEUvstn1E/tvu1TFbk19XxzbN1tREDru7ZgvZG5JWtgyKS+
         koKyHk/B89lTEpD2xBMBRD5Iwnc9kop+5Tyjtsrz5FfTndWyppx610eVdewYfZNvjazB
         ZDnS7AQ54zRih3v73xKD3/8bPQKA7av7bZ4QqKjf9fpDEkwFwOq8cfN3eP1L8naHiXQE
         Yn3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=un18wzEDnkuSF5pguqVhvU0JkLA9XRuGr5XNrOtPx54=;
        b=CXw8BfArsmW7BS5ycxDuVICiLrdYbrUSmLmRpfmq63+JcUnG9g3hyH+iKXMLiuEDBC
         hMaqwLypHcSzS3VB5ocgOA3BUwYcm+h3m+x9kFePDn3l55S77VkWOtbXC6BmvCoI+kaH
         Re51DYI/K57vKabySnERXZxqTer2uRtXnWzLCDilxbyo/f9vrkzDlr4GHD0w++ctVq+w
         czkc9SGRQFheT8xLXwXSBNODRxHeIw76URx45Wv45qFXX1rm/sgl+m/qI6CyoARbjYN7
         cqvSNVI8O9Yf1wjpXKdz9Sc/pzBxewVndRKMBxGNm5g/dA7JDZCf0xElSlGImp3KrQuK
         TOvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5323POOJedyPEgTZcdWnCfdhJrkHLFT446LcwZKluXnsXvOzBwk+
	y6tfVD9XGYBhWYYyE+uvHZc=
X-Google-Smtp-Source: ABdhPJyLJEBWiNk1N21o3x/lAVv8utXjI3lXy/dpZ0chxDl1+t5xuOMUW6w0Z9XyXZx20vcNuWcmkQ==
X-Received: by 2002:aa7:9a5b:: with SMTP id x27mr23708376pfj.15.1597044387682;
        Mon, 10 Aug 2020 00:26:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7e0a:: with SMTP id z10ls692322pfc.8.gmail; Mon, 10 Aug
 2020 00:26:27 -0700 (PDT)
X-Received: by 2002:a65:6243:: with SMTP id q3mr21036608pgv.57.1597044387220;
        Mon, 10 Aug 2020 00:26:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597044387; cv=none;
        d=google.com; s=arc-20160816;
        b=diSS4SRwd9ZG2Ev4G2PHsEvwSiFk0XR7M7f05NFX+MNXsmyp80Rb/VZ4HGjcVjniiD
         27O6RKvCBSbvzl5cr1KQl2KO1hijM5ovxkOx6oDT6+GaxcV9XTXPiDHMkrjSJ3O+s9aA
         xPu2ktRmBYmVAZSNrjx/AnCNoYxWXZIUlDTGHeM27fGYbRTxkynfc7PA0fxusSNuyLkn
         0CqtbuwsvSn/QRx9X5znBijzrceVswK8VS1I9hAh4sjaXgg7sRSs2BxIW7pczlUx2Vl9
         PG/mSgqm3oczEvQzSW7Gt7d7RWYnWbN2LRy/9lEnHMDBQnkDWPydoR/G/v+beAnqEJeo
         S3Ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=MiZ6leJF9tYuSzVOQIulz0H4R7mIPrSUOEtllZRLwmQ=;
        b=aqKqvofKCrB2Kv5s7bxxh38FgTxCy+0TjkEN9efUFeyZiUXzAmbUILNkXsK+PPvILb
         c5zrglBWKH2ix/E7el6UyWTIJsmLQk4lEK+EqU9s0+G03lTX2+azGxinFtmNv18waFxB
         KzGG9tBgsN88lvIQa2FhY9JOtnjRKuEHs7OTaa7/ZXzNRJss0DdPq3EDEH+nJCUoKGWs
         0HO6ivbZoAmE2pKgR/jn7+586IHArIhHjESwIBCUbAC5Zt+DhBlG4vfI8pT9AAKKoq2m
         VXV3343OP3UbMQO3Z2UUEXj4kVmz2EqZdx7osCMZNZLmkaE42UtyRmGpr0PELHd2S6IE
         dUdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=GyJWAJ4X;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id q137si1013989pfc.4.2020.08.10.00.26.26
        for <kasan-dev@googlegroups.com>;
        Mon, 10 Aug 2020 00:26:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 3103f9590f114368a6175e1b069cbd80-20200810
X-UUID: 3103f9590f114368a6175e1b069cbd80-20200810
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 455172873; Mon, 10 Aug 2020 15:26:23 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 10 Aug 2020 15:26:22 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 10 Aug 2020 15:26:20 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH 3/5] lib/test_kasan.c: add timer test case
Date: Mon, 10 Aug 2020 15:26:20 +0800
Message-ID: <20200810072620.747-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=GyJWAJ4X;       spf=pass
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

Adds a test case to verify timer stack recording
and print the last timer stack in KASAN report.

The KASAN report was as follows(cleaned up slightly):

 BUG: KASAN: use-after-free in kasan_timer_uaf

 Freed by task 0:
  kasan_save_stack+0x24/0x50
  kasan_set_track+0x24/0x38
  kasan_set_free_info+0x20/0x40
  __kasan_slab_free+0x10c/0x170
  kasan_slab_free+0x10/0x18
  kfree+0x98/0x270
  kasan_timer_function+0x1c/0x28

 Last timer stack:
  kasan_save_stack+0x24/0x50
  kasan_record_tmr_stack+0xa8/0xb8
  init_timer_key+0xf0/0x248
  kasan_timer_uaf+0x5c/0xd8

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
---
 lib/test_kasan.c | 25 +++++++++++++++++++++++++
 1 file changed, 25 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 6e5fb05d42d8..2bd61674c7a3 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -821,6 +821,30 @@ static noinline void __init kasan_rcu_uaf(void)
 	call_rcu(&global_ptr->rcu, kasan_rcu_reclaim);
 }
 
+static noinline void __init kasan_timer_function(struct timer_list *timer)
+{
+	del_timer(timer);
+	kfree(timer);
+}
+
+static noinline void __init kasan_timer_uaf(void)
+{
+	struct timer_list *timer;
+
+	timer = kmalloc(sizeof(struct timer_list), GFP_KERNEL);
+	if (!timer) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	timer_setup(timer, kasan_timer_function, 0);
+	add_timer(timer);
+	msleep(100);
+
+	pr_info("use-after-free on timer\n");
+	((volatile struct timer_list *)timer)->expires;
+}
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -869,6 +893,7 @@ static int __init kmalloc_tests_init(void)
 	kmalloc_double_kzfree();
 	vmalloc_oob();
 	kasan_rcu_uaf();
+	kasan_timer_uaf();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200810072620.747-1-walter-zh.wu%40mediatek.com.

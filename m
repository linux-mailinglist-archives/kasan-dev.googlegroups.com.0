Return-Path: <kasan-dev+bncBDGPTM5BQUDRBIHNRX5AKGQEHGEJUOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 469C624F3B3
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 10:13:22 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id 129sf5568500pfv.6
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 01:13:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598256800; cv=pass;
        d=google.com; s=arc-20160816;
        b=vkSTRNAmr92W6JqbPI6qaMwXr9MoMZd3sUHvMsmybzZOM2qGhAU0xAg9nxHvR/ngvl
         VCWqf3SPdnGlYyQ5vBcxE72Z3HjVsYa1ye2pfmFUvoxpoBjf5zHWi95HA8LOCEzBS2wu
         QqXIK/LKmnnIpfjOfBL1vNBO6nSjKPJwSeEle0pRpZIYlpaTtM0uWAWU1aybOIefNJaM
         5VL0+iAc045clDp4qraTcC+J94ulYh+uD7CMSHlqQiiWB68SFZD3wQ/kOjPXevkmNad+
         4ZoTr5ez33ZwAcueQ2D3ZN7maNxnZyG8sHgJnCYl9/ydgAzd7nrSEIefI8S1ljj7wnr6
         Nfog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=L6/Hz6dGh9qmU/hon6gzoxGu+9RirxwJgfG73lsPRWI=;
        b=sfN7Z6D/KiS9Iuru3DmKlGA/RLc7o/RX4MYb5EBWqU65DbOR1HfflzfvjA2MPBKtJp
         OOqO2qkhGXgXcUiabt2mbNfqVxp8nqO8DzCHkLlVyAerJGcsUohiJ4GUgzvTpidtVyVx
         JbMkypEDh6FZgneWmgYvYq3L3CDtw7S+mYsEWFKXLC5kNz7Mwa+3VFsM+awLd2soQj0A
         j7vR3opN0NiZpzLKlNnbU1WPJbGUeTKQab1UpVmkIHAqwnbwEE7zPDqM5xf2Vve0+/0P
         TdOe9X5f2L3QOeHHARnXRrzITGpmdJKQ4xyZWYcaIGIcAcWnvsISYGgLFIAAKJRrA08l
         BuEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="rA/byCzr";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L6/Hz6dGh9qmU/hon6gzoxGu+9RirxwJgfG73lsPRWI=;
        b=sQeyyLUAJqElxhYb8TaW3w7NK1ECcoYhRRTYm1FQ3OXBLMSmFmiHpubvJ1Bg1jybZT
         11ahprgxgc2qMBfT/EP9xkNvgM/UNCGcySBtj2KKbJScMoMf/x5AAKQiPbNVhUsNafsf
         xeDWIClKEmvouVnVrDjHeaLJaTIVqIHT2IW7qvzjzAD6WUnlnPo4F55NwpdFpS4UFye3
         RlYm3xuS5mJy+soIuff9Ws1PU0QkiRb93XzZY4HEp3cCaKYOO98PUg7HA5g71N2H4cbA
         nXcDdkHcfJqGTf7HATEgRFRIaFDPiLwSOFmqq3VK7VXxI445AO8Qoi/aNzLvaXCaC6FO
         8I3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=L6/Hz6dGh9qmU/hon6gzoxGu+9RirxwJgfG73lsPRWI=;
        b=Zay6QO9E4elIbmKuHtpKyGFTDHUPWU0JD9oB7mZpzAyPXftxvpqcwzHnjW0+R6IO5N
         HvXx+Vni1TW2sPWl21m51pfq6oyNMOfguFy5UVz0gp3qYaTr2+0x8A2zqU6OidBhWp7n
         GIuTgVKG22iZR8n9hJ+jkajcNL4jOnWMI7A4GgLuNd6qHGMeWExNspK1ngiqHepN0Ung
         HK7XhMd8CLuqiF/zTw3y8G/N7SOg01y5d0LESRgH9pgsx6lnlGKQA/9IY8KZ0NoZ4GJE
         BBpsQjYtJVupu+vZJSkKze78L+sHblrgSv/ioaskAVOgpRiTnanPXlYelYawKvX4m40k
         WauA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533q1DlIuLlz/MHfXQi6l5vczh1uaSzvP0w9IGmxs7oOFmXmkeCh
	SyZoe6VPoRmTd8xAeFsPcgI=
X-Google-Smtp-Source: ABdhPJyK6TWUE/DXhgTGXVdaUPmPkP3Cs/kTmPdMR7CVCrJl1XNmXE9pYrcY5wrP9tKZEEjr1ALbHw==
X-Received: by 2002:a17:902:768b:: with SMTP id m11mr3098414pll.234.1598256800687;
        Mon, 24 Aug 2020 01:13:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:4ec4:: with SMTP id c187ls1390304pfb.7.gmail; Mon, 24
 Aug 2020 01:13:18 -0700 (PDT)
X-Received: by 2002:a62:838a:: with SMTP id h132mr3307818pfe.72.1598256798755;
        Mon, 24 Aug 2020 01:13:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598256798; cv=none;
        d=google.com; s=arc-20160816;
        b=Lyr/DjxfX35kOQMxwqQzmCYdzDM+agte9Yp89ydgCpLRMQ34aORWLNyiYy/WFrzSfO
         XlUKu47BwUE6pzGaT7B7bfRKqGbE/iQejXVSnLo35DxtC2g8vbXxOEQsHQuatlTq/dyW
         JuutZW8d5jqjYof9h42UYe5nrZLxJsRMQkgWJpMrUbMJUqEf6Mo+oD7Ijk1neWeGurVj
         3CiUNQP+PGs4IcyOSurqjChWe9vN0y6E/hUccP5rZ/zBDsRXkcbiuPlJlSAcakFigRdL
         ydTr2AHcUxGrbdKB/WuTum4qc8/DFBwQ8RZ8b2CZFmJZEBc88a8nUBB6cRo3DjnntZKM
         8tPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=epF31PMWeocflqrG14ZTfXrn/tbNID2roIzjg+E6Ras=;
        b=IUg9GfGhpGfqWoCcTH32xLuA66jPlK83zX5vla56prekmguktWVedSqkrRBFfcTEot
         ALU6UhZewwyfJ//OgGrywedL+61/Du8kvRMyoYvfT0T+2w1SwSv+y4z1oqFxF/SwMZ5v
         afXI1vSp709JsWyAjhc9TDUXAf4WEfX/9Q83AKm9HFPMdw1+1tu2u5kHXiZTzcXK/OTA
         LbnDMwSR5hlBDSWaOvemO8Hl/P499z71F1fWfYg4n5e3WO2YYi0Iywm8wWFDsWd84Wd0
         vC1b6kwzTfgPaeYGs4AgSvyGjvvi8sNIQ+E54vbNzMTqOKh1VtqkLZPlVW56b7TrdFIF
         XK7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="rA/byCzr";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id 129si219270pgf.2.2020.08.24.01.13.18
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Aug 2020 01:13:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 9c950f80946c46fbae63dea326b723a3-20200824
X-UUID: 9c950f80946c46fbae63dea326b723a3-20200824
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1057839245; Mon, 24 Aug 2020 16:13:16 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 24 Aug 2020 16:13:13 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 24 Aug 2020 16:13:13 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 4/6] kasan: add tests for timer stack recording
Date: Mon, 24 Aug 2020 16:13:12 +0800
Message-ID: <20200824081312.24972-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="rA/byCzr";       spf=pass
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

Adds a test to verify timer stack recording and print it
in KASAN report.

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
 
 Last potentially related work creation:
  kasan_save_stack+0x24/0x50
  kasan_record_tmr_stack+0xa8/0xb8
  init_timer_key+0xf0/0x248
  kasan_timer_uaf+0x5c/0xd8

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200824081312.24972-1-walter-zh.wu%40mediatek.com.

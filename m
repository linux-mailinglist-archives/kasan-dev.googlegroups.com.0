Return-Path: <kasan-dev+bncBDGPTM5BQUDRBRFWWD5QKGQEWKLBZFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D2AD276784
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 06:06:29 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id o18sf996193ilm.16
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Sep 2020 21:06:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600920388; cv=pass;
        d=google.com; s=arc-20160816;
        b=BJZWWilxN/iCWNsqa8CUwnU0zP6pXWy1n8sk5evK61Ag73AtsU7ETPz89qq+ZokyB/
         MD1HO+pyhGgI5DlQMqiYSIoUpNFZMr9Lo4eGO+KMX3cEkXCmQGJp4Gb2c1HCFE2RLfl9
         4MCfymH/cAQzm8GJQ7ZLiQjfFXP8FB8gYsGApWPNliRHuQORb3b07S8KJEOEg+hZ9X6Y
         4RstnFOrud6obgKxiZnwq7T0/NRgqK3ZAEI4MGwiwaILVhd4rEkF+KsW3RgzkBlpMjH4
         AQ7I5Jn1fCidRlpQi7EzrUGBlt5YQoda51qxlNZHA3WYDdsYYU6PbhyC5Jt4UCyld8Av
         svKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=FbqZQIr72+Sqg6W9G4us2VeN/nUp8/mccZrjFxVpoCc=;
        b=ebI3RH3Tb6U9NA5hzFlVZ8t1s3gKW0vrS4b0XxuOlfQKZBy9nr0aquivqcZewVyD/z
         tVDd+dSQ8cKnZNJSTd7FIxg00y12liJcNNcQI4uTAWpmA2zvZN8kn1cRRRAfK5jiqWFL
         HxM4ZgiwQG4mUbFxgjFXg5Lk7oxncjL4oFLE/jUwihsWw6SukDCysIb4+H4G4LvT0nEB
         2+xGQ5tI6icgJDEnunBh6/ZqUMgSkvSKJZHsk9I9XMu+ibSM8LMtrQoQhZIIpOfZdkhw
         /Q8pUWmxIMllbA78mizKT73ra5QlBYE/EW92ssdbJM4e7isE+eXPrOEY06TZ4bGq59Rl
         853Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=BU628Vj8;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FbqZQIr72+Sqg6W9G4us2VeN/nUp8/mccZrjFxVpoCc=;
        b=T33DPJCNEwfhC/VfduCgd2bsmnghpMzwzYOOhlQoC7i96GbM+EZEpCNZZ9HuLt64RT
         mjxZB212fjWzYtAB9HlLIfDaV9GGB4x37zllBn7ufzGuhu7eyn/hg3ppH/garAz7ISd8
         wwHaUQVCsbvEEsJbk7xgknFkWTUksclOs8ltsTB0+K+rbinOahV2kuu+2QJ6if0hrlcx
         klZr8CEHAzfQjbheiIDN1ogcni+/8zjbXLOhy0sPbK+dh+D6yzJRYNinsSNkr/XIyj9n
         tqHHCWeOPgdDN7a7PYU33xTErUI/7w7hMjWwsUXPuDTB40CKpIf+njoPAik7r/9hWx1b
         m8Qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FbqZQIr72+Sqg6W9G4us2VeN/nUp8/mccZrjFxVpoCc=;
        b=pxm48N1m4k2CLFfc1cgVYxuy2QyyS8RFJIwRNNpsn6rUno+GH2xSRJtF0JoZAPBxUl
         a6ULI1TItCcCNtc7D6btz8icZyE9Fs/fyRD9JRlNIw0cbjx+U3shVSol3j5BbLgCgcTQ
         LZn/7fsS5yxLrGM2oyH1Vs7kCBLf2ihCaTZYy1Ek4oA3hRNugPpoMliH+TnQZ/yoMP19
         8AQnCTwt1ckgm6h2jUlQxcAx76Uvf1deCaO4NW+Qq1ZpGnmuX9w92eBDbKDfdfyOHb/6
         xQeFtGD2H+2oMJOjnYd8IuhVDpy2J0Y46ZtB1c1px5mFd/wzZ18/rb2eajt8xG8Yv8I5
         5ubA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531CF508gi3yTJJZ9emJtU9bRKg+ruAQJ7olXUH72RpDjXNb8+Jv
	EZWhsv5WchrDC5QGBCdA6Y4=
X-Google-Smtp-Source: ABdhPJwokHg48MEZ7Qom62ulZHFV2z09gTRzmMVabU2cjWihOEugvg5vWLh82jTNgv2Jy6g3YmkQLw==
X-Received: by 2002:a05:6e02:e87:: with SMTP id t7mr2501610ilj.261.1600920388204;
        Wed, 23 Sep 2020 21:06:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:b603:: with SMTP id h3ls241032jam.4.gmail; Wed, 23 Sep
 2020 21:06:27 -0700 (PDT)
X-Received: by 2002:a02:9986:: with SMTP id a6mr2240192jal.28.1600920387736;
        Wed, 23 Sep 2020 21:06:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600920387; cv=none;
        d=google.com; s=arc-20160816;
        b=muqYUpUz8veZamIZhuX5A35HuTRTB5TDGm9UuggUgtqunNtbJD+o7YLOGMJqrhbjPR
         LT1flu918UgPMUSdy33ArcqIwDPagc79tQUYnZLvA0oNHcfnjhTuLA0fZ00+llXkv5Nv
         S3PiZ/vESMQYfP6gmC9FaoVNOtfqx818sYlkvhjmYQ98hnA4WuwVqOIq1VpPR7QxazDs
         Lx4tf1/7ofVXQ/9mQg7IIBYY3c42rRkYT3cJUgQiOuG2Y36uagg9P2iRk/VcFY8bBdek
         FugwOSW1rGIKc3O22STdJ5l8WPqrT1zc8WpBbkLlq5tIeMe62K3THO0Geno1uFHooFSF
         gwpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=IVo58NkQ33GGKE0b3jzyWWKlUmdeJt6uk543PzI5rcE=;
        b=Y7FiXG5Q9GPRc25KC/UU4c9eOb+6A05b+iOFtx51DTkSylTHRgj+wAvm6CZtMGOxi3
         /EnB95lY0pkcDZSSJJSpKYtWpOvzVEz2s9UdstIIZ/ekBsU3M1v7qIyZjKN47HTId33m
         ynOuZFhC5VyqhwfbdAbc4Up+iWkvfjAPmIDsNod3HFjBE74uUaiMF8KR+0NfXzrf5XYT
         TisPEq7Pl1Mb4CT8ZgMUJDMA0sG0m16KK45Y9PEoaDccYHoA8mCNXjju8tghwyg0LGIv
         9/+mda1fSmxtDoKUZbbZsLenO7XvqNDIVSgkZrqa9mgYzaIsguNU7nhHQPgnQ/ui8ukm
         ieVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=BU628Vj8;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id b12si50784iow.0.2020.09.23.21.06.27
        for <kasan-dev@googlegroups.com>;
        Wed, 23 Sep 2020 21:06:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 888a959d97b549a499044dc089591337-20200924
X-UUID: 888a959d97b549a499044dc089591337-20200924
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1807994880; Thu, 24 Sep 2020 12:06:23 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 24 Sep 2020 12:06:22 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 24 Sep 2020 12:06:21 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
	<andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: PATCH v4 5/6] kasan: add tests for workqueue stack recording
Date: Thu, 24 Sep 2020 12:06:21 +0800
Message-ID: <20200924040621.31164-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=BU628Vj8;       spf=pass
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
Acked-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
---

v4:
- testcase has merge conflict, so that rebase onto the KASAN-KUNIT

---
 lib/test_kasan_module.c | 30 ++++++++++++++++++++++++++++++
 1 file changed, 30 insertions(+)

diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
index 2e5e7be96955..c3a2d113e757 100644
--- a/lib/test_kasan_module.c
+++ b/lib/test_kasan_module.c
@@ -115,6 +115,35 @@ static noinline void __init kasan_timer_uaf(void)
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
 static int __init test_kasan_module_init(void)
 {
 	/*
@@ -126,6 +155,7 @@ static int __init test_kasan_module_init(void)
 	copy_user_test();
 	kasan_rcu_uaf();
 	kasan_timer_uaf();
+	kasan_workqueue_uaf();
 
 	kasan_restore_multi_shot(multishot);
 	return -EAGAIN;
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200924040621.31164-1-walter-zh.wu%40mediatek.com.

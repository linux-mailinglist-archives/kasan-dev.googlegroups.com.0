Return-Path: <kasan-dev+bncBDGPTM5BQUDRBP7MRX5AKGQEYW5KVAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A01D24F3AD
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 10:11:44 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id o18sf293055ioa.21
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 01:11:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598256703; cv=pass;
        d=google.com; s=arc-20160816;
        b=P7pz/dqacJaWtY95Dcf6JbJjHrXlrlU8EBcgvGHRjfnZXQChFN/PcpfzTa38fCEz16
         PVNtEyNsBxSIGT+PRgtw1ywrEob1lyyrEmsLS45NTqLbP4LE7CX2ZKtjyMTSGoI9eJNn
         SYgRIRfmBXuL5vNPg4Xy0V0ugV+bzABt34PgFUFM6vd+YdsOB1ysTrOKS6BpglsthSEk
         CcgC2wFjR84a0Z8Z5xa7CtOpFopueC5Ha8ycIUPhreUch/9GUmqV7bG7LrKxmEBKYYWX
         xD76EZN8f2a21Po1jttlaTNCkuW6A+AJ4BbrZC1job2GbWf3L6CZJ1fla3Q07yM9FTFf
         0LsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=KulH1U4vPOjNsa35Ovg+gEYDusQvM2fZnhd0DdDZiFw=;
        b=theYP/XPnUC7TZkYRBh7AvZRVtDV8Jp8M+3CvTgd2HthFuPl+MMocGzDBUJciRE+Ka
         Y8SfRM88uygJZoWc2dXbX22QmuRW2I40onz9+ZIBJf48m5sPw4CMAadRwKfRimMw+VS0
         3mXKVA6ynNTnZYH9E7n8TBBr0ep+zvRaCAh7kOozC30zmhGHKLalqUKE7LN2Ccr8MiiO
         Y0ewo9UzWf8zu1vd5AgtzUC97kweNvCTCn01KCF46XI5ov7n4mYnOSQzuvqCI7+ehiMH
         nyZzInsr8FhgY0JMEOf27wVHqyKoxji3n0eb2o5xMEf+3ilUcif5C4zUmeBZXKOWq/ug
         7kPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=mxlEXcwl;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KulH1U4vPOjNsa35Ovg+gEYDusQvM2fZnhd0DdDZiFw=;
        b=JC4PYYVGLhpLr/k0RKyVdD2Ebmi71jVyeRKm2ZU8TrGmOOLzolP0lJrh7xUUivYJpE
         RGbNfJ8ZjZ2P00gEPgaTGkv3vZtnW3RI6mvHqCLUbM5zHynoyEr3CS6cQ6p+snHn7fND
         hNoMwr3Tktym/OXB3h3wgXZVnR9aSnjE7ExHc74PKza3iNRMR7ovdmGUHgmOcO1ARhNm
         gf4VFmIr0C6EplAQnd9Dj7yCzpQO0KaMlKr/KRbt/XuOPZJPtHzhofjnb9b5daGpEEKd
         e/gTZZUsWyPAfgZA6VpBaadfkGNHH0wSFc4jwlqK5AYGjTInZDeqwhfzTwYwf0tbbs0T
         ekXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KulH1U4vPOjNsa35Ovg+gEYDusQvM2fZnhd0DdDZiFw=;
        b=aZbgtHeLS6IBT9pmYTru1rSi3lb2xiPl+Jx1/7XbKeJLklbTPYi0asnpyB+tXRgpI2
         KoMQVQhTI5JP3XH+s3FOfLFrFZTAkv6+1h7WzD99M/jHm6SPjWglC43kTLLn6MVkdAtE
         YP9oyLkkH0GhYZm+AoLge0dEL1ooBllZWUBreG0Iyu9aDDSPRHqH03cCHA1zA53cNOi6
         fRoefo6zmE8zWCO9LZH1myZwlb/88mVMgZU4HPtPt99mIzfxoZxUgKVjbvoSHtogK1OG
         rEEOoxqHLz3ILBaZnt5szRJi/gc2bfl5MbCpj7MD8m7chOsTQ47QMjrgJ/Bbqn6KERoo
         v0Qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wHdQAtYUarUZANi3xLpA3aSoFAyilSfAAzwCWgRH/SePdeEO4
	hQtBSu7Vucbsbl7TNPqW5ww=
X-Google-Smtp-Source: ABdhPJyHuSUreDjFIDVhtISEUUprV3+qtT1vXuWb52dR7wIGZlw5p8lrW23n1p9cXdEBQvhjm/8W1Q==
X-Received: by 2002:a05:6e02:de5:: with SMTP id m5mr3882869ilj.85.1598256703428;
        Mon, 24 Aug 2020 01:11:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d18d:: with SMTP id z13ls1083544ilz.4.gmail; Mon, 24 Aug
 2020 01:11:43 -0700 (PDT)
X-Received: by 2002:a92:bad5:: with SMTP id t82mr3988674ill.22.1598256703134;
        Mon, 24 Aug 2020 01:11:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598256703; cv=none;
        d=google.com; s=arc-20160816;
        b=gZCnybysr0DPbsXPEZcZ3N05r6eeya1Ctving/FFvkf8KlhB4NSZhg+smkijH9nOLL
         8GffuL3Hg84dSIZRoQnDPIUCEQ4zf2cCZXaK1y/Uv6IdKmUhLrJRlD1gvlmNANLzgv1V
         SGc3wMphqnjqOq+LGs8kCGqQ4CiV63vPEz38zwTdHUnlvDQiTT+0S/VziL7jgVZICrko
         yym280Y9peEmh9zuElJjgzuHRaXIGk0gykXKmp2VKpdVx6sJjyMNJKOsUhDEUzO+XmHQ
         ghpKFvgvcPFCR8sXgwDK9Sy6lKRlJDEgVLyXXW0T3MnT/zt/VkTUgNoxz7UCVghhJ4yE
         hB3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=QjiWiguuQ5aBJrBkNVTbpiMEZNHatuVj+uLpNS9djNY=;
        b=Pst5quX5Yv/+ckuxhD0mEB/nFvFH8LQDWzLZ1G2wBGfKbCYjnnDN1EtKTFQRRrNsRZ
         GwPaW7VjN+hJVyHsqWIFkDtY8vUZS1UNpYCaYu2jJsG2pqhTgexx11+IYax0+RGLacQf
         yD9WgVulbUOunixvxwiHC0q++YbXG1d6xroJ2uP9MkmVY6WpLgECjhlWT8AKOdtsYf4h
         qzxW/8giJdBbSf7oxdiQ51w4pMCXbyeJqksUNgzkQLgymH3zs4dkM/s5Be68heDXbBS9
         +oiXqlm+NC+icokD3WOdu0OLhF0Cf+/Y+8aZ+puYVCd9SLGbxrDd8DwmRVLhs/FuQuQg
         edkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=mxlEXcwl;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id y21si399887ior.2.2020.08.24.01.11.42
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Aug 2020 01:11:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: b5572d05064548b889a8982518a003d1-20200824
X-UUID: b5572d05064548b889a8982518a003d1-20200824
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1824185160; Mon, 24 Aug 2020 16:11:40 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs06n2.mediatek.inc (172.21.101.130) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 24 Aug 2020 16:11:39 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 24 Aug 2020 16:11:37 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Marco Elver <elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>, Andrew Morton
	<akpm@linux-foundation.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
	<jiangshanlai@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v2 2/6] workqueue: kasan: record workqueue stack
Date: Mon, 24 Aug 2020 16:11:36 +0800
Message-ID: <20200824081137.24868-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: D0B37EE3B138F4637CDEA086AC379B046EFA71CCCB3AF00EA178387DE11421E22000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=mxlEXcwl;       spf=pass
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

Records the last two enqueuing work call stacks in order to print them
in KASAN report. It is useful for programmers to solve use-after-free
or double-free memory workqueue issue.

For workqueue it has turned out to be useful to record the enqueuing
work call stacks. Because user can see KASAN report to determine
whether it is root cause. They don't need to enable debugobjects,
but they have a chance to find out the root cause.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Tejun Heo <tj@kernel.org>
Cc: Lai Jiangshan <jiangshanlai@gmail.com>
---

v2:
- Thanks for Marco suggestion.
- Remove unnecessary code
- reuse kasan_record_aux_stack() and aux_stack
  to record timer and workqueue stack

---

 kernel/workqueue.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/workqueue.c b/kernel/workqueue.c
index c41c3c17b86a..5fea7dc9180f 100644
--- a/kernel/workqueue.c
+++ b/kernel/workqueue.c
@@ -1324,6 +1324,9 @@ static void insert_work(struct pool_workqueue *pwq, struct work_struct *work,
 {
 	struct worker_pool *pool = pwq->pool;
 
+	/* record the work call stack in order to print it in KASAN reports */
+	kasan_record_aux_stack(work);
+
 	/* we own @work, set data and link */
 	set_work_pwq(work, pwq, extra_flags);
 	list_add_tail(&work->entry, head);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200824081137.24868-1-walter-zh.wu%40mediatek.com.

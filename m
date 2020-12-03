Return-Path: <kasan-dev+bncBDGPTM5BQUDRBKU2UH7AKGQEVJJQHCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C1F2D2CCC9B
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 03:27:55 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id e11sf472454qvu.18
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Dec 2020 18:27:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606962475; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hfg5FX5hVFo+y9ZTsumr7i+XDAtzQW1+ARY1lrn3CyW+PUONGFMuNwaMX5hBhF7Kc1
         3FgmGM3GSx3bREFtGe6lw9hFC5IOd7dAfXXgIngbnvuiwS4FFe1k760pM38xQTlds9Eh
         h5mmm4ibXHD1d5gJIyPrmzj6LtLgyMzp0XgTSaQpCAT4RQDKfRy2pPhmOfrpwmX07saq
         LtX4jP+VwcB370r6Yhuw6EiyRC2eZ9cR0XzKJXAF5j8jPH5auLBGDk9Vcl1C5PnGh16A
         AiQo7kxW7AaVmnuq9B2vE3Vzguz0FpjITgT3nX5ebRGK6IIpoWlDLWD4L5mi5RnN+Hw8
         A0Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=gSMm+25iK3jNqWXv28i5PQyg4qOd+mvJf2XR9hnXqDI=;
        b=X8slDr1BamncY4uFKa+40GcTetscaqbC3ZyOYHwRp1RPelAC/CcJGNefe7wBFaFKeI
         ziWtYFimWlF1RyKADGdbwtRGqmdos/+KHlNz60SUGtxGMkuH9gLTaBj8SPKtzowMjmhH
         ifqcKrKzwLV+oN3ogXw8n1ISU99zOra/LPpKtBj8mPB+t6WeRDtKInTpbhPbk/Mf8EZO
         ShU47n56du/3TJo9qzZ7yo+O+L+9JvENuazai1WiNjkXp0W9Dr8naJ1n2/x1eVpSkLX3
         pOTWrKnKeDkM3cEMW66hqXB0f/dDfedBfsIoYHrQ+0hUQ4VDdGPZDvlh4GdrD/1iulHl
         MI4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gSMm+25iK3jNqWXv28i5PQyg4qOd+mvJf2XR9hnXqDI=;
        b=aQtJY3lHDF9TVxcgzigB0cD5S8ooSXvstNgedO7mjB7yA3Dd7DR4Cmm11NBpGMItBm
         HE9omOeu4URil5JoyEu6WZU371Ei/TJ+nvU9YEdU2ePIYNw1hJsgeWlKg65IUXaeBE1n
         sinOOZqvJIbQbr48igfxm4775p3Xqkne4xUc4+54m1+GDvQYRVvOoByNNR3bQ4fu4sZZ
         DiKTNsrG0UDyswV6v1WQ/fmIrCoR3ZGduD7uTNEBWoYPwYKixx14K0rafHt92gHy8y5B
         3k4U0jOm+Qk2mNFGSVdI5BbVQXD5AbQKhcZBjr9NhjhTRloBL/98kDI9xECLQ8hLvm5d
         k/cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gSMm+25iK3jNqWXv28i5PQyg4qOd+mvJf2XR9hnXqDI=;
        b=PwE7Hjz+EDJdqFmAS7RzETBZfcJoHxA+SeAj9mL6BCInXoOeje/RofHdae2M3NDlTc
         zfwEmKLz+/ZWLwHjX2KQWO5n4jezDRg6DvJ8nhrlSCwgz6N4Vc3+lqMg7D92PwJ8Bujp
         K/n9afzLpYBaIJmgvp3Q/d49/OTE69sOpI7ds4T6qgiRgAiWma/wIWB8DaCxVIZbzPek
         TTGPPgY5rzjAjGZF4Yl7S1MBMRTLabV1YNOvzsKGQXFahEAYf4pjvZhHvT9eJL+Q+mFM
         xLN+KKZhpax7mRSUc++WCEhR+m82/qYMTEwfuOHWy+DdXPrmcP5phNXgoOKZ4Dpde4LQ
         lUDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531WI4jzunT4p3jMDpy2fjZZ08q1EdQfGecMGPsVFL1rE61grKk3
	uixzs4HH1A8+FAcqMJX3Dz4=
X-Google-Smtp-Source: ABdhPJya+oiAp6MiDmU+czusTer5xR+a726VejE0LvdJjXZUP3WH7E8msYNgsP7XZZE/cbQVcLkPJg==
X-Received: by 2002:ac8:60ca:: with SMTP id i10mr1244257qtm.195.1606962474900;
        Wed, 02 Dec 2020 18:27:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7dc5:: with SMTP id y188ls1787506qkc.6.gmail; Wed, 02
 Dec 2020 18:27:54 -0800 (PST)
X-Received: by 2002:a05:620a:622:: with SMTP id 2mr892453qkv.436.1606962474457;
        Wed, 02 Dec 2020 18:27:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606962474; cv=none;
        d=google.com; s=arc-20160816;
        b=CcY5KV2A4n6rJMg6nH3CP3EZijD2+CFi2MngbMlV4npEctEjxll+ucUfaMiDgTwsGo
         Xl3qMNliWeFORjHeUwH54ncgiE4iggjKz6VIyAohphHbGpWc6GtTjVXUroP0GaJ0zDS8
         Jgywt3edlorhbIBK7RpxW9SKVJDocagtHEfnYhYQoy5QI6gCr2Ii7qrfr79bguDDisfe
         OJmjld4EmSlhzWPOq1U7lUPb50N9zHFARlpOscb1Kr6HrzClTxhKykyb5svla1Ku/YVC
         V1yIoNZTy9pRE0T7L7T2yg1VKrkPHzXPsY1TXrw27POyb2F0Lg7TZkdQ3qsxZnHX/icc
         mSpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=nJws5cOrux4qoa6rTbzVJ+Li+KylYzsSbjETzC/4mfY=;
        b=hujv4NzDLatDZLbkjmZZavca6VMPy9ciFZ9PFdhJ0UIEW2bc47GXXq0CulPgE6dzaP
         sUyD4Re2EvJKdm28tgoOQtJ6Ne1lVyG3cv7n8uUVu9/WaJpCIfg4tiGfos3bHRKpRjB2
         9VrCS/vNa6NTxUoMHqYRIYgje6TaMIjEo7tyhn4HCje0ItUZUTmEHeEf+TJN6p289/zL
         RoVd1DMM0iNDcWuH911UXg0AGlnW7GY9H9mBfcvDvLREBjmJU312uEgiHC4B2673C+ST
         0XIu4PrUvuNTaJjkmwSBaiN9/KtJTjDThXjmOXYIBcQMWlgYopqWXCiC4/O6pHnUpmZz
         fsLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id f21si36666qtx.5.2020.12.02.18.27.53
        for <kasan-dev@googlegroups.com>;
        Wed, 02 Dec 2020 18:27:54 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 5a3d1b56714f4046bd72a8c5bb642daa-20201203
X-UUID: 5a3d1b56714f4046bd72a8c5bb642daa-20201203
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1617248778; Thu, 03 Dec 2020 10:27:50 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 3 Dec 2020 10:27:48 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 3 Dec 2020 10:27:49 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
	<andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v5 3/4] lib/test_kasan.c: add workqueue test case
Date: Thu, 3 Dec 2020 10:27:48 +0800
Message-ID: <20201203022748.30681-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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
 lib/test_kasan_module.c | 29 +++++++++++++++++++++++++++++
 1 file changed, 29 insertions(+)

diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
index 2d68db6ae67b..62a87854b120 100644
--- a/lib/test_kasan_module.c
+++ b/lib/test_kasan_module.c
@@ -91,6 +91,34 @@ static noinline void __init kasan_rcu_uaf(void)
 	call_rcu(&global_rcu_ptr->rcu, kasan_rcu_reclaim);
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
 
 static int __init test_kasan_module_init(void)
 {
@@ -102,6 +130,7 @@ static int __init test_kasan_module_init(void)
 
 	copy_user_test();
 	kasan_rcu_uaf();
+	kasan_workqueue_uaf();
 
 	kasan_restore_multi_shot(multishot);
 	return -EAGAIN;
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201203022748.30681-1-walter-zh.wu%40mediatek.com.

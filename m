Return-Path: <kasan-dev+bncBDGPTM5BQUDRBAOXRD3AKGQEBY5OIHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id C05E71D70FD
	for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 08:30:26 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id x20sf5216162ilj.22
        for <lists+kasan-dev@lfdr.de>; Sun, 17 May 2020 23:30:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589783425; cv=pass;
        d=google.com; s=arc-20160816;
        b=cp66l53mS56btaNo50UMWeW6uv43wj6GN0nPpb+nis8OgPUnh4f6tQT3Yrn9YaydaD
         ScFI+qIa7U1xQ+XXE9YooHbPZzK//XdlPwSPqk4UY1IQnZXVVsMyLVwkItRFBfdc5IoA
         Pq5s0DCA0uA27mGTYPxmOcUXOakYiNJHEKut239T8xqAamHZed9N8sH1d80R264bnxLZ
         rOjNgjTdWlHccQa/+LDW8+C0IoW9vLWCm2jyQcB+Kq+Q4NqTk8d34cz8ciQuqMeZ1q6u
         gLHhhkuY26XmJTWsZAkHPIfiaHJMOsm44E344X6VA7zNWz0oumt+td9sDCR6/wioiUZM
         oiPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=E3c4ar1dxbyFdqj6axMPzpbsDl3WXUlkrRoM3yNCCZw=;
        b=Uxjuc51/xPc/UO/ZeC20vhs+t6pPJOwDklmtem4Z5D5Err3ggQU6wPGm+p1rofCE/d
         1ynKx3yVZboXToHlyiDyAbmNCVzK2foa3y/RgLwqj2rlzeXNG/GELbBN/nLP4FhSjaDZ
         jQ+xbkzbuhIYhfJOaizcWPLMgV5rkkBYlu3EzqbJiPU+yhMcgFYgDK5ipzyDuMN7ESSb
         Js0lEOHcnK2pqaU0ve0HCbND3ulMhfU+0B0T/7E9Uyj55TNokcbecIqE3JsxuZD3tJrs
         l1urPnSItyn8ZT5dLGQF2r+snse0MBH+OR/1L1JcmcOXJaL8ADy12kUKnBRUgXb2MNAv
         PVZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Zw4ceQI4;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E3c4ar1dxbyFdqj6axMPzpbsDl3WXUlkrRoM3yNCCZw=;
        b=MEOMIVtXuUOQVm+eA9J+3hce9hV8SSAnlF0XhtTRF2lDT4MGXUnnSTYLPZrKSxCM9E
         fmfI8+r8UuynO6jNWa+8pGfWTX+yn5adRo0CvihpVVbfEC9YBkG7U/dhe75QvZJsFRo6
         7+Wzm/B/op1Qqwr8Hjepksk28T0iVjxKzLpqUfa4h29kVH/CbmngVvDe7fkcLuDxuKYX
         f6PlbdngY5V0azRVecq+/ZaH4DKHNT5B3r+2ctvM4j51aWd+7961LyZtgiYyIRN97xpY
         3vctm3jfMFeJqqMiNd9TQWRAHK8mqZvWtBsA2Xn+cCT0nB4pdrCL+egdnr6ieoXCUWaI
         CVuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=E3c4ar1dxbyFdqj6axMPzpbsDl3WXUlkrRoM3yNCCZw=;
        b=lfPsigt8qbDb0+nVoC/twZtBDEI4ywBUYYo7zJaxlM9Sl54r8FQcCsQ34hLU9yVRVC
         RxARD5QCOf6sPi/R8V9kdp0X+pFOfV+7Kb8yjd8eQWbS8+n3aesBA1UnzR9/tq/AYxFL
         CwVGGQKgRFsWOkm0WOxOQQ9/TG8vdeqPB38eqUlXSba4fbendvWkzjAACy3rgkgZIEYr
         4Xp1YLh2Vi0ejziHP/YhBLbXUnGW1pKB5bTY9KPfPBBznYLAHdI61peTk9sKU2SDOLfA
         5Pk+Ju7XAEP/o4IpuKAQGsZ/U18L+O4+R3ZfR9QRmPwuOM0sia9nylJimJ7N5+sWFocW
         Vaog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532bNYYx6cUk4tjqFsepSm0aF6yLRet/vIDOCMbWCzOMqvoTM4cV
	GVePxBNJe9rU7tybNQZYGb4=
X-Google-Smtp-Source: ABdhPJywjh6DkibVCpKl8K5iFGM2kYwiUKnffAlLM6IyzJCTPicgqeGo1x2QZEd23rDVLBop5wRl+w==
X-Received: by 2002:a92:b001:: with SMTP id x1mr4600319ilh.18.1589783425524;
        Sun, 17 May 2020 23:30:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5b8c:: with SMTP id c12ls2300420ilg.5.gmail; Sun, 17 May
 2020 23:30:25 -0700 (PDT)
X-Received: by 2002:a92:ba05:: with SMTP id o5mr8142124ili.263.1589783425283;
        Sun, 17 May 2020 23:30:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589783425; cv=none;
        d=google.com; s=arc-20160816;
        b=uukkAsbQlmaYWjmzQMW8O3OL0x14P6GrqfqtUj+todbtkeXvUCPatxTBZkJnnALONa
         8mRMosgoTvCtnT7OZq5+MbTzZt3ya62wat+WrSqy8htSARcfdtoosPQd86nQ+m1RTl7a
         9+PagqKAyfv/Knn8Tw9RYOIIey6lONqCWVFsRDfwg13mKqn3bN22Mi5jXfK6jZdhsRQf
         Z51dkymprXcjGQRkQzn9933XYn236WIdWsK0mVUCzqZ5ixFj1KUwS+DMghtSE8Jjq4Cs
         VDAbpQ5T358C1Ry1iatSmvYZayF697AyzqIs5fjoFIEZ5l5GwPmZ7j7wCE64hfgdYLEZ
         bvYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=YlRyO64pnH8FZf+sdaf75snQYwi8eIDYf2MbHf8zjzk=;
        b=X+qxSjiBM6WkTRbaRm15rUxysJITjfx+vwDMTy8eGp4jgI4rdnFuUqJYpewcyXCZuW
         8f1rwbgFJ/QbJj6poSmllrQhed5uxUGI6z/uNXPQatsoXOBE4Eu/YAq/g4zSAcqRJFod
         T4yoqEhqOIv1SAwH++YcIR6yvdNT9qnAkG15c3LvHblFCGEfmkTEGa36gJFI7Z7Z5f7z
         WwE9WDuR/TJ8yWyt7U4QAFFNHAKpimhyOevZmaVVwTJrt4PWlZiHlz+Yp7Izys3taUmY
         YlLpecR8Dakf/fJroK5GxK2UVUbiUCgOZczj7NA6qYK9Y2mvQtmrC8tWiTbsfyP1RfZb
         N9vA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Zw4ceQI4;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id g5si544873ioq.3.2020.05.17.23.30.24
        for <kasan-dev@googlegroups.com>;
        Sun, 17 May 2020 23:30:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 2489c0d6f6b64d0d9a8fce8d153f77fe-20200518
X-UUID: 2489c0d6f6b64d0d9a8fce8d153f77fe-20200518
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 482467777; Mon, 18 May 2020 14:30:20 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 18 May 2020 14:30:19 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 18 May 2020 14:30:17 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v3 3/4] kasan: add tests for call_rcu stack recording
Date: Mon, 18 May 2020 14:30:17 +0800
Message-ID: <20200518063017.4766-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=Zw4ceQI4;       spf=pass
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

Test call_rcu() call stack recording whether it correctly is printed
in KASAN report.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
---
 lib/test_kasan.c | 30 ++++++++++++++++++++++++++++++
 1 file changed, 30 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e3087d90e00d..0e9ff02f0a8b 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -792,6 +792,35 @@ static noinline void __init vmalloc_oob(void)
 static void __init vmalloc_oob(void) {}
 #endif
 
+static struct kasan_rcu_info {
+	int i;
+	struct rcu_head rcu;
+} *global_ptr;
+
+static noinline void __init kasan_rcu_reclaim(struct rcu_head *rp)
+{
+	struct kasan_rcu_info *fp = container_of(rp,
+						struct kasan_rcu_info, rcu);
+
+	kfree(fp);
+	fp->i = 1;
+}
+
+static noinline void __init kasan_rcu_uaf(void)
+{
+	struct kasan_rcu_info *ptr;
+
+	pr_info("use-after-free in kasan_rcu_reclaim\n");
+	ptr = kmalloc(sizeof(struct kasan_rcu_info), GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	global_ptr = rcu_dereference_protected(ptr, NULL);
+	call_rcu(&global_ptr->rcu, kasan_rcu_reclaim);
+}
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -839,6 +868,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_bitops();
 	kmalloc_double_kzfree();
 	vmalloc_oob();
+	kasan_rcu_uaf();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200518063017.4766-1-walter-zh.wu%40mediatek.com.

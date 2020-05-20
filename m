Return-Path: <kasan-dev+bncBDGPTM5BQUDRBMWJST3AKGQEASMIZXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id ACEF51DB3B2
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 14:38:11 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id z2sf2359371pfz.13
        for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 05:38:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589978290; cv=pass;
        d=google.com; s=arc-20160816;
        b=YDcyolCFMn/lbpgk1QHaSnudt8oyZ161CWaiUYQ8IFYrVYuSTeNZhUnpgutfgkmbzi
         HelXGRipcLGLe1WOLt/ntMNQr4AHgYbApJoxWSbPIdniA6nP3e8kHQlyN/v3QM/Q4GQN
         H+8jhHkTJK6rp4OZj+3ZuYqNvtJN4xM6yfU0v65kBydye0ZEZeHgYMIqh0TuF+6lBrdg
         K6CJOA7VXu5FtRE1Zfj/btM+oEfigrswKdE7Wvb+TU6MIUOt2StzsyzmFZ4iHzwscWQ0
         Tkt+aEqj8L7aPqGhOclR24bgmqrJCPMjrKhuJF5YcgXLC7YPJgjYVtjieUQReD+9VlFT
         ipyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=M/DcUGyxD3iAxg7MB9I876xmoGPgVNiuvvLy+NMx5is=;
        b=yDThauo/cgtd2b0aILIIlJBgUBFYWh5O1O7ZkEeI6Fajq1n5xfjXsLaVcDh4sy6lle
         dMAUjh7MwqHkkItjETtR17/2V4tlYgwTbC4CcHLinHE/9jILHeyoUTp5GgT4mt9pgJ29
         HA6qOe7Qkc2XjiRUiIWZm71bORZtlX4sZ9J4gGZkUwjyF2JxtR3761vtdfG2ZuOkBctZ
         6z/ZAFi4z3AEexusY5iUkmVBiL60Unfoa0zH0G1yPo/uyevfAa3G9e9fhS915Wi2DsI9
         8v9QeTQUH3srzsVTBV3qIST1aYCBoFmuPgmmFDDxue7A7AMHDsXo2BDsLJR1mljltpJ6
         FCtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=hwtd7E49;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M/DcUGyxD3iAxg7MB9I876xmoGPgVNiuvvLy+NMx5is=;
        b=dlgsU/K4maF+YFFHC843sXp+owQ5scG9L8k21jj7mB8h4EPwkrDKv4gf/phpZYgAEa
         op5Kxc/XLMEAJGHkVQaafPBhVGSGC8EAhwMjFS4D61PL+UFANZhgpBLWgpIp1TM2MjJh
         DCr6KqL5YgLcoSqtkGiYzinAwm/SsCcb39Arf3qx69fxLSw9Z/eekAIWpbG9aRhkjooE
         m4E4hCBHJBMlwwg2D+S3N90wB36CCp9iCq9ReI56wUODffNkQFsrIECLI3BZpionT8v0
         2Xd5YuaU55c2Tk7OPjMICSa6T5YlQVSsFdGn8owsGIa4n+YuVNOWQPmIy2JsaASY1D6S
         ZZYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=M/DcUGyxD3iAxg7MB9I876xmoGPgVNiuvvLy+NMx5is=;
        b=L/BStcRUI1gnrmg0fFo2/UgwwmH5e9H4/ePS+VYAneeLy/MyMG4eRGnBOFNwSx0AF8
         8MYI3W59CMXidSbUwjx+q2Wbpo4GrwKu2UKlKVFqHQ41IKpnpn+ZqB71QLd5AzWBX1es
         tOy0CkVAzi6GpVT7YrZIN2h17aHC0DLPc9k3QpBrZfBdlqY8G82xhroFTza1xlDnEhmK
         mVZsV1rVDkW3BhHMMXsk0Oc0qrETCMKFCGMWxHXc6gi+XYveyS4BCCkJGudm3vCfI10K
         WDG69w+LG9So/eSLCs9kEuzqaE8Tv+frTVT/U69RjBa5BQ54I0pWqnA7QpQNrGUMyj89
         OVuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Knav1BWzmwyQyCAeM43Dh18O07/YDk7rpGMdjv8e+JG2sQxj2
	msdWDeFRVeGH7tGfjJk4Er8=
X-Google-Smtp-Source: ABdhPJxykAUIxP1tpErUwINqY5BkLxDTd5/nHc06JUBpqqRuAI7bT13aj/26sOD2zDPUQm00B/hUEg==
X-Received: by 2002:a05:6a00:150c:: with SMTP id q12mr4114323pfu.270.1589978290415;
        Wed, 20 May 2020 05:38:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:c31a:: with SMTP id v26ls921157pfg.2.gmail; Wed, 20 May
 2020 05:38:10 -0700 (PDT)
X-Received: by 2002:a65:6094:: with SMTP id t20mr4040334pgu.220.1589978289996;
        Wed, 20 May 2020 05:38:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589978289; cv=none;
        d=google.com; s=arc-20160816;
        b=HB4YYbjV8OMrWs1s/NC3hCYAzuKOXHw1jXT8i69Li0dOr67cH8gi7EcFV7T5wm9f3h
         SnYFuKQGFKze8Mhx3tXIhb9FZrGdiaoq05iscMdHQITgV0sh7vyzeO1NyhUvOT8UgHlp
         kx2tQv77mRSDACp5pkrHDoMaCUCZtvol+X4RPXsRBBlVgY0vQRPChJbjJSwmHPmoBIAN
         jLpF0UhkSEzNgH3ydOHYxNdX3GFmELVZppDNWKp3MbyR5X8hP6zEvE8TcVKo/g00SMUa
         uaW37qezjT8kIPkb3XePUBoWu+7WsIc+r76duCgc/letSKyVQrlJ5adn9hr2QOSyU2aY
         gyKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=DbdlJu8vuZUyyQAeAhd6YD50kjTkWp9bEKvDh4VAu5A=;
        b=ZBjPkZdjyaARDmR3yfECLt4rgsXre/EKO76iTpieG1BhsqTuHntHboMWntu1g9XR82
         8qvg6t+WD/ldGrAcAARcybdYSq8BR60t4zjDy8pxamKTVX9zcl6VxHIMlYX7HiGjsP61
         E0v7Sy0wSMgFha9zRXt/sypjFr+co/ASrwh/+3UJ0LsT+bolCY1R1GUaInhjC2IFZdhh
         u6Ss2DCIDn0vHx3vFrmRg5VG63pt1TrkSvEYQEQspM1qkDCGdxqPqaP/T0H8zgHyq+tD
         JkhoTubKLOamLIiYtNAP8sBpX8+YVAujU3N1V96yq7qe8mk/BS11LsihTxlWyOtIkeV4
         rkcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=hwtd7E49;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id y7si185423pjv.0.2020.05.20.05.38.09
        for <kasan-dev@googlegroups.com>;
        Wed, 20 May 2020 05:38:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 274d28ae69704d65b2323cbde2ff1810-20200520
X-UUID: 274d28ae69704d65b2323cbde2ff1810-20200520
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 922761856; Wed, 20 May 2020 20:38:04 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 20 May 2020 20:38:03 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 20 May 2020 20:38:02 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v5 3/4] kasan: add tests for call_rcu stack recording
Date: Wed, 20 May 2020 20:37:45 +0800
Message-ID: <20200520123745.4024-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=hwtd7E49;       spf=pass
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

Test call_rcu() call stack recording and verify whether it correctly
is printed in KASAN report.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
---
 lib/test_kasan.c | 30 ++++++++++++++++++++++++++++++
 1 file changed, 30 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e3087d90e00d..6e5fb05d42d8 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200520123745.4024-1-walter-zh.wu%40mediatek.com.

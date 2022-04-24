Return-Path: <kasan-dev+bncBAABB263SSJQMGQE6YMPHKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id CCDF650D162
	for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 13:01:02 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id x2-20020a63aa42000000b003aafe948eeesf1621537pgo.0
        for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 04:01:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650798061; cv=pass;
        d=google.com; s=arc-20160816;
        b=offeYmswsfZw7MNriC/Vlh33WAHrWARwk1EwSvmOhHHMLAWNpbVgbC8r9zGPqPDuM0
         jdShSZ38i8cWmHHqW/0jnIoAEgirywN947qb0G2CZsJJFHiJxOPnNaoKdeI0qJf/ZFL4
         QUtisiCUv3Lh4nrPETyqE6qXscu1a1lrNxr+Bi4eC63g+ymfz5Gu8ysF/X6QTNOTC4i3
         yLFM33Z+BcznWwCYMwXsjWPDn6cUkfZJlIzrezGriTZ+afQcTICRznVRePWKUxjPWg5F
         UiPwVx/cZVDI8u+1zei0KenEA8P7GkewedDgg5EMHe5T/oB83qwRzH9Wo2RkLzHyDuWk
         03+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=D1SZkFiwnTUJfoHO2QqMM7uidQ7c6ul4msyPQOChANw=;
        b=rnU/QI2k8hSYsL194xm/NCW7lxLHi4IvXFcXgBEPaAJr7XG6PBEGS1QOUHEbOjpz/1
         48QHe+xS2+9Db6g/CyR0378eF0F/Kgxoj/nQJHnRzC0xokPsnV2U7FrGwGyS948pgcmW
         ygkjc9A+Q7XxFVEF21QYOsbQc8m/eghed2V9UagjG2F8qIFg6Yvf6De0YnzxyH1JJJK/
         YHQDheEx1+z4vOTjBz0oP+xS6hSBps+0CVgoYP4Rklm8r3s/4sei0ATuD1gs+cQc0bia
         40pPhD1MS6hf9+dmrtQGpHwJTK5cBe9cd+FTvYav7mOwy25MSuoSmEftg/E5WkpxZ89L
         6b3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=D1SZkFiwnTUJfoHO2QqMM7uidQ7c6ul4msyPQOChANw=;
        b=i4FjeXtDLJkA2+/F6jFq9k4uyycdhPO2pLtsD9i06/u/shTY26nF5aHB77hgUdX4sg
         yHEDFy2oXvEuot8ZO8/ZxMh2nH4VZFd3Leb0dOEDSJ80YGmP0kiVQ+scxchZdK6YJKs2
         CeTs3+A+51YbKpIJEgIiU/7QRuimnTKJUVcWMm8uHyASt1oLRSwDMFxQ2TzXTIUPmzBp
         K1fcOJlaFpHGgXPvykrujdrTDHsAbOjnCU5bcArU4WnYoXPROOKVsD/JsV/F52DdQV67
         fEkFab7+DDQI7n3KMEdO1z4DtkAUVN2pHLfPUFWzawKNMeBdI2DxQYvuDR/OxdWBGsZX
         f/1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=D1SZkFiwnTUJfoHO2QqMM7uidQ7c6ul4msyPQOChANw=;
        b=PaRCVFnODTvoy2pbT0oBXftSfq25wQBMtubrSlCqE4+fCPqrUjD5thNNbhyirlyO9M
         8uKZYd5hacUTaHTucJ8269x+9iyr/857gi9e4gqmz1VudjxK0su7Ax5oyz1KDwfGO3OA
         SEBW34v5ZVRCuJTyxmMceFE9zes/YjnHDZXHA5go9hisu+iC+a6GxWMEQS6ZInMf30Oh
         HymuIRNJyBKWbX9RPXqBLwZvkG0QzsMovjItEweurUasdL4EObHi2HSe94g+0fuC0Jrh
         fD8ONlOYuKEo7XFM+yAmsgw24Bm5G6WuO4w6NTgCniJFtKFg9Xs3FVHyXHeubVu2T3tq
         x2VA==
X-Gm-Message-State: AOAM531HYmR7wKv74Q9NF032RRVwL6nbEjLAh3L48YUzKOX4ouIgqmpK
	rj7W3x+Bxtro06WjOY9YWtg=
X-Google-Smtp-Source: ABdhPJyoq07pdhZ5016ZsLAMyCpjnQfd5mn3RQZnroiQOF+7cJagCPljAbX4PD5dnmLar/qX6FTl5w==
X-Received: by 2002:a63:164f:0:b0:3a2:ced0:3327 with SMTP id 15-20020a63164f000000b003a2ced03327mr10856386pgw.425.1650798060051;
        Sun, 24 Apr 2022 04:01:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:22c6:b0:50a:6f7b:bb0b with SMTP id
 f6-20020a056a0022c600b0050a6f7bbb0bls2588122pfj.3.gmail; Sun, 24 Apr 2022
 04:00:59 -0700 (PDT)
X-Received: by 2002:a05:6a00:1c5c:b0:505:7469:134a with SMTP id s28-20020a056a001c5c00b005057469134amr13753780pfw.16.1650798059563;
        Sun, 24 Apr 2022 04:00:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650798059; cv=none;
        d=google.com; s=arc-20160816;
        b=WarfwarvBwCLLjL86Ts10REYmpLoVati1hg88ufLTt31+1wDoT/Hf87RakFj2K3wI5
         M0CcriDghrpN83rpO6+8Xcz7ILGKotZXcjQDwfW58K4MhOs/o3xRbVkGyODmFF7IcJx9
         7Rc8BHf0wrAhLRbYl5VqxkhurpgjfTW7HAXTlA447TSXndLmCDjpOcDhXNgj7G6S092u
         t8yRlZ294LWfSoKxIQo2+TX58fM1MgH5vkISV9XIslsgBETwmF6bLAzXyT0v9vuCCKug
         9RDlw77Qvc4AnE5C6JiWLi9ZjT5X/sIveHTsXr8mKYaTPsqm31VNTaWSuCRFb1ZFcVm3
         bSwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=qHpngez5DphifoPrXNbj8mL8YKDsg5IJNceMCO923So=;
        b=pP3P9P663LxqAmSMnmTlUP5MmngRGy6LKeDqgV4KSlW22fWzOspWFh69VT5EO6r65V
         QVTaD6AsO73X/kX6anuReCuIsGlx1ln+m1H8esK5ZuK8RRixPXK2Y1UvqIqnxvbXJ63M
         zHCymnRESLvMsMVSfRuR5j7VbXvs7fK8TQu88WwfscwyFg/UwL22mVZO0eEiHBTHMYVh
         w+LIuTQXPg1prsCIC6VPS9bpUkF3AcOfggWACQbcWk5I6gxDFIpct8MOT3lbMuKBfeMA
         UcC3PrIhwyxDWIRQAhef2yWyur5CDYiKiZ32OZsX7CgnQ4ya/l8XIPD2GcRZvvtciqxR
         407w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id x10-20020a17090a970a00b001d975e7eed4si689pjo.0.2022.04.24.04.00.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 24 Apr 2022 04:00:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from kwepemi100005.china.huawei.com (unknown [172.30.72.54])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4KmQCc1z70zhYT6;
	Sun, 24 Apr 2022 19:00:12 +0800 (CST)
Received: from kwepemm600020.china.huawei.com (7.193.23.147) by
 kwepemi100005.china.huawei.com (7.221.188.155) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Sun, 24 Apr 2022 19:00:26 +0800
Received: from DESKTOP-E0KHRBE.china.huawei.com (10.67.111.5) by
 kwepemm600020.china.huawei.com (7.193.23.147) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Sun, 24 Apr 2022 19:00:25 +0800
From: "'Shaobo Huang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <glider@google.com>, <elver@google.com>, <dvyukov@google.com>,
	<akpm@linux-foundation.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
CC: <young.liuyang@huawei.com>, <zengweilin@huawei.com>,
	<chenzefeng2@huawei.com>, <nixiaoming@huawei.com>, <wangbing6@huawei.com>,
	<huangshaobo6@huawei.com>, <wangfangpeng1@huawei.com>,
	<zhongjubin@huawei.com>
Subject: [PATCH v2] kfence: enable check kfence canary in panic via boot param
Date: Sun, 24 Apr 2022 18:59:49 +0800
Message-ID: <20220424105949.50016-1-huangshaobo6@huawei.com>
X-Mailer: git-send-email 2.21.0.windows.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.111.5]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 kwepemm600020.china.huawei.com (7.193.23.147)
X-CFilter-Loop: Reflected
X-Original-Sender: huangshaobo6@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Shaobo Huang <huangshaobo6@huawei.com>
Reply-To: Shaobo Huang <huangshaobo6@huawei.com>
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

From: huangshaobo <huangshaobo6@huawei.com>

when writing out of bounds to the red zone, it can only be
detected at kfree. However, the system may have been reset
before freeing the memory, which would result in undetected
oob. Therefore, it is necessary to detect oob behavior in
panic. Since only the allocated mem call stack is available,
it may be difficult to find the oob maker. Therefore, this
feature is disabled by default and can only be enabled via
boot parameter.

Suggested-by: chenzefeng <chenzefeng2@huawei.com>
Signed-off-by: huangshaobo <huangshaobo6@huawei.com>
---
v2:
- it is only detected in panic.
- it is disabled by default.
- can only be enabled via boot parameter.
- the code is moved to the specified partition.
Thanks to Marco for the valuable modification suggestion.
---
 mm/kfence/core.c | 33 +++++++++++++++++++++++++++++++++
 1 file changed, 33 insertions(+)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 9b2b5f56f4ae..0b2b934a1666 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -29,6 +29,8 @@
 #include <linux/slab.h>
 #include <linux/spinlock.h>
 #include <linux/string.h>
+#include <linux/notifier.h>
+#include <linux/panic_notifier.h>
 
 #include <asm/kfence.h>
 
@@ -99,6 +101,10 @@ module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644)
 static bool kfence_deferrable __read_mostly = IS_ENABLED(CONFIG_KFENCE_DEFERRABLE);
 module_param_named(deferrable, kfence_deferrable, bool, 0444);
 
+/* If true, check kfence canary in panic. */
+static bool kfence_check_on_panic;
+module_param_named(check_on_panic, kfence_check_on_panic, bool, 0444);
+
 /* The pool of pages used for guard pages and objects. */
 char *__kfence_pool __read_mostly;
 EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
@@ -727,6 +733,30 @@ static int __init kfence_debugfs_init(void)
 
 late_initcall(kfence_debugfs_init);
 
+/* === Panic Notifier ====================================================== */
+static void kfence_check_all_canary(void)
+{
+	int i;
+
+	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+		struct kfence_metadata *meta = &kfence_metadata[i];
+
+		if (meta->state == KFENCE_OBJECT_ALLOCATED)
+			for_each_canary(meta, check_canary_byte);
+	}
+}
+
+static int kfence_check_canary_callback(struct notifier_block *nb,
+					unsigned long reason, void *arg)
+{
+	kfence_check_all_canary();
+	return NOTIFY_OK;
+}
+
+static struct notifier_block kfence_check_canary_notifier = {
+	.notifier_call = kfence_check_canary_callback,
+};
+
 /* === Allocation Gate Timer ================================================ */
 
 static struct delayed_work kfence_timer;
@@ -804,6 +834,9 @@ static void kfence_init_enable(void)
 	else
 		INIT_DELAYED_WORK(&kfence_timer, toggle_allocation_gate);
 
+	if (kfence_check_on_panic)
+		atomic_notifier_chain_register(&panic_notifier_list, &kfence_check_canary_notifier);
+
 	WRITE_ONCE(kfence_enabled, true);
 	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
 
-- 
2.12.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220424105949.50016-1-huangshaobo6%40huawei.com.

Return-Path: <kasan-dev+bncBAABB74MTCJQMGQE7B3RMJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 012F350D6F3
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Apr 2022 04:25:05 +0200 (CEST)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-2f4d9e92a0asf85781367b3.9
        for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 19:25:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650853503; cv=pass;
        d=google.com; s=arc-20160816;
        b=WiF4SDlWSRjvCEsI8pPQKXkhzLmO+x+48YSP1et0mdcNZCW3cN5aSa/ntPwCKjajvZ
         f3KReF71k4GHxJb7MgNGUHiLYQMciR1h5oSr9vfhQun+t0ckpmdtbnIdmUz79TLFVHhf
         IxTCvrkiZ1jPHljIyUvDIpLED1/bMMbAp8R8VFiynXMEknzpo6EC3RodMOPeKkvODJVg
         pzQi0eDAzClcGqBDmN4Nc6wpvhxiwKAUfoLQYTE2LxdSZ/Pwlfa3sZm3j0ih4PTsxlRU
         g1xTO30XAm6UUizs/g0SLQnpuLRwHTH0hnSdIGBkLxbp1uWw9l7zD3Oo7YV/nSINliwT
         pETg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=5ABHIUgCQJebXaKpFNIx6jOezHcwg/mJSwEN0frKvHY=;
        b=Lq+mp1M57PW5DjKLwHXy2EsZLX9LWercIPALfDmkTgGm4T/qNskPJZrpMCOJokt0ir
         9gH3beYw0YNBWkBfhyFJ6NKGEq2/NeZgNfvSi70SPCmAeQAMNUS4yR5lJqwXqGU9c6W+
         qlGJCAnEtV2RoMaxhUu0cmMDeR67BpL2/N8qc3NiTbeLl40OZtBXOmt2faRVX+TBUsef
         FwpyJ3aeV5FcI4BX9X/F4/DkTbvW9e0bL9FwL95s3SjP5Mq/ntMlXhZyuc7fWpwY9bnj
         vABxdkOwpmQqeoh4XXSksm39B3/+Krsq04xVWeATllTIAmAKVI1KX9DXfmmYOy2KkQXO
         ezLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5ABHIUgCQJebXaKpFNIx6jOezHcwg/mJSwEN0frKvHY=;
        b=Tym65geW8dFGcyWGhfL9C/7Vc8JXXxiXy7ggR/qBvdbkDbkNhiSNvzx4YmLX/Cyv6h
         7EppQH9TrgYPm8kprWsMsTKT1IryZqbPs57zWQCurh9rYqshXtZRCyP8AEgaFHoW3vTQ
         av6T+cACzVsIumncrHf5WLO8rg9YWgSOaBRE5EoX8RU5tB2b6lzZMDgBe2sDu2trCjoF
         eDYKP9SLuRWYYPSCcgIeaveUKl2SIvzxPItg0uCQktPrkWrtJiz6t4TGD8jfFPfrZmlO
         EPJzWznwjSFe17Zkz+E9bHPBdTouEpkP4p7HAu5qvTVFDlWYfUW6LjPxTOgNjO6yEDRE
         EfJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5ABHIUgCQJebXaKpFNIx6jOezHcwg/mJSwEN0frKvHY=;
        b=DKN+RwvtRatZS3PFqsACIE+G9u1tKKAuCyzv/LbZwB+ikdwmGhdt4+En/w+fgFwqFI
         kA3KmWDG+51+7UaWIfJUbGI0k/vbaOWoYYiiHICWtLoP491J0UXIy3bR0E5NAnnxi4yV
         XGj8dcnnDD+GyHn0p1YbEKflC8ZldJw6ov95fhwxeCSAhmp+835aNunu4pbEw29j8i2d
         HAQ9KuIpLden1WQOCSa9dpwUg5wx9hfgqAytlhp6kS2rD/9XsByj+511UbaeheY0gF6S
         6O2vNp07X2dPvfUsnLojDfAvcyao5KrS3nr2Vudd8BwsCv5jxdnSchIpcmcIDvau0Vin
         QA+w==
X-Gm-Message-State: AOAM5307FgQcnMHPuR4Pk0H7q1GhrGyVKBYC2BqBQinO/zasU+Tzw6gi
	+IfsNTnyNvhPNfLBPFqGeoc=
X-Google-Smtp-Source: ABdhPJy/NjbRirryT429tMNPwbIG5hbc6sE6jZuIEk7XCo65gyQOrv+ra/s7f6n66pDzfEI0h6N2Kw==
X-Received: by 2002:a5b:f87:0:b0:62b:f9d8:ed5 with SMTP id q7-20020a5b0f87000000b0062bf9d80ed5mr13951488ybh.467.1650853503702;
        Sun, 24 Apr 2022 19:25:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1547:b0:645:7c0e:4bba with SMTP id
 r7-20020a056902154700b006457c0e4bbals7752093ybu.5.gmail; Sun, 24 Apr 2022
 19:25:03 -0700 (PDT)
X-Received: by 2002:a25:4f0a:0:b0:644:b519:1022 with SMTP id d10-20020a254f0a000000b00644b5191022mr13462974ybb.564.1650853503296;
        Sun, 24 Apr 2022 19:25:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650853503; cv=none;
        d=google.com; s=arc-20160816;
        b=MiGfWJ+84btBebZ4BpYkvagF+NX2MNloCSaYjhrDYC/O1dNc0vnNfVRK9e1xPthNAz
         baMuCsPs0Ki92e7Ze2F9dQ4Pkryre+PrvG2ZmhLVJCI3HcGwmCQ4NSMYYiVXdOt5uO5q
         gAGNPGueyRy3NWQp8HGNLWbv22N7qC86AFEm3ZHTx5amt/LOKd20s8t6CscrmYJgZ71n
         7V3HHoCYU3hXOW1UfDzt0mh9Bz0cKCpMEkJ94l3z+Iv+2Upd0Annr0fKGT/VRQHUEHuu
         rLdA/GLgKEdTOvxH/1hcgyxagqqTsBJhm2W1YKekvR/NStWWJR4vTlfSgBaSjaSqG/mW
         2EQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=ycPZlYasdPQRvzETITwR9Sy6fn5bVlARmDpjcFCaN/k=;
        b=ULFhBKtxNG5MGK9dsEZ+iVHhRHV2Ozoi9mboo7cqhNGd4rNVBuYLYqm4qrIP3AYqzc
         jtU4SBNz6IBxpqXeBlmdDOUlx6JTyAaJCIdu/Tyz0gbdODrxt+opx+5kE01b4PBIDX/Q
         ezQVsJZVoelVQbC0RYJMLrjvtVqgtHdpcw8CvMT44Ba6l0lC1iQQqIt54/M4MdSK04QD
         GZsonkrgG4M1i5gHaoqYevjMgE0vgwS9ed862iLLE2AlQyJd6f0QSDlmqu2vjzxdra5v
         K2wxkLFcGD2FWS0AsRV34iv0PMUt7yB8vpgMvFOsRCh2fI1AtBirnIJQJeLH4oQTurtZ
         6gnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id y125-20020a813283000000b002f654f4c062si926524ywy.1.2022.04.24.19.25.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 24 Apr 2022 19:25:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from kwepemi500015.china.huawei.com (unknown [172.30.72.53])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4KmpkP4LRbzhYj7;
	Mon, 25 Apr 2022 10:24:45 +0800 (CST)
Received: from kwepemm600020.china.huawei.com (7.193.23.147) by
 kwepemi500015.china.huawei.com (7.221.188.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Mon, 25 Apr 2022 10:25:00 +0800
Received: from DESKTOP-E0KHRBE.china.huawei.com (10.67.111.5) by
 kwepemm600020.china.huawei.com (7.193.23.147) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Mon, 25 Apr 2022 10:24:59 +0800
From: "'Shaobo Huang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <glider@google.com>, <elver@google.com>, <dvyukov@google.com>,
	<akpm@linux-foundation.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
CC: <young.liuyang@huawei.com>, <zengweilin@huawei.com>,
	<chenzefeng2@huawei.com>, <nixiaoming@huawei.com>, <wangbing6@huawei.com>,
	<huangshaobo6@huawei.com>, <wangfangpeng1@huawei.com>,
	<zhongjubin@huawei.com>
Subject: [PATCH v3] kfence: enable check kfence canary on panic via boot param
Date: Mon, 25 Apr 2022 10:24:56 +0800
Message-ID: <20220425022456.44300-1-huangshaobo6@huawei.com>
X-Mailer: git-send-email 2.21.0.windows.1
In-Reply-To: <20220424105949.50016-1-huangshaobo6@huawei.com>
References: <20220424105949.50016-1-huangshaobo6@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.111.5]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
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

Out-of-bounds accesses that aren't caught by a guard page will result
in corruption of canary memory. In pathological cases, where an object
has certain alignment requirements, an out-of-bounds access might
never be caught by the guard page. Such corruptions, however, are only
detected on kfree() normally. If the bug causes the kernel to panic
before kfree(), KFENCE has no opportunity to report the issue. Such
corruptions may also indicate failing memory or other faults.

To provide some more information in such cases, add the option to
check canary bytes on panic. This might help narrow the search for the
panic cause; but, due to only having the allocation stack trace, such
reports are difficult to use to diagnose an issue alone. In most
cases, such reports are inactionable, and is therefore an opt-in
feature (disabled by default).

Suggested-by: chenzefeng <chenzefeng2@huawei.com>
Signed-off-by: huangshaobo <huangshaobo6@huawei.com>
---
v3:
- use Marco's description replace the commit message
- keep these includes sorted alphabetically
- "in panic" replaced with "on panic" in title and comments
- Blank line between /* === ... */ and function.
v2:
- it is only detected in panic.
- it is disabled by default.
- can only be enabled via boot parameter.
- the code is moved to the specified partition.
  https://lore.kernel.org/all/20220424105949.50016-1-huangshaobo6@huawei.com/
v1:
  https://lore.kernel.org/all/20220420104927.59056-1-huangshaobo6@huawei.com/
Thanks again Marco for the suggestion.
---
 mm/kfence/core.c | 34 ++++++++++++++++++++++++++++++++++
 1 file changed, 34 insertions(+)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 9b2b5f56f4ae..06232d51e021 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -21,6 +21,8 @@
 #include <linux/log2.h>
 #include <linux/memblock.h>
 #include <linux/moduleparam.h>
+#include <linux/notifier.h>
+#include <linux/panic_notifier.h>
 #include <linux/random.h>
 #include <linux/rcupdate.h>
 #include <linux/sched/clock.h>
@@ -99,6 +101,10 @@ module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644)
 static bool kfence_deferrable __read_mostly = IS_ENABLED(CONFIG_KFENCE_DEFERRABLE);
 module_param_named(deferrable, kfence_deferrable, bool, 0444);
 
+/* If true, check all canary bytes on panic. */
+static bool kfence_check_on_panic;
+module_param_named(check_on_panic, kfence_check_on_panic, bool, 0444);
+
 /* The pool of pages used for guard pages and objects. */
 char *__kfence_pool __read_mostly;
 EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
@@ -727,6 +733,31 @@ static int __init kfence_debugfs_init(void)
 
 late_initcall(kfence_debugfs_init);
 
+/* === Panic Notifier ====================================================== */
+
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
@@ -804,6 +835,9 @@ static void kfence_init_enable(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220425022456.44300-1-huangshaobo6%40huawei.com.

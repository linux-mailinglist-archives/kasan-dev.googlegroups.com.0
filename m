Return-Path: <kasan-dev+bncBAABB74TZWHQMGQEZ7P456Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id B76C249F0A2
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 02:42:25 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id m200-20020a628cd1000000b004c7473d8cb5sf2569714pfd.5
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jan 2022 17:42:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643334144; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nl0ssRDQJF6cxeIk64qSEDSmocakBIgIfeTM0jZTvbTkN3ex64jqv409MuQeOj+1Bq
         tl42ezCwpNodPXqL2MxjrpcjO83j49a0V8iPz0EtJY3fNeBdFcShI+axf16K83rY7z9Q
         xrkveD6/EBwNgQRNaofmYC0AeWeaznf4fH0kF3tqr5YDu6VjDgXtu7lDTRaT3zJ4O1JN
         Aua2ovga3VcQRTlKKXk910KX7qu4TCh7fNRuy+J0hHWiM3TfQYKMaYT5hVKHiXGX0UTs
         nD+S2/GD1qhLyYkRyACUhlDB2J4rauTLL/VdHChnxFneKgfKonXWt3BBHMiqrn+dxE+t
         /pcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=pMGEFaglOnjXLkfhQ250B+ee/yu9PcMzbldBTdLXZr8=;
        b=Ko8O/GNh8gAMcplZsZT8aUc3RuclKqRkF+jkRf6qEFiuAlVYp9JxsPCqj3ATLIXOGm
         +EusWuKSm1XZ7hveaLstMw9eFv80xSvJi0c4CT1aSIuVLKeWczCR+pacd/3CGW9wvCYv
         jJHGuuCJSS3JgwcqSIosB4VF7tQh3iVLAdjmNEqEqqGYNW0uM5aZ7IRgWDa6N60KvX2z
         FsK2CiCkwSZ452yhxlDji/xYpoJdf/j6V/KfuC/G7q61bImL8uq6H3GGy3hbV0R8JNnc
         bnwTaGfCgHVW66eCpf2gF9Ak0wZNxARdAj6IYTVdFk1vSmz+791lyWOyBXHl8uWdywQd
         Kqww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pMGEFaglOnjXLkfhQ250B+ee/yu9PcMzbldBTdLXZr8=;
        b=cc+AC4I/Wy++MOqDQiaDjMenZ1NUjxYazwmQBD9f8afEZtdJi155HjTpsb0LodGRJw
         JPexk//R+Ujwkn4oCGG+8f69MQ7VtBF0sk4Y6VvcWHFLaOhDq8vopVLbH3r5AAzr19CJ
         Wo8G87f1dMwowequdWd6/qaBzXLDmt3fatkOv6ps5ho1GGstiYpYKf0pWj7QRRcfe/Ba
         2hSW/2ASowkHLfcZNRXUYQtEjkazFyyZU01Z0/aez/UCTYy+W35vZWI4UQlflXneCcUw
         7P5BUUuvmMUFuM0t8+tg7jP+paIaSl8v9MXoIDZAGF/tU2bJ+mAMrZ0RgODvU3Z6ln7S
         PKPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pMGEFaglOnjXLkfhQ250B+ee/yu9PcMzbldBTdLXZr8=;
        b=3R2QVD0zwMttpV7MzQOyHFich0wLRilpnm9OMNPCr+GGb31fVV83Kn6D2C0gv8ccKd
         3SHEpqGtzbyr/rAGQTYejcy896QXobWzMj4G0aN0AOpBmb5qC31GxvO7rKQTmPIZl6UE
         s2SlLOy2hv2rUFpWGB51vykdvpDGSbBBnwZeLTMGjV8jhDuIhhSKso6JQVvvEiuA85mb
         YG3YvBTmvSYDBVE2LCSou1i8WGa5PI1t5tnb/OupFkLXuJf84tDTv4DCmEP0r0cs76TY
         PjdDFWxT/N/KOkd5Qvo1TRmEuAobks4w689MKQpDA2f3aDslEfcwOaacD/IGXVaBnHJE
         g/Ng==
X-Gm-Message-State: AOAM5323joeikWko0oeMOL01l0KFuXi0tsEp+GYZc1aBgcIze9HplHDp
	dE9FjyypPEr45Zonzo1tuxA=
X-Google-Smtp-Source: ABdhPJx4+/Cb5ibHeHjD0pGcGXEpmSs2G56AU0gXaomr0WI1m89APQRh28W9DvYdL+/fnuTvkx1IOw==
X-Received: by 2002:a17:902:7603:: with SMTP id k3mr6834693pll.160.1643334144034;
        Thu, 27 Jan 2022 17:42:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:10c3:: with SMTP id d3ls2949701pfu.9.gmail; Thu, 27
 Jan 2022 17:42:23 -0800 (PST)
X-Received: by 2002:a63:90c9:: with SMTP id a192mr4796861pge.278.1643334143539;
        Thu, 27 Jan 2022 17:42:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643334143; cv=none;
        d=google.com; s=arc-20160816;
        b=IaCpvdciLGcX0ZG4R2r8QTonqssbzg2VAn4RtE+PHJjiWnDRD3HnxAneQHG9U4lh+7
         gRrsWEQKkDqH4+kjt/kSB5A1vs9RWLgVqjtMDl4hmqZeAmoEJq681QWqP8ps64z6RMW+
         bXk+hFnrb0vQfgAIHwCN8VxtwQdXeHfhcz2eTPreaxsgAhWoF1HpMgSv2ovFvZlKGxlH
         e0FAMSHeQep+M35FFnWKIB3eaH9me6E/R7PmDALVlXl+l54gnIlKSaz5j642xejAHcEL
         d34rE/KgvuUFgSKlgKuPCbw2GSZUJ6sn4xgwT6vsMD2m+LnCzrS7AFbupZcd6vCfr6Fk
         Xn6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=8CH0wvcR+CrliiA2gs4dx/6ORq3BjletmBurx0/y3Is=;
        b=YfojRWERMV8/2L4WIyb5ioLJr9l7Qjj4LdKAa9U3AJDeNviic/Rere9N20nE6f57wp
         buq+fDJPyCB28Us84dii0i/Oeav83uu9lDYkJNR9uGu3ePKBQOpdWbuZC+fYbHlDidsY
         +2lE1tc9hdA5DaKm89cAi1Ze1/HRrF+pwYyviCxuY8X35d/XvVNxK4ahXW3+eTPRAkdY
         x2ykwo/hayAqAomx/o44iFnqMWSt7A4U62FG9DnPfNJzxZHxrVc3+OaBpmKjdgGTYT6u
         4sJf/2g2K8cxcUciLrGN9om1u+xvoyjo9tsGhXB7LE2su0r5+v7lCIrVBN60Hrxr2B9g
         WxhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id q10si244649pfj.5.2022.01.27.17.42.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jan 2022 17:42:23 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from kwepemi500020.china.huawei.com (unknown [172.30.72.57])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4JlKt34L5PzccpN;
	Fri, 28 Jan 2022 09:40:59 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi500020.china.huawei.com (7.221.188.8) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Fri, 28 Jan 2022 09:41:50 +0800
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Fri, 28 Jan 2022 09:41:49 +0800
From: "'Peng Liu' via kasan-dev" <kasan-dev@googlegroups.com>
To: <glider@google.com>, <elver@google.com>, <dvyukov@google.com>,
	<corbet@lwn.net>, <sumit.semwal@linaro.org>, <christian.koenig@amd.com>,
	<akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-doc@vger.kernel.org>,
	<linux-kernel@vger.kernel.org>, <linaro-mm-sig@lists.linaro.org>,
	<linux-mm@kvack.org>, <liupeng256@huawei.com>
Subject: [PATCH v2] kfence: Make test case compatible with run time set sample interval
Date: Fri, 28 Jan 2022 01:57:52 +0000
Message-ID: <20220128015752.931256-1-liupeng256@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=liupeng256@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Peng Liu <liupeng256@huawei.com>
Reply-To: Peng Liu <liupeng256@huawei.com>
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

The parameter kfence_sample_interval can be set via boot parameter
and late shell command, which is convenient for automatical tests
and KFENCE parameter optimation. However, KFENCE test case just use
compile time CONFIG_KFENCE_SAMPLE_INTERVAL, this will make KFENCE
test case not run as user desired. This patch will make KFENCE test
case compatible with run-time-set sample interval.

v1->v2:
- Use EXPORT_SYMBOL_GPL replace EXPORT_SYMBOL

Signed-off-by: Peng Liu <liupeng256@huawei.com>
---
 include/linux/kfence.h  | 2 ++
 mm/kfence/core.c        | 3 ++-
 mm/kfence/kfence_test.c | 8 ++++----
 3 files changed, 8 insertions(+), 5 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 4b5e3679a72c..f49e64222628 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -17,6 +17,8 @@
 #include <linux/atomic.h>
 #include <linux/static_key.h>
 
+extern unsigned long kfence_sample_interval;
+
 /*
  * We allocate an even number of pages, as it simplifies calculations to map
  * address to metadata indices; effectively, the very first page serves as an
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 5ad40e3add45..13128fa13062 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -47,7 +47,8 @@
 
 static bool kfence_enabled __read_mostly;
 
-static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
+unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
+EXPORT_SYMBOL_GPL(kfence_sample_interval); /* Export for test modules. */
 
 #ifdef MODULE_PARAM_PREFIX
 #undef MODULE_PARAM_PREFIX
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index a22b1af85577..50dbb815a2a8 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -268,13 +268,13 @@ static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocat
 	 * 100x the sample interval should be more than enough to ensure we get
 	 * a KFENCE allocation eventually.
 	 */
-	timeout = jiffies + msecs_to_jiffies(100 * CONFIG_KFENCE_SAMPLE_INTERVAL);
+	timeout = jiffies + msecs_to_jiffies(100 * kfence_sample_interval);
 	/*
 	 * Especially for non-preemption kernels, ensure the allocation-gate
 	 * timer can catch up: after @resched_after, every failed allocation
 	 * attempt yields, to ensure the allocation-gate timer is scheduled.
 	 */
-	resched_after = jiffies + msecs_to_jiffies(CONFIG_KFENCE_SAMPLE_INTERVAL);
+	resched_after = jiffies + msecs_to_jiffies(kfence_sample_interval);
 	do {
 		if (test_cache)
 			alloc = kmem_cache_alloc(test_cache, gfp);
@@ -608,7 +608,7 @@ static void test_gfpzero(struct kunit *test)
 	int i;
 
 	/* Skip if we think it'd take too long. */
-	KFENCE_TEST_REQUIRES(test, CONFIG_KFENCE_SAMPLE_INTERVAL <= 100);
+	KFENCE_TEST_REQUIRES(test, kfence_sample_interval <= 100);
 
 	setup_test_cache(test, size, 0, NULL);
 	buf1 = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
@@ -739,7 +739,7 @@ static void test_memcache_alloc_bulk(struct kunit *test)
 	 * 100x the sample interval should be more than enough to ensure we get
 	 * a KFENCE allocation eventually.
 	 */
-	timeout = jiffies + msecs_to_jiffies(100 * CONFIG_KFENCE_SAMPLE_INTERVAL);
+	timeout = jiffies + msecs_to_jiffies(100 * kfence_sample_interval);
 	do {
 		void *objects[100];
 		int i, num = kmem_cache_alloc_bulk(test_cache, GFP_ATOMIC, ARRAY_SIZE(objects),
-- 
2.18.0.huawei.25

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220128015752.931256-1-liupeng256%40huawei.com.

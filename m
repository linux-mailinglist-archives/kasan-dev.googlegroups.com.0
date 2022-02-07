Return-Path: <kasan-dev+bncBAABBGFEQKIAMGQE3J52YTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AB704AB36C
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 04:29:29 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id l34-20020a0568302b2200b005a22eb442dasf5165084otv.15
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Feb 2022 19:29:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644204568; cv=pass;
        d=google.com; s=arc-20160816;
        b=HN2K2Nq2zVwP5o+hhWYf1aRh18k2TkDhLlYEPt2MXeYb4jad62sqrBna1We2CUr7zV
         kXXSjudHDr5KU4gjJLTw8+OcXunKF3uLPvNvuEyHwVGlqjqyVApS/spSTOemBymPtXab
         Z+gsZG2pJMStsd0XSJpcmHB1XhVxXG57F43Zl9MagHAuafitFTR9DtOZ8RNHpWtft03z
         +BENjuFgBe6KQo7lPqyPeFMYhjn38Of9NmnNsYsggJnk7qGieSwG63Sndgy7S7PrXRPJ
         wlOz0nCFUcltSwq7XJr21+Twq0tu+JDdzd8mG5TCX3dGtHJXaj12QSdFHgn0hMyTY8rd
         vYeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=WI4pRQiYIiHs3Xlk01dMG5ydVPgvT6ocY/SZ3wh/984=;
        b=yqRy+KgNIizbArOvsdaneseE6CTNy4jJfiH3qB7GUFq3YHL6V7rml5cMKrroNRjcN0
         wB58zScK4Cc7ubUiNVlMtcvKx6lXE7R/Z5oZvQdK1X7OOMIny86G92zjzwOxD/uQFONo
         4yyXrW5mAic+ZVBqFoLwEov6sunuRzH9lJrvuYKLbG7b8Qj+3pnoMcD5+Icq7zYZ4FSr
         qCWyympP5hgpq80Zi3gSkbq1xujeFFkzUyeVQUtuiOO/0CsOWC7VeLaUk5SQy5F7EzUD
         6SxiTPb6aTEtKnCVGb4mBoHibGr2udRtUj21LsV4+8h4dR5m8uLXwAlzSMjiBzUb8MzH
         Gveg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=WI4pRQiYIiHs3Xlk01dMG5ydVPgvT6ocY/SZ3wh/984=;
        b=WyH5aWNMYTltbshu7HOAa3nGHnZAk4FHPObZdmPDUs3//RQDOGbuKxg9FsR8/c5d/l
         eHDPkuJq1P0/sUXQ88RIUsbx3/PQml+Dhx5S5t5yzJRgFGr5G/aPWApC5RzcA9REk9uR
         HL1VPl4MBRIpTrqLNpuPOt/E644FiuaJUB32yObqOENy2WMZjAcYBtQLckAqmppSnY/1
         doPrCN2RhuTJyS84biO13eJVM1+rmPOJDvuDw0iTORNl5b4K6xBQ6/x9k/5X7mXHqz1L
         SFtDqj4FiJbcUWn1u1H0saooJp3QbvzcTbWsArnapSBJDpDdf451xdi+LfWHr4HwfYT1
         dgSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WI4pRQiYIiHs3Xlk01dMG5ydVPgvT6ocY/SZ3wh/984=;
        b=RaSke48TTapRhUkLuYDASpCHYHVogQz9h1PhERgPMHGJ218Pal5knSDYCgMPM+5WQV
         9Rrduge88MvozNC53YFUtcH14RaJA2+FxO4um4Ky4KZla+MtgC7PFOc26GGvbHyYsEeO
         kGOkkOudP4yKGnTOIqt5RaRB+ODeJp1Tl1jqEIO8M/EKukbuJ9z9AzAeDGV2hGaXUXF4
         Gf3VIvy2gS59RG48zQpnN8PoSCKLjeaqIBgiqbplR4APrl8l8Ihk3OgWrGyCr/LNjRV9
         YplPPRAWrnuqGiU9SAU6sAe6MBeQiHS81yaFAZ5qSpZoHe5qSF9feOjaB9v5E3t6O4OJ
         Ztug==
X-Gm-Message-State: AOAM530jk2HuyjmrR7ukrHIsw8p27npWQkSlVzWcJHCZW040jtVwR8tk
	KKsNth5H5FopruY3T2zcI9U=
X-Google-Smtp-Source: ABdhPJxUpsk59NvIKzgPYj/lBBEVDebdbBpSCBnvGqpSnYBIVvYuYJ+QhPWFvQhYTAy6Q/STzUx8Zg==
X-Received: by 2002:a05:6808:189f:: with SMTP id bi31mr4365882oib.5.1644204568119;
        Sun, 06 Feb 2022 19:29:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c787:: with SMTP id dy7ls402916oab.11.gmail; Sun,
 06 Feb 2022 19:29:27 -0800 (PST)
X-Received: by 2002:a05:6870:344:: with SMTP id n4mr2782875oaf.209.1644204567821;
        Sun, 06 Feb 2022 19:29:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644204567; cv=none;
        d=google.com; s=arc-20160816;
        b=kSOxE9e4467cB+fxlT5GvpexoVTuIEOtj1dXgG8LoEayZ5UCRIU2bRBwegeJve7Sxv
         tUCtniFgU1WByXrgJ8E4dLoi46DrZPZAYw8Wg7fdDO6D/I+M49izbfngwmuBf0OHjkKx
         mQppaF250t583tP5ojyvM5d+n5plp7x8SMPZtZKFtSlrcpEBsKWQil3k3wZnkHc8vzCk
         f+RhNdpijVNmHl/WxXzzN001hboq9jox0At4gpZDh/1hoy3sog6jFEWkGcVVwaCSZw2a
         BH29otbsUxwpR6q/w+U+Z+HqDwNo3BHGyU4mQqZArJMIcXeTGQ8bk5Mdmojf0nkSDLvb
         QNsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=gTo8ai/a7MM1heAA3JG4rDQ6Cc/5KlwuCu3+RgSziU0=;
        b=X74AqVK1EOgZB2UGdoksAhgQFJEj7in9R+c31LBlD7RcW2kSYHthe+Ag5d+t00bdYy
         w9367Cqq8/BCfIW79sdwD5ib46UXfM1SvnTOb18oD7UR5bYhGPWM8whI5ar/sjiZGPSu
         gTu/0lkYe/9MCaV5o4rgjS2t+JRfXVT6HUBxe/f9ndOdsUN6UzY3yVzP9t9bjojC6b+q
         xwnOsye1OIK2fL/mD1B4/Rx6e9Y5ONkTO+rwdbU47kbiog6ZdEA1C1oKBJT1EVxLQ/PM
         NIjD87ZmwBjrDPDlZ5JcQcYZAeSK++j6pXnAisoHeDklK027Fzn1/3p9o2ayujsPjPdQ
         XpDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id x31si608609otr.0.2022.02.06.19.29.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 06 Feb 2022 19:29:27 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from kwepemi500011.china.huawei.com (unknown [172.30.72.55])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4JsWjl51mXzZfM0;
	Mon,  7 Feb 2022 11:25:15 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi500011.china.huawei.com (7.221.188.124) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 7 Feb 2022 11:29:25 +0800
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 7 Feb 2022 11:29:24 +0800
From: "'Peng Liu' via kasan-dev" <kasan-dev@googlegroups.com>
To: <glider@google.com>, <elver@google.com>, <dvyukov@google.com>,
	<corbet@lwn.net>, <sumit.semwal@linaro.org>, <christian.koenig@amd.com>,
	<akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-doc@vger.kernel.org>,
	<linux-kernel@vger.kernel.org>, <linaro-mm-sig@lists.linaro.org>,
	<linux-mm@kvack.org>, <liupeng256@huawei.com>
Subject: [PATCH v3] kfence: Make test case compatible with run time set sample interval
Date: Mon, 7 Feb 2022 03:44:32 +0000
Message-ID: <20220207034432.185532-1-liupeng256@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
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
and late shell command, which is convenient for automated tests and
KFENCE parameter optimization. However, KFENCE test case just uses
compile-time CONFIG_KFENCE_SAMPLE_INTERVAL, which will make KFENCE
test case not run as users desired. Export kfence_sample_interval,
so that KFENCE test case can use run-time-set sample interval.

Signed-off-by: Peng Liu <liupeng256@huawei.com>
---
v2->v3:
- Revise change log description
v1->v2:
- Use EXPORT_SYMBOL_GPL replace EXPORT_SYMBOL

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207034432.185532-1-liupeng256%40huawei.com.

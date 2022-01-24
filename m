Return-Path: <kasan-dev+bncBAABB65BXCHQMGQE6KJ66RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A8F1497774
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 03:37:48 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id m3-20020a056e02158300b002b6e3d1f97csf8602286ilu.19
        for <lists+kasan-dev@lfdr.de>; Sun, 23 Jan 2022 18:37:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642991867; cv=pass;
        d=google.com; s=arc-20160816;
        b=VrBKSRvwuDFzLQdMWF0Q7rmWiSMbeuHDADZEaQVpU5vGpKbn6cXZ/GYLXSUqphjnkx
         U2RhV+i4ygmUdcPjKv4K5fRmfuwOw4a+7rENE9VCICCVjBIYxmmIJFWp+TfFGR2wM1vI
         LMx1kvuPyF1rW1MabOSjEyMbACnYi7YhkymCu+wUP9z4gfbsKIielmlZpb1xMWKYBMij
         Vl4Pf3R2SIqayiMdSnasBRiJ7xFa6IF3u2f79ugx2xH68cUs0IFJgeNOocnvhN9d7tL8
         /rvq2ZdgCwX5EsfPg/KL1Plpd1+82pm6Lboab7N6dUW5AtLQvt8lX8akSYlaIMY27XLw
         QN2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=0Vv+NSlNrhEBFkAe5eDf7Edcah9O+VJ95is+XBb5tII=;
        b=QlEsW80YcwfLR2gukjQZ0HxHqmlEBO5uoyMEFX8WINXqGZGLsrId8lN0jkYFvjUP+M
         1s0faLtWejK9wkxlhKnYBWarph6xOS3ataz+1v0ireVhMdZUZ/9fH/5ENOQWXJCXepNI
         fPbTSog9u6cKP/0AAoFkddGl+wRAq/RNARt+sdgmD64HWLM++uwzoVF78dotqqeydacf
         te7Q44d9ZrxUjIs1eTUiWbrBGvc9Uh+LgZnx+24y2gc6UH+kAspChCXsEbTugzeypPWm
         OqsLj+gj92FgyEj8bcBbXzDGag1BeR6ifG1L+ddbaBfftk8i3PHXk2XI76TsQSyiXCLH
         5eiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0Vv+NSlNrhEBFkAe5eDf7Edcah9O+VJ95is+XBb5tII=;
        b=YaW/IliFUvwCR1h1TMFaWWGks3fbC5UtRRcgXnYMJzzr71U3OvYwkeYM3rbdaromAt
         TWkz3U1XVnBFU5RlPkPMAjKa8hRdL1kMTUTmIz18ZbGAFHJ6yRQl7y1g12rh9qf7Qrsu
         EZk4+4YE5ad5OTzVrTVCKws6QuGPtpWyQMX+qe23mMRrmAiyH9YkqNZ7c1cL0Sz0e7nU
         IB0PvthcHpRkk9tL03cuk7edp77ZGBulj/lhX/mktJq/VyoBZzfZMDcynvMzihhWCens
         7AfSD3PR66crZBFwFZGyohuNOjNmXvOyvk+HRV/dF6g/OqPAfcDTJY4FOmKdsiER1Mpd
         vIlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0Vv+NSlNrhEBFkAe5eDf7Edcah9O+VJ95is+XBb5tII=;
        b=VUc+C75Wd420f+zJBmCv3me3W+39GOE0t5Dh/7BvdZT/cx+CuzxiL5Ho/THUTzQdmA
         dIFLZcakW31+08MMvzInKlrdvvMM1/nTOE95RxeT10xc1h7dWoUPMB+VNDgpE/Bbug6P
         vcM6+U2l84EQcELkera2FvLU8BDZ7mplpMqHtvwVBS80mp3xq13uvcQKE6Y3pEtjOsnQ
         nTa3lQUK6vJhwRJXx9b0UTBIN65CDc70w9bEtN00JYqJKZYZKZ7Gjwmw44/mYK7FaVrw
         RIqphPQHzQr4OUjwEeVSzopCSZZtrztKkipLBANiMiNq8slr4a2iRF4W9H6QjXC4LguP
         OCkA==
X-Gm-Message-State: AOAM5333I76LwLGJqkBgxq4QHGmDgaYBPR9V+Mb/mKkKNz/dGrNf6YvQ
	GMhHii+VJmwVxkw06h1ZzzI=
X-Google-Smtp-Source: ABdhPJwtGjS6sfob2KFOeArb5nddOGd+1bYGs77kLgb5XxLMzXvQm9a2tsEL9DqTdjTSWZXHasb7sQ==
X-Received: by 2002:a05:6602:2d8e:: with SMTP id k14mr7161842iow.197.1642991867131;
        Sun, 23 Jan 2022 18:37:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:b01:: with SMTP id a1ls241913jab.11.gmail; Sun, 23
 Jan 2022 18:37:46 -0800 (PST)
X-Received: by 2002:a02:114a:: with SMTP id 71mr6142492jaf.88.1642991866842;
        Sun, 23 Jan 2022 18:37:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642991866; cv=none;
        d=google.com; s=arc-20160816;
        b=cnuGYRWaTkgiHpnbRUoMdjFcndvAfM4CdC+43L9IWbxzjNIZ3On/jUSJyNRjdxhF4e
         jDQ4LGpdf36iWZJIfTbLbtS7Uo/UidGleus26AYuZBQUZglL78MQs2tuLM73bJKCMpB2
         DqjCrAlg8lut13koIGi8rW4lGX9zCd7WYVRMAScx9T4kp/CWl0QEAjwuat34z/6LpOA6
         Hc6nsDsz9odrTw9iJUpwtUtGGPcwl4QUfyFm6HOYxLxc4vETfH3krL/Pnez/lj427MGI
         dGnqql3iw4+qSYoNQz8IhosJugr7IZEc+ngTNxaAsGxBMsbRQDtkIRkCAu2smarhBLar
         8DVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=M4ajph3ZtbzHDPolT3FV/tEBfiEmftpEQWZYjP10uII=;
        b=bnrHA9mCkVbIxLiCxYMxv0VLYXPEnHupwxxgA8oGM19z5Lo5R+zebNEKafo+kpjLeB
         Y225FywPGEoxOWVcMNzvpmDhz1OBF77DFbme0RP6dGn5C+ePCTojGHuLFyNe74Mz4Uk/
         T+r4ZTrkCCrP/k710DsNpU6L8Bq7sChIDy6YXyQ2YgJtTDIMuiqlgnYOjERNiRq/mI0K
         U027tCxOFYwgH6U0VDAwJ8g3Dfbzal80iVoenzwyEoADmXOKd4WGj+dTz3P7uV1tXban
         r+PnLdSN7C+P1xXJ2Mo9FrgTAqxIuxcHGbIsjZgfuAx0BVREet8wfwTZHRXNpoW43ZNr
         3Y+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id i7si85304iov.0.2022.01.23.18.37.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 23 Jan 2022 18:37:46 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from kwepemi100026.china.huawei.com (unknown [172.30.72.55])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4JhvJR4KKjzbk5R;
	Mon, 24 Jan 2022 10:36:55 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi100026.china.huawei.com (7.221.188.60) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 24 Jan 2022 10:37:44 +0800
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 24 Jan 2022 10:37:43 +0800
From: "'Peng Liu' via kasan-dev" <kasan-dev@googlegroups.com>
To: <glider@google.com>, <elver@google.com>, <dvyukov@google.com>,
	<corbet@lwn.net>, <sumit.semwal@linaro.org>, <christian.koenig@amd.com>,
	<akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-doc@vger.kernel.org>,
	<linux-kernel@vger.kernel.org>, <linaro-mm-sig@lists.linaro.org>,
	<linux-mm@kvack.org>, <liupeng256@huawei.com>
Subject: [PATCH RFC 3/3] kfence: Make test case compatible with run time set sample interval
Date: Mon, 24 Jan 2022 02:52:05 +0000
Message-ID: <20220124025205.329752-4-liupeng256@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
In-Reply-To: <20220124025205.329752-1-liupeng256@huawei.com>
References: <20220124025205.329752-1-liupeng256@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as
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
and late shell command. However, KFENCE test case just use compile
time CONFIG_KFENCE_SAMPLE_INTERVAL, this will make KFENCE test case
not run as user desired. This patch will make KFENCE test case
compatible with run-time-set sample interval.

Signed-off-by: Peng Liu <liupeng256@huawei.com>
---
 include/linux/kfence.h  | 2 ++
 mm/kfence/core.c        | 3 ++-
 mm/kfence/kfence_test.c | 8 ++++----
 3 files changed, 8 insertions(+), 5 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index bf91b76b87ee..0fc913a7f017 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -19,6 +19,8 @@
 
 extern bool kfence_enabled;
 extern unsigned long kfence_num_objects;
+extern unsigned long kfence_sample_interval;
+
 /*
  * We allocate an even number of pages, as it simplifies calculations to map
  * address to metadata indices; effectively, the very first page serves as an
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 2301923182b8..e2fcae34cc84 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -50,7 +50,8 @@
 
 bool kfence_enabled __read_mostly;
 
-static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
+unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
+EXPORT_SYMBOL(kfence_sample_interval); /* Export for test modules. */
 
 #ifdef MODULE_PARAM_PREFIX
 #undef MODULE_PARAM_PREFIX
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 084e3a55aebb..97ff3a133f11 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220124025205.329752-4-liupeng256%40huawei.com.

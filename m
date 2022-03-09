Return-Path: <kasan-dev+bncBAABBHOGUGIQMGQECDMAJWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 6657E4D2A7B
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 09:19:43 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id b18-20020a63d812000000b0037e1aa59c0bsf904937pgh.12
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Mar 2022 00:19:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646813982; cv=pass;
        d=google.com; s=arc-20160816;
        b=KuKYdXudLKniaPKKvrI57RBi0Wppq1uS+KbpjtFQ9pNovwqcl3MA12htjF44eMVx4/
         EsXhd7+vGXCp292cGn9msiNB6PlKMBCA3srkEm7S/kKRQ4thsF1RVBr5KcraoAjOeMlM
         jZ3mbjoKR3bjiSowzgfpqVAZFQw+5thPtSMt20G43JMaTNWQVL7KlIY6oJ42YgigMcG8
         DAfVJCKvH8WMf0FrJBPsVlzcQ+ZrtabEdSCZLohbDBNrV9qS8E4CS9lk5HKWHIHFnzAi
         gVugx0OIgD5XUGMsF5P+0xDVuoJt8cmgamEy2WdZ4UJQmFniGSHgHvV8nONottsnvnBi
         ht8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=rYOd9wizCYaUeFDk8vdwrskKSmNukS8odvLKvLUR6ys=;
        b=TyV4PyG3DTLmCqJ7CSd8ja4eWpc+7Ju7i2UU91uqfNUIlXSoG3J/AXxWSvhD6WY0ea
         TJXzu57cUui9VQj5zyB1FjHCl5i1tDlUv5NDZU1A/yTvibp0nQ0ij3fGoIcF0ShRh+kr
         iLDZ2Q3a36QcTCum5coInr0R38McuLcPrwWJfcB3SuJaI8CS3zjyMBWHVCVbxw58PqYA
         pdnve8tkeJmiaJfXHvzCdQKIIpPBMab186NFN+hJVkD6dDo8bVCbyFt4JQ0FH7LAD2Pf
         1rbqOX0MNolVIcI4w23+ucVCrJc8gDVaQxCG7Xnr9bRuSskmNavlZQPMn8ClmJypYfmb
         2L9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rYOd9wizCYaUeFDk8vdwrskKSmNukS8odvLKvLUR6ys=;
        b=KY+Qr9dXeOdH7IAs/ViMTO2ylbqNUzp2kyqsXsnPIXgUxSrCeVOZ4lKFoJGY2KhZoZ
         BfFoDTO3rf4mBVgfUOdpGX9aDVvFnCY9r+v1lo27z/FU4h8MwEks7/5jOQn5gTQ+0IyR
         YaFKfDjAo3E0SowI0SfPANASm8pa6N8eSHicV0PuWT5upvIMFMoOeSquYlqRIzVfzFLB
         AaE782xAYvsoelyEm14qlkfYkrWTJvqNH4xwyDLm6maIN1Tx8MfNxA+S2CN3THi7e5GE
         CismJKSE86R3uUErRgpkOC0OuK58zYSXhNJqedjkEG4Y6aMwa85gapQhlyNlvkt8BuiA
         /Btw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rYOd9wizCYaUeFDk8vdwrskKSmNukS8odvLKvLUR6ys=;
        b=D8gmyfJMkvKwVARERmsxWY3sby4Fa7fML8rWOlj3D3q4wtPjMWvdKgs2FBbCaCQHqX
         AIUKNl5CUolJtgHpW2mfjWQRLT8DVyVB6OtgemrvhRWBHzgsnQVx2k2PsNuiHwVObult
         Vro1FFM3b78eTkllJ6om7Q+4dcQPILJYaMEE9Zk9WQJDKD/6ok2eU/5iE4HR5gtivgaQ
         0pNT7gPQC7smkFan58T18O05xAam6feH47TolIlybfQ3PJos1ZEQile+NFQ7bXEG5Slf
         Q/lmee8oKRRll77AHMJD9eLvsgjfhzxEGU9wZGnagVjTzOR3yqnk0YVLzgXnC5Cr6Z/9
         wQrQ==
X-Gm-Message-State: AOAM5304GfhJ/8plN0sE3LlP8WQljR7WBjmGDroy1RII472m8nqq3Y/c
	vVzzqvh/BfQdUmfpXcSSjUU=
X-Google-Smtp-Source: ABdhPJzfGaAkik1aH71p6dFo8Ibvpg4ZQ5a6cNDuKt+/yewhrrybpaD8ApoVpykLdRug5aruXyYEbw==
X-Received: by 2002:a17:90b:38c9:b0:1bf:8668:9399 with SMTP id nn9-20020a17090b38c900b001bf86689399mr8900185pjb.87.1646813981861;
        Wed, 09 Mar 2022 00:19:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ee09:b0:151:da27:670d with SMTP id
 z9-20020a170902ee0900b00151da27670dls1133827plb.2.gmail; Wed, 09 Mar 2022
 00:19:41 -0800 (PST)
X-Received: by 2002:a17:903:4a:b0:151:be09:3de9 with SMTP id l10-20020a170903004a00b00151be093de9mr21754321pla.138.1646813981347;
        Wed, 09 Mar 2022 00:19:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646813981; cv=none;
        d=google.com; s=arc-20160816;
        b=mpNzQnEgKUpD42ABl1TIlhb+LIqVkCxyIc+GoxLmeZ29AmQLgMQH7NE7NvwPiXyHqM
         WWF5OokNflBh/TOSLDwCIu1Fq/x7kx4qSRsjWHBcaa8gt5+pb98f7zymOv1zL5HwkInC
         q4lGaQGjV94DXd5l4zYtG4ROoe14ao8BJv8DSiBmNTVLpcnn8Qpoi61dS3EghET8WP/A
         1hAZuCKDMLlg4UoG9QpzFPWHdf5WFa3LJHFS2RnSjHBPUBCrXr/6dJoI+LAuQ9eq9uWD
         uYYAIhV/P3pV1gRNenmA+5nPUrLX/lknn+qUqYA6DLgCrgO5PUPog92pdkGyuI05yrWW
         3dpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=CaCAAvfDCDaoKxEdA66+fje/StGnTpKfrPr4efsjt/s=;
        b=r0rOoricu0prrJ781Vh9PMvNsoxmTwK5jOWAoZy0kv/celewhKKFoaqU2g5eb5ywHR
         1DmkkjJvvlkXpTcZ0w955dFVhBBC0jt48a6EW2t3k0tfpBZaxRnL+q9nl2iZ0teasVGv
         Q33j8GdQf8rdnZAkpiqhARQApzyGDr95EjDXw4B5i7qYE9Q6zIwqfcMJGjyqsqU0+LR6
         RoTexjImVwYC5+HdsueF0dULvKpGbCZ6Cp/N+wMaAM2wjrYh4gluoW7EVlRlJpu+fw3j
         HNII/kca9V/0sSgergYaozP++hr7oPBgoBjG0iak5ukAD/OoZZl7WSttQ5SOgplkY7KV
         PfIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id j8-20020a62b608000000b004f71382081esi47888pff.6.2022.03.09.00.19.41
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 09 Mar 2022 00:19:41 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from kwepemi500005.china.huawei.com (unknown [172.30.72.55])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4KD4k241ZNzbc0G;
	Wed,  9 Mar 2022 16:14:50 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi500005.china.huawei.com (7.221.188.179) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 16:19:39 +0800
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 16:19:38 +0800
From: "'Peng Liu' via kasan-dev" <kasan-dev@googlegroups.com>
To: <brendanhiggins@google.com>, <glider@google.com>, <elver@google.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>,
	<linux-kselftest@vger.kernel.org>, <kunit-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>
CC: <wangkefeng.wang@huawei.com>, <liupeng256@huawei.com>
Subject: [PATCH v2 3/3] kfence: test: try to avoid test_gfpzero trigger rcu_stall
Date: Wed, 9 Mar 2022 08:37:53 +0000
Message-ID: <20220309083753.1561921-4-liupeng256@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
In-Reply-To: <20220309083753.1561921-1-liupeng256@huawei.com>
References: <20220309083753.1561921-1-liupeng256@huawei.com>
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

When CONFIG_KFENCE_NUM_OBJECTS is set to a big number, kfence
kunit-test-case test_gfpzero will eat up nearly all the CPU's
resources and rcu_stall is reported as the following log which
is cut from a physical server.

  rcu: INFO: rcu_sched self-detected stall on CPU
  rcu: 	68-....: (14422 ticks this GP) idle=6ce/1/0x4000000000000002
  softirq=592/592 fqs=7500 (t=15004 jiffies g=10677 q=20019)
  Task dump for CPU 68:
  task:kunit_try_catch state:R  running task
  stack:    0 pid: 9728 ppid:     2 flags:0x0000020a
  Call trace:
   dump_backtrace+0x0/0x1e4
   show_stack+0x20/0x2c
   sched_show_task+0x148/0x170
   ...
   rcu_sched_clock_irq+0x70/0x180
   update_process_times+0x68/0xb0
   tick_sched_handle+0x38/0x74
   ...
   gic_handle_irq+0x78/0x2c0
   el1_irq+0xb8/0x140
   kfree+0xd8/0x53c
   test_alloc+0x264/0x310 [kfence_test]
   test_gfpzero+0xf4/0x840 [kfence_test]
   kunit_try_run_case+0x48/0x20c
   kunit_generic_run_threadfn_adapter+0x28/0x34
   kthread+0x108/0x13c
   ret_from_fork+0x10/0x18

To avoid rcu_stall and unacceptable latency, a schedule point is
added to test_gfpzero.

Signed-off-by: Peng Liu <liupeng256@huawei.com>
---
 mm/kfence/kfence_test.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index caed6b4eba94..1b50f70a4c0f 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -627,6 +627,7 @@ static void test_gfpzero(struct kunit *test)
 			kunit_warn(test, "giving up ... cannot get same object back\n");
 			return;
 		}
+		cond_resched();
 	}
 
 	for (i = 0; i < size; i++)
-- 
2.18.0.huawei.25

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220309083753.1561921-4-liupeng256%40huawei.com.

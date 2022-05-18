Return-Path: <kasan-dev+bncBAABB5MLSGKAMGQE6U2LARQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 81F0552AF93
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 03:03:50 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id i8-20020a0565123e0800b004725f87c5f2sf306226lfv.1
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 18:03:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652835830; cv=pass;
        d=google.com; s=arc-20160816;
        b=oabsSb3GO8r3mSI2M/ruAM3oey1t65A/bIaKkzXqpMONK8pDhRMpwcR4532lM9lu9s
         DsB9t6hkucTg0gOu15vgpjF2oxB9udMcBo73gso+JC7taKKoJo9nsj2CxevZowXWgIHV
         Di9AXmqLt3mjoUANlob14WbghYg58FmPSxUIeYppUGBFRapataCHRYeqQ/gcy/PFIDQK
         RoIbYvhTft1tVV+bgQGOGudplyZPw9L53gcbpNvBMcVjJEn60LTLAzE1VukFUpvZlFYL
         lHFPWKPIi1xw3ibEA5QUvj6/gDT7KODeHvjA7fIC9pLPai6MH90kLCyVuwIYgHRkQLbL
         nHPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=8WeIGxusIcCpvS8QfaLjnzaCj9N6yBvdNTReOYDto0o=;
        b=MS8oVn2Aaf4N9NAU2kK9HVfgM4my5ZXNVRAQr/kl+S70xTi/ofwoSzkUKNAxjrmvsK
         CLBgeMc2fHYe+2ID7YU/nARmUPSNI7qcnPmsEHiMBQ7UGEnL+dvXfnSO2UoEmqbJh0Sh
         Gwtt0Fc0jdfiiPjFTq7pFuVjzXCpbH7yVeR7D7yHsd7ry+zjqpM+UCwoPolM9ObSc+n0
         27Flg/H+JLuPqTRzJPO5aZgIFQMxbDB3qgLo/lApeTsnEd7bLT52G3hkbFZj7f30F9ZL
         4ms+5buO0TdZOtC7DubundFWAfnACF5mO9Z6eCRun09G88MJ/rFmi4Os4R1PckWvGixX
         d9wA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="WmW7H0/8";
       spf=pass (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=liu.yun@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8WeIGxusIcCpvS8QfaLjnzaCj9N6yBvdNTReOYDto0o=;
        b=LCD0ebem73lAY5VKxKMb7vCngb3SsAIIfhpz0l+RFa+74UVQJHlk1dYeDSHUCbbfrl
         kwZi31eT62x9lDdop5gEv3C4ePIWwx7JdcCy/eNJhaOl/WziQ5jwngWP/mex+adUGmHf
         vofMH3AnYuZ9AHyCoHjN3dJnlZg/u9T9YeSkBMuozy51iS71MXBe4kS9shpKNiO8ow9r
         FB1yREpw0P3U9O8SIpAW4vqJzsW45HDC0MskR7VpXK8HVEw+AOHIF/Bnp4xUuw4U+Bb8
         l4q/jE0YgNjbuAGxqYr/9UQVNswPTnR+kavDgOkvNnyXnj0JJfoRI3Fk5em2Wft4TBMm
         xz4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8WeIGxusIcCpvS8QfaLjnzaCj9N6yBvdNTReOYDto0o=;
        b=TcpB10lh1SusnHcwcybqLQNvAH6D0FP79OYNfdnIOfwugNcW64IKpu+GCh9i7CM+ta
         UY7XtL1SOURpeGgnoAonPDL0nEzDuUSSch1JGZmE+vJDlZaCpaHwHB+9QCjg6QpSSOX+
         7Dj7qeq3SqM3HWj1SRYx6x+i55A/bYnpWvyR37gfnbNpLEd/m9lR/bfOqK0Epw52Ym79
         3ROURbMF3ssGJ531pUSjzJ5O7w1CjdOQ1uhch/GBn1xxSVwyfsP6pcu9M2Yk/CmocSFs
         VnhLzKJ+fK24b2fuEPaMgxZ2uVRVE05gSJa2Ccz4IEUL4mMjKmw8LlZmyOdc2l7oB7vU
         s8KQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530shS/8uwsmnG1Tkbqu9pTgmK3LOpGL9rEoYtipX6SPuQZaQfjk
	syBvgEXbt94UtMVjdQXMkb4=
X-Google-Smtp-Source: ABdhPJwhulFBwX7xn2j3Blo3xnWWRoj3gkhKCwMoqjdJbjQXGnfTnIXnHUKgflK9Cz2eCLrMQT7qhw==
X-Received: by 2002:a05:6512:3484:b0:472:13f9:4aee with SMTP id v4-20020a056512348400b0047213f94aeemr19021766lfr.288.1652835829914;
        Tue, 17 May 2022 18:03:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als12833598lfa.2.gmail; Tue, 17 May 2022
 18:03:49 -0700 (PDT)
X-Received: by 2002:a05:6512:c0a:b0:473:7b98:8d42 with SMTP id z10-20020a0565120c0a00b004737b988d42mr17958533lfu.511.1652835829016;
        Tue, 17 May 2022 18:03:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652835829; cv=none;
        d=google.com; s=arc-20160816;
        b=YGJFbVAiVMqEVO8rutFhaZfAH2rvvf1HQM56v1gPo99MiyGHvg0w1dqOHCAOc279fw
         TGTRzfQdKW5eY+HBrkEPhTVO+TgfVPJOgjFkByJhRB0C0LKq40L6wGztlGw4WZJnyC8l
         xHFqK4lYICdK2//UsCa0EsYXnQSOq2kvjArSmSsMzbtGRYZmSeiIIsY5E/+vXAp6Zjjm
         PbpYUapv5TovbNWoaBmGV4ZgXaDlA3Vsc5WkQl4IS1bGLLD6s1kP+8Bm0dD/iKgE40cG
         6EhLKXeRMuFmfRXyJhlz+zYoJU4FHLm+emRuOSnO8QNJcuco+C+enZ4bm/lm1hlBlyV2
         ih9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=IV8aCkpgePtdIt2HbGuwXZxBeztp0KNzc6pwPhSXF1Y=;
        b=EEBvleEx2TVw1mXJh/lT3fkDyZh0V6N8FL+hHI1DsLu7nCPFAizg7C8izVxVNQ/6E/
         pLV7koqxmHQSKChaElZbnxgmhFMXjdh8x/GtBezJIYWzxjorC74rsURy+PVZOy/Rwa4u
         Qsio1L7MYPuHFfqGzs+I0k6H1fZpLapGvuKqhAoREdtWiCjIaykTpRBUbG6YcbZlfE9n
         UQy6IePWtKXae9d14GnbdUBW7XwhGMhIGuN/2sMm4O+EVRfHhpMJvClGNKwwSICYJy/q
         1hQgsSHu5EcuWGLPn0daEidj7bkbgWoB6k5+Sf1irKGFpuJOzapGGykR+Hf0bPHIsfrC
         ISwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="WmW7H0/8";
       spf=pass (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=liu.yun@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id c19-20020a056512105300b0047238f0bc72si19598lfb.12.2022.05.17.18.03.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 17 May 2022 18:03:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Jackie Liu <liu.yun@linux.dev>
To: elver@google.com
Cc: glider@google.com,
	liu.yun@linux.dev,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH v3] mm/kfence: print disabling or re-enabling message
Date: Wed, 18 May 2022 09:03:19 +0800
Message-Id: <20220518010319.4161482-1-liu.yun@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: liu.yun@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="WmW7H0/8";       spf=pass
 (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:aacc:: as
 permitted sender) smtp.mailfrom=liu.yun@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Jackie Liu <liuyun01@kylinos.cn>

By printing information, we can friendly prompt the status change
information of kfence by dmesg and record by syslog.

Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Jackie Liu <liuyun01@kylinos.cn>
---
 v1->v2:
   fixup by Marco Elver <elver@google.com>
 v2->v3:
   write kfence_enabled=false only true before

 mm/kfence/core.c | 10 ++++++++--
 1 file changed, 8 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 11a954763be9..41840b8d9cb3 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -67,8 +67,13 @@ static int param_set_sample_interval(const char *val, const struct kernel_param
 	if (ret < 0)
 		return ret;
 
-	if (!num) /* Using 0 to indicate KFENCE is disabled. */
-		WRITE_ONCE(kfence_enabled, false);
+	/* Using 0 to indicate KFENCE is disabled. */
+	if (!num) {
+		if (READ_ONCE(kfence_enabled)) {
+			pr_info("disabled\n");
+			WRITE_ONCE(kfence_enabled, false);
+		}
+	}
 
 	*((unsigned long *)kp->arg) = num;
 
@@ -874,6 +879,7 @@ static int kfence_enable_late(void)
 
 	WRITE_ONCE(kfence_enabled, true);
 	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
+	pr_info("re-enabled\n");
 	return 0;
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518010319.4161482-1-liu.yun%40linux.dev.

Return-Path: <kasan-dev+bncBAABBTWBSKKAMGQEBK7RLCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BE8252B36F
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 09:31:27 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id i8-20020a0565123e0800b004725f87c5f2sf721250lfv.1
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 00:31:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652859087; cv=pass;
        d=google.com; s=arc-20160816;
        b=0nxQh2k24r+W4PPUbdgDXznMeihhUBXk7teHaElbjrwLB+tAZ41t6O/KsgFZ4lFllN
         svYRX0mo9E68g6nAtzZ6/0a8UYyxWnQfFoIqDCLJsehafV0gW2oTM2lrTRuTLrjHpANB
         FF525f0Zf+VisdGdhRpo0dWf8U96bHCxR3kl4Mttir8fNRiv5XbQMY1ynrQg0T1cMq5M
         k3K0/4+EPEHOZhOpfFS8nXcH01Jn8pBT3LfTviJfIaJcPmj+/6oLYvKrlrDXNV+DV+FM
         e1+bCw0H1lHYlam5Z9xzYYv+AqADE5H1hX4XenCByGDmg8x4W2mJF6qSDUp65F9JwS6w
         hFZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=PcQpPR/LhUZes/RUcRXVIivfJizQXYVk+55XpBZETLM=;
        b=v1FakPDDyULpyVD97m4S5tanTq+ZgtxTkzxuwb0NeWmuMEQZ2rnBJySD4O5Q97Ie/S
         wHRt7z/TWT4Lz8yiU5/lXuzQU6HsqRL3zXn57ibX4YeEsUbt6WvUkW6CoX1pP+MGNrMQ
         i9ITuWmoUDG1DCavz+x48MNMaveZIfkBDD9RN/j1R/w0JdFeHy5kKz9qU2ciWXtGA+DP
         hjWAgQgJvYdaP97F68oQdxXklRTezDVKWqne7g+GPVrpLn+EAswAriMz6kcJhveER8sS
         3rdVeBpWtmjK0itoRTZzJs+QZU7WPEgtCwEbs1y1oG0jyTB5I8cJQDVluRM++1FdaROm
         /3TQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZPPC2sJY;
       spf=pass (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=liu.yun@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PcQpPR/LhUZes/RUcRXVIivfJizQXYVk+55XpBZETLM=;
        b=dvtK6g2fc6HuHTCk98Ia3hd9kvzu9M4NspyZt9h++m3GdxO7TqNQgcsOTI3Gk3h5VI
         J2HKZwf4/Ykq2jPh543OuUj7apcOO3730Quaf1Rv+gcKls62ehzCQWfBaWU83QXY02QZ
         yCDr10d9pM/QwvDKYTKVvkJjKF/27THSkMot0qH1/jYCNXI5sBunDiz5ApoKGbp+Qchz
         Z+BJEPcbNSA38+ssaBJkiiDpOdP1JfqJyNhQ5If+QNb9BAuI0Ju0M7+zPEAX4w54o0Q3
         RiPajfR7XNQyXri00CnUBPNgdU5cXVR+q9qcoFy2OpUL6WMazoMdtCICJq6odZ+pXo6L
         xBfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PcQpPR/LhUZes/RUcRXVIivfJizQXYVk+55XpBZETLM=;
        b=QAS+sHmiQaOCp4GA3izpuc2DYLc4IDW1Q0YUNtpA6DF47a0BWm7tbQiTDgpoSrMONK
         jVRi3GpIErBWGifDy1iasbe6L3tg2aUFkJ5iIXyQBzEVffdVgbc8p4jNAihKoGKGfiAJ
         1zl28k6j7LD3fm09f/P/u9jb4jDhNdnt2ycFa9Vn+51Gr/z8tyjspmWJfFRjgyWrO+Dy
         FmOBqzRy7IMDOwxA38sfKg/4KjR0wWe24hM8GmcaobTOp35pQt86uHMKqyxJxd6eyVvK
         vPpIZCbF0GSchx5uYFd764WK7jCkkYHdD05w0t/Lpi+i7tfqXa7XE/5Bjn+JadqwZZrh
         F3vg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533omqHnCndR031+Dx3UnCakx2loZjJeL2iy+E5Ts1E8m898KifP
	Lzm9Q3m55xOYJewyqPkikBA=
X-Google-Smtp-Source: ABdhPJyu+7AveVYbV5mm8OPbrluOYV3TzZjAEvQQ3AtwwF0DO5GzxYuTivAE4jchLGy0clAMPSj9DA==
X-Received: by 2002:ac2:53a5:0:b0:477:b080:f59f with SMTP id j5-20020ac253a5000000b00477b080f59fmr3611386lfh.241.1652859086795;
        Wed, 18 May 2022 00:31:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als13387040lfa.2.gmail; Wed, 18 May 2022
 00:31:26 -0700 (PDT)
X-Received: by 2002:a05:6512:2510:b0:474:2364:bf5e with SMTP id be16-20020a056512251000b004742364bf5emr19037240lfb.323.1652859085885;
        Wed, 18 May 2022 00:31:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652859085; cv=none;
        d=google.com; s=arc-20160816;
        b=KbKkRJOZaxGH5osog78Zl5vHUp4sDktXdy8WfSihIh8yhYbCzNsqcXIYd8TPQqZ4YP
         O9kdcE6Otrx9qBr3ZHQZh6E2GxASDO/TymMU20Ew4u8Mggl3M2pFHgVgzw97As7sjQLT
         OD5jTmGSKyQSQdDGazn+hXN2imrwZYUOjtq7THDOD76ToByqIN5pg0O5AXpOMI5JtmI7
         CiMtLemvbH+qnHnesa5crA0k7mWciNiL38dePfCAlPK6hvP0cHyBEYBNIWq7gJEc2ORn
         95A7XJQYhRqFiaeJ7ZzzzXO5zgUrigJIgsspVV4173bUfiSpdXHn11htt4hjsIsU2Sol
         Kz4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=0EM8qsmNmS7Fmz5qE3a96NkBQN0Ii+hZn5vOwarbKn4=;
        b=C4degXf70tyXc7+yYhIVm0wKohsCgrE/r1c/02ZtiseuyxsDYddY++ZlnUliKjd8YX
         F2PMaBj80x3CywtTmLgSXa8DuEVGYqYU/vWUnKwxv5FTLrruYMrckWUYTZyQXC4q12Jg
         G2BzxWy4rLDzY7dbfxy+b7guiB3sTEIJ4fPZtEElPliMqPryFT4sy8TqcUpKA6YJPrxt
         dwwZSQ0dYAKcCUpTN//iUB/fyAe0SFfqIDYgPEwE/4JkaIpENmU1sfVznVOi12P6PXSh
         RtWMLyadmy7+2IWH+K463p+/WXeqhMmVbqm997TvbzH/Y9QrX3s9TC1yUDa6xBklSsOX
         cE6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZPPC2sJY;
       spf=pass (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=liu.yun@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id x20-20020a05651c105400b0024f0dcb32f8si55259ljm.5.2022.05.18.00.31.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 18 May 2022 00:31:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Jackie Liu <liu.yun@linux.dev>
To: elver@google.com
Cc: glider@google.com,
	liu.yun@linux.dev,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH v4] mm/kfence: print disabling or re-enabling message
Date: Wed, 18 May 2022 15:31:05 +0800
Message-Id: <20220518073105.3160335-1-liu.yun@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: liu.yun@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ZPPC2sJY;       spf=pass
 (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:863f:: as
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

Also, set kfence_enabled to false only when needed.

Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Jackie Liu <liuyun01@kylinos.cn>
---
 v1->v2:
   fixup by Marco Elver <elver@google.com>
 v2->v3:
   write kfence_enabled=false only true before
 v3->v4:
   cleanup

 mm/kfence/core.c | 6 +++++-
 1 file changed, 5 insertions(+), 1 deletion(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 11a954763be9..af0489d4d149 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -67,8 +67,11 @@ static int param_set_sample_interval(const char *val, const struct kernel_param
 	if (ret < 0)
 		return ret;
 
-	if (!num) /* Using 0 to indicate KFENCE is disabled. */
+	/* Using 0 to indicate KFENCE is disabled. */
+	if (!num && READ_ONCE(kfence_enabled)) {
+		pr_info("disabled\n");
 		WRITE_ONCE(kfence_enabled, false);
+	}
 
 	*((unsigned long *)kp->arg) = num;
 
@@ -874,6 +877,7 @@ static int kfence_enable_late(void)
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518073105.3160335-1-liu.yun%40linux.dev.

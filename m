Return-Path: <kasan-dev+bncBCAPVX4AQUOBBF6M5OBAMGQERN22Z2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E9FA347215
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 08:11:21 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id 17sf535914plj.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 00:11:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616569880; cv=pass;
        d=google.com; s=arc-20160816;
        b=MugH81jwMp8VjNsg5Hs6EaohYynJSWAtNJGz+ExOAVgMNQJAyr0Lf0yTDHsxY1fK6n
         eGmzQuB5s12+rhFxwyoXO3cwJWuaS7gJllr+Jq+w4opSDQfeTqfN7C6QLH8mMSCb3/zv
         Z8xa7+4zImoludF5DoJfPZ0wJRqiOPrh+O46OgTYIDaKuif/wY5gxKwTO7FIhB7seQUM
         K3y6sPvhEZUIhaX69ZusjpPaA1rovagjvUUOGmzwbXri9juhEmKLDhckXD7RcPx9vTHr
         Jx2s9SpGAM1YCW/M5iCAi8GZTxG2cUqgpBIvi+8ZL1KBMf4mno4+T8pbUGcp1RC2qmcx
         wmcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=KN2x+9o17OJrq6njiXPtgGiK4z7qiHxgWEiRCIGAqFA=;
        b=hRyUseHugLuubeTW7+thy5XrUPDQ7faThPmbG2wnnGecXSzkUaNvnrFBD5XcnagvR+
         ZkKTgkWlMc+yriid93MxdHy22505LceGnhncYpYHgxVex2R1IXWDrldB2hzFdXnF8o7c
         JiWjgq8hkDxPq9AVRrK4Mpgst2azADIfGFxozIH27VuT36rotEydC+fFXkLjoa16hhpm
         h36tSI9PTAEikBq4bMqcxRtZQIFvjpi5vQW0mqty3YHcRpUOmmbif4siQcyKZ6btByGg
         TEQobKLLUQZkD58bAIylGhLkbOkyn3l93glGDvr7pPwG42qTba67wUEmc1r4ilnWXYjP
         TIcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="I/b9W7kp";
       spf=pass (google.com: domain of tl445047925@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=tl445047925@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KN2x+9o17OJrq6njiXPtgGiK4z7qiHxgWEiRCIGAqFA=;
        b=kAISoLfa3+pN5KG/gj0xaLftGsNIQYsuVkxiiqPSWmkEMXq9CNT7axXJmfbhtrKMI/
         C7yM+mGdddZB+FqycQlEqBwlhudOAZkdXwvwPKWNWAnz1i1G0yXJzIIcnmmUsm9fP0j6
         0sk7ErCT2U+gH4ji747xzfOYPYMliadF+MIRpeFR6+hXxhhKW+WqI5hW0IFXKk6HXToj
         gYbuIsJesy/L5kBLf4eYSevU3OlzJFoKvdUA7DQQGXJY5NdUflwI9CUvdyn8x+q/+gvF
         qmcAO5qSms+luajZthonSGNLxqSH4InSqsXGn07o1GXY75LAiOZ2RWQ6TqvkzYKP0U13
         IsDQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KN2x+9o17OJrq6njiXPtgGiK4z7qiHxgWEiRCIGAqFA=;
        b=uz4wGx2yt0n1xGGZnhEFtrsFxYylZFDIGhhNFlmMt7rcqm4+do4twKGkV90PmWN4pA
         iW8A59XIFd9ya7d5Y9roivkxacO10wsHGZDT2bLdS61ayPavtqLQNUo25qnqTUKt7Y3l
         kVES+SvCpzG3diK9YSYePGKGksx5U3rggpAbBka/G4R7FdStPi/EahK47QoY3KerjnS2
         0NAAuweRCtcDaNP48okN/EVPvOye0aaDialvBJNNMvklmfJKp/znnkeX/hzJ3779DS1u
         YRg9V09tJ3zjW3lMnHZF7xKvRc5vx5T1gGFIFsEqn1mzVMzbzEk3axZtRf52Wtkll45r
         3TbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KN2x+9o17OJrq6njiXPtgGiK4z7qiHxgWEiRCIGAqFA=;
        b=V7XRVRsGoEW75ISg9hCdN7WRywr3gEDYAnJ4jAhUrZIjcY29MSR/no4Vfr9C5I41zS
         gkxeCGsD/GnJZqhdnt7kjlVXKceBWtecFsYnGU5/zxd6cXXADUQX9x8CsFnc4rG1Bjkq
         pE+LGhznarSoKXin/T2Qjsx8YvmA+IE3Z5i3QCqGdxFTMalew828zYviqNMcHc5lAmrQ
         /o9UB6OPLAnDSKeLXakr/3gxehtYnbxJ0JOYGuk43tb2G688shy28vhcjZo5L6aiFMV1
         dSkMk3wKIvqXco9K51IH7vSNbDGJNzymwBG59nXvERuqRwT3LOaWWcGe76PmIsdc7L0s
         MlZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533tRMJz9+bEhkhQNHkbtCAToc0rXMQUKh/p+zyeGq3Qvx4jxH89
	Y6dyXeLcA2T5iK5StVMGpYo=
X-Google-Smtp-Source: ABdhPJx6nO1Q5Xe/+bkRI3mgh2gK6ayGpZihTdcnniu40By1/RKKMHM8v4Z8OC4ug3t5zp2IuvIkYg==
X-Received: by 2002:a63:5805:: with SMTP id m5mr1851745pgb.370.1616569879900;
        Wed, 24 Mar 2021 00:11:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a507:: with SMTP id s7ls796420plq.3.gmail; Wed, 24
 Mar 2021 00:11:19 -0700 (PDT)
X-Received: by 2002:a17:90a:a618:: with SMTP id c24mr2082385pjq.108.1616569879287;
        Wed, 24 Mar 2021 00:11:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616569879; cv=none;
        d=google.com; s=arc-20160816;
        b=fzjbvqETw0Jgjk1pWLWY8xPkPLMwR1Ww5cHdCwLDa5NpsB/awYFYEB24CiCP3GaTfK
         WYh6Q//1/3tPbScqd9Od7Ay6Fd7gwOlCZsdUrM5sSeDI94zRDGeyuDZHwx1ofUUMFKWT
         /nWhpMyyP6Al9B0py2IiaWo+3qh9X+IfduK2oY5GsQXGkVqj0OmpF7cJvltmIUnu2zee
         1CXO1Y4Lp33yUs4vohKDQhTfpNvPBnoKkja7dSpLLe6xlJzc987SNuatmCZ+2BxrYXTA
         sb/HozdFCr7d0YHhy8atlHBMcw4smmPcqE3el0RHtlbNg3vyAZBhiGowTQSIVLF0LyzK
         3E3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=hOA91KZa0RMsWzyqfvojmi3qgn7CmaL9hdafy/3G/PU=;
        b=s8IkuY6A9ocXjeq2/NBZt6Oi24cZb7tR2lfGKjD+6/QOnxthmE7JUCK1I69ggdJSwG
         JgJD0KBkz6/0uoOR8VVaytp7s10VXwVTorDxces9VW3iYgIdhi9anFGUau83bnezx9M5
         92zJ/fZFG+SyzZwP5pHQnSNSUzc4DcqjuLLXeVxsGugksf4+Y/fbFmBQfm0khsZR9xIW
         UKjI1C2ARVA5cHNyDfDdFxn1mDgoxA0GeOr8Yo6Kls+QRrSvSjf2E0s50KdVdq0pY3A6
         zwavnpzaD7VM5lbOZd97o3z8v1K+bMVtOsgQEEt78NHtXwOHxmGbr01bCRwGBeyW3V8P
         orYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="I/b9W7kp";
       spf=pass (google.com: domain of tl445047925@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=tl445047925@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id h92si66186pjd.2.2021.03.24.00.11.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 00:11:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of tl445047925@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id g15so16671817pfq.3
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 00:11:19 -0700 (PDT)
X-Received: by 2002:a05:6a00:c1:b029:20f:1d03:7177 with SMTP id e1-20020a056a0000c1b029020f1d037177mr1981055pfj.17.1616569878872;
        Wed, 24 Mar 2021 00:11:18 -0700 (PDT)
Received: from localhost.localdomain (ctf2.cs.nctu.edu.tw. [140.113.209.24])
        by smtp.gmail.com with ESMTPSA id gz4sm1234228pjb.0.2021.03.24.00.11.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Mar 2021 00:11:18 -0700 (PDT)
From: Tim Yang <tl445047925@gmail.com>
To: dvyukov@google.com
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Tim Yang <tl445047925@gmail.com>
Subject: [PATCH] kernel: kcov: fix a typo in comment
Date: Wed, 24 Mar 2021 15:10:51 +0800
Message-Id: <20210324071051.55229-1-tl445047925@gmail.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: tl445047925@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="I/b9W7kp";       spf=pass
 (google.com: domain of tl445047925@gmail.com designates 2607:f8b0:4864:20::434
 as permitted sender) smtp.mailfrom=tl445047925@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Fix a typo in comment.

Signed-off-by: Tim Yang <tl445047925@gmail.com>
---
 kernel/kcov.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 80bfe71bbe13..6f59842f2caf 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -527,7 +527,7 @@ static int kcov_get_mode(unsigned long arg)
 
 /*
  * Fault in a lazily-faulted vmalloc area before it can be used by
- * __santizer_cov_trace_pc(), to avoid recursion issues if any code on the
+ * __sanitizer_cov_trace_pc(), to avoid recursion issues if any code on the
  * vmalloc fault handling path is instrumented.
  */
 static void kcov_fault_in_area(struct kcov *kcov)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324071051.55229-1-tl445047925%40gmail.com.

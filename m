Return-Path: <kasan-dev+bncBDDO7SMFVEFBBYEWUWJQMGQEP52NGEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id DD9E851188E
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 15:55:44 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id dp12-20020a170906c14c00b006e7e8234ae2sf1222087ejc.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 06:55:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651067744; cv=pass;
        d=google.com; s=arc-20160816;
        b=HvTSUKI7EmwEnsEfzk7Nlo3UX2ZG8dGifrozP5/2MlE7NuWV3euiFu/JI5arZx1pJE
         u9zU4WTyE6G7dN3NlclmwRQkGqvLdaKQ/BA2DtFZwRbXCSCvYRpAX24jLkSXsrEsf19Y
         ekkBCQsU506KdAgxMxr7R7dRkxN2WgHSg+5qN5YkBENXK0AX9+cszHyDpiBUM+wQ9hlf
         dkXfxHroRBDLdDZmb1chmH8QV1YvEFpBt3ajN9mqBUy/pNuNQcKhxdNseKcAPHXEeUyG
         Wwbx9fVOZxzU4fm96Y/z7MGKxsG3ntXGFZ83fb/tJdE8O41e11HMS76YvRVfZPjK7EOa
         2eig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Yuy7Ln3Z8iGDHYRJB1EmSybqnJWemC9k7n3EerRNMCU=;
        b=yMwWeib4YI2Obi4RZm7VysmT497bXj7a1SIzGxjmDrLOobpZEiNAO8toCJxdPPfdea
         3HhQbtrGz64RG0iZ+jFmoAkKa4x15vwFDrYXWiF97dHY+N021+e9VxTscpMA48hVt5j6
         OBJs208yiRZrh8VjwhBCUPFrOZQst9P7+6ZIKIztCdpNn+A/fC1e0003dOUJ5gSlkXjY
         znQ98teuEs8WZcX7mHkOp5QyOMeeJyoT4V7hWbmDUZcwh4nPQ7Yy4HGWZbC4s1zamj8L
         rQmcf2+/3OYQ3Zv1m4dyASC1L37+MiyL55CLP9dfOsINzKJj4X+oDSzH6smh0BiiJb7T
         INEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=WuXZAV5b;
       spf=pass (google.com: domain of jun.miao@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=jun.miao@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yuy7Ln3Z8iGDHYRJB1EmSybqnJWemC9k7n3EerRNMCU=;
        b=HhiNV+MrhzbddBdvySuEBmZYYpvBHqq34Jpi4MGonRyKBYgNtJDwzyQjnHyJkTWOeG
         cwvElJcvF3sr1MQhbZbydndTrIqsX9DDMmQh/AyOmW33B+qWiSWUl7adfliftWhi5YVt
         0J68nxzZoG1yzC7mR3UQS4mcwKEQcybQSTJKNnCnMjmc8+nXbRAX0774fbgyDjYv1rHw
         TzzUrIqiJuGRS6dyn67NFjEJyZKDf54rw3CG+RMDj5bdRiUi5TmapVlTMwPV3vF7/aMO
         It7LR0OU8RmTNoRcWZcTYXt9TzCf1meg/X3Zl1h7JQLGWWHkl2o6d+Jp+1TBVgB7fpDX
         ViFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Yuy7Ln3Z8iGDHYRJB1EmSybqnJWemC9k7n3EerRNMCU=;
        b=bP6vXHY/zSW4aeTaIYXcY9yGVQPm1NKNWjsOtPxhgJyUT/R2Cq6wRkBdj3D1OLgszP
         MQEf6UM3g4P9icC1uHKlnru5JhkXHaJZQ1L0ISyb9RsPE1Tm4douxSwmm/oaReq5h1XK
         oaGdtsO5PTRSrV/SGtW8PlyGSiEKd+tA7wafHcq75Gvjza6mrOB8jvyfOQXL4MCx8j2y
         JDZwPz7AYFZF9zyj//swWxchdU/QePYtUZY24qQK+Nwh/Q/uGqSBC/Y43cqAa1ZJ41xE
         bpA+MysSzHNKvRO5apeSvMDQaLDLbAzgxr+ZlM/iMFXhkFU0QMcJGFYCHaIHswqYU/yV
         ZFAw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530MHo202grRVEwl5RsU9zEXocpEcjkNKk+5JyvJUDnhJ0pF7jBa
	wFV5Kx+b79oSQbf8/aecgoM=
X-Google-Smtp-Source: ABdhPJys64oWjOKIFmf91SBk8JuHxR9Q/ldwBsqAAHSY6UzTU7kHM6LE6ZIQSxG/BH4B+eeTfXRyfQ==
X-Received: by 2002:a17:906:c114:b0:6f3:ad4c:c886 with SMTP id do20-20020a170906c11400b006f3ad4cc886mr9542223ejc.124.1651067744586;
        Wed, 27 Apr 2022 06:55:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:430e:b0:425:f7f0:fb74 with SMTP id
 m14-20020a056402430e00b00425f7f0fb74ls4146370edc.0.gmail; Wed, 27 Apr 2022
 06:55:43 -0700 (PDT)
X-Received: by 2002:a50:baa1:0:b0:418:849a:c66a with SMTP id x30-20020a50baa1000000b00418849ac66amr31193842ede.234.1651067743485;
        Wed, 27 Apr 2022 06:55:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651067743; cv=none;
        d=google.com; s=arc-20160816;
        b=oLWBJeSqJ/feeXYd5xcXdxvk36fYL9jB1wGq3n3Toe67qJxOOp2QWlTqOc8Uv2B26t
         6da2y1xMQAxSmSoez4IW3NyDYsPWb6n0rUBbL7iU+QBVwIDwv/wzg5kZ/Rw6k5CSivKj
         RKx3fSJEpZMVunP330qmbpf0LllbuOrrU81gJEpulN3sOx1LzZZ+nFfUfjG+JRWWtwW8
         8936WHergXz09/VQAPy5WDhYnT4xeDDLUosUzN+jdwKNYwsbbkptV9Flhd1xcRX0ROpu
         QoXkdzHt2hpRtVl/ulHuGq1mO8+RNGI5doUglJAXe4w2lf4QeZmfDb6VS73vaBjvqIWa
         lB3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=YGkcCUL5M/vzciD6y5Hc1c1GLdQkthAtXZg2UPJTZPw=;
        b=vgiRmys8j8ZBYRhBugWOcTs+rgRKNc6OrIdsrSjkysWDSSq5QbKk8LfFEMdR3qNcnf
         65RarqV8CzUCosUobAbpcEuw3JeUrQJVQr+U47L7tGPDuP0Mne+COT/aQuQlTGVMb8ZX
         s1pG5jReLbDNlsZVgwryfwfz7rREzcaBOKP9R9HaTXblHciS7oDeqaEwXSh9rnWRUhu6
         OgWwXdLiFz9WP/KpfHKaitbb1hq+Tz4C7pv71S9oZAocRDVLqiVsprvWJeKmqW6Da5lu
         SuHvMlwt6hQ+jQZBfMHGWy4DgNEhhH51ApUgB3E8MaxvNLa9J00iKh3JCEsPNPkX+Qgr
         uDhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=WuXZAV5b;
       spf=pass (google.com: domain of jun.miao@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=jun.miao@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga11.intel.com (mga11.intel.com. [192.55.52.93])
        by gmr-mx.google.com with ESMTPS id ec22-20020a0564020d5600b00425ac5c09aesi84756edb.1.2022.04.27.06.55.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Apr 2022 06:55:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of jun.miao@intel.com designates 192.55.52.93 as permitted sender) client-ip=192.55.52.93;
X-IronPort-AV: E=McAfee;i="6400,9594,10329"; a="263520403"
X-IronPort-AV: E=Sophos;i="5.90,293,1643702400"; 
   d="scan'208";a="263520403"
Received: from orsmga001.jf.intel.com ([10.7.209.18])
  by fmsmga102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Apr 2022 06:55:41 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,293,1643702400"; 
   d="scan'208";a="596287912"
Received: from ubuntu.bj.intel.com ([10.238.155.108])
  by orsmga001.jf.intel.com with ESMTP; 27 Apr 2022 06:55:38 -0700
From: Jun Miao <jun.miao@intel.com>
To: elver@google.com,
	dvyukov@google.com,
	ryabinin.a.a@gmail.com,
	peterz@infradead.org
Cc: bigeasy@linutronix.de,
	qiang1.zhang@intel.com,
	andreyknvl@gmail.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	akpm@linux-foundation.org,
	jun.miao@intel.com
Subject: [PATCH v2] irq_work: Make irq_work_queue_on() NMI-safe again
Date: Wed, 27 Apr 2022 21:55:49 +0800
Message-Id: <20220427135549.20901-1-jun.miao@intel.com>
X-Mailer: git-send-email 2.32.0
MIME-Version: 1.0
X-Original-Sender: jun.miao@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=WuXZAV5b;       spf=pass
 (google.com: domain of jun.miao@intel.com designates 192.55.52.93 as
 permitted sender) smtp.mailfrom=jun.miao@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

We should not put NMI unsafe code in irq_work_queue_on().

The KASAN of kasan_record_aux_stack_noalloc() is not NMI safe. Because which
will call the spinlock. While the irq_work_queue_on() is also very carefully
crafted to be exactly that.
When unable CONFIG_SMP or local CPU, the irq_work_queue_on() is even same to
irq_work_queue(). So delete KASAN instantly.

Fixes: e2b5bcf9f5ba ("irq_work: record irq_work_queue() call stack")
Suggested by: "Huang, Ying" <ying.huang@intel.com>
Signed-off-by: Jun Miao <jun.miao@intel.com>
Acked-by: Marco Elver <elver@google.com>
---
 kernel/irq_work.c | 3 ---
 1 file changed, 3 deletions(-)

diff --git a/kernel/irq_work.c b/kernel/irq_work.c
index 7afa40fe5cc4..e7f48aa8d8af 100644
--- a/kernel/irq_work.c
+++ b/kernel/irq_work.c
@@ -20,7 +20,6 @@
 #include <linux/smp.h>
 #include <linux/smpboot.h>
 #include <asm/processor.h>
-#include <linux/kasan.h>
 
 static DEFINE_PER_CPU(struct llist_head, raised_list);
 static DEFINE_PER_CPU(struct llist_head, lazy_list);
@@ -137,8 +136,6 @@ bool irq_work_queue_on(struct irq_work *work, int cpu)
 	if (!irq_work_claim(work))
 		return false;
 
-	kasan_record_aux_stack_noalloc(work);
-
 	preempt_disable();
 	if (cpu != smp_processor_id()) {
 		/* Arch remote IPI send/receive backend aren't NMI safe */
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220427135549.20901-1-jun.miao%40intel.com.

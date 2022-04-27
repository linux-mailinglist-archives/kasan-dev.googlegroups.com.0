Return-Path: <kasan-dev+bncBDDO7SMFVEFBBNEUUWJQMGQEBDCIH6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B22B511883
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 15:50:45 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id i131-20020a1c3b89000000b00393fbb0718bsf1708395wma.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 06:50:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651067445; cv=pass;
        d=google.com; s=arc-20160816;
        b=lj/N3VSPGSiFUunqKuOf+ntKZTxfFIYZG/+VFUauJSgsVbfm7WJKtkM9GDXt5MFAA3
         6BAck+dNddYM515NyvZj7d1AfCB1tNrOFv1ZoB0lX8wxCt0aL6veQ5gY0+gJt0QMrSVX
         3vhtjHReq5w8GXVxtDYXvc4ZElPY0zkJ7m2+anPAQSPNkNIhS3fZXiGWt1lugORT5nSs
         Vvu6g/NttndwFnURgbsiFnVSMZ1GvYF2XuNvxCXmDzdOcITy5u6zYdes2/b9qfO508+Z
         knU4jc2HRfJkqfqLtLNk4f5uL395ilOZd88+m4yVL82krcFHHNWEXC8Coph/Dwq7WSDx
         XDbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=dNBY60JzeabJbm8L9vX56OiNYfNgPxNrjGLWEW4ViGo=;
        b=0P0sPfsZylsq3KqfeML5XKoE9cmmSnGnordG/3VdE49pIscyft+fI2S0sqTPcWDyv2
         TizKzz1dLMIRS4EbTFk7c3xEX0qrfJzXPX+W2aqA+tamXZXyaQPZv6Af425ud4pv8elH
         nI29n6Y8uNBo7PCfaOAAtO0PUP2XzK9SZmOU64KveDCn6VrvPaHRh9vRT8OtKYEHQT12
         r5PfskcsEnuD7dmyrPIA1UMZq7kv15YMzWjHtPc3N53Jc0aO4G09+2Cwaqs8hAiAPzBa
         CUtL5kQ9LLIvdaEVJ8n6LUB5EF6fvd8J3hzp6MvPh4e2ubecG3H2qMn5atBy8cwi7EBv
         ZxCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UIgoIHZS;
       spf=pass (google.com: domain of jun.miao@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=jun.miao@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dNBY60JzeabJbm8L9vX56OiNYfNgPxNrjGLWEW4ViGo=;
        b=hWelPZO0pJ6o0aUZfJChs4Sb7+04u+tmcqWRKo8Es18+zF33SvRlHvZn4hWPMlmj1+
         ljHnKHsOoVJqO0iRSHIZFxeWo06W2qGqBsTQ46h0YfPNcohHDvelDjvAE316HzMRBRVM
         gBvdTCGgSlSDB1BlWZ2HOJQ39MvVMnlWGFH6Tlo07Fy1PziMiMmbPE1sW78VueeZhUn6
         mqC8NF9lIr27GLyIrRv4lEgL4MQOvM1JqbA2ed9xy+lKlRE6b4jYLCy910MFSEg4dn+f
         +oVtil9TwAunypQDjNaZ39g0RTGG2UpqD8r75qfNFUHx2U5rXIgXTFTl01WsN7YCvPoG
         k/2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dNBY60JzeabJbm8L9vX56OiNYfNgPxNrjGLWEW4ViGo=;
        b=4b02zgxPXoPGcPYy2Q/45/XXmlYLmbNizwV3hMmzrcDJegzyDLLFfOYQYi+m2PqBAR
         78vSZUkgJvnlif+Jl/Z6U5oh9PDhaKpeAJqzMss9kvrAT+fBH5T/6VryIS3nnzLq8h+a
         iml3a087Ho7sxz74WiDc23qPavPFP/HNfxVeYR4mV/RUM1FGw8JxFfYMFOMkkQ4pV+Xo
         NrdvDaW2rv4DCleKCylgCQsjcEIhMLB0ZKdJ9xkfBE2hOy+sl0D/lEQ0NcQ5GGqVreQt
         2oyLw2+eqxxUQrCodsm0yrsYTmsZo0EpqZFCv4pEOy3eHeoPEuZ8TH7314ByNnJMdmNo
         6BTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Rnn1SZtsqDmP655YOxtHcHZ4erkTuhM2gy/tZDKBmjb8rNsC2
	VSwkpqo/iq1/aIRT7iW36IA=
X-Google-Smtp-Source: ABdhPJym4jDXhnzrBTJaBefEKnMJtWyUx7unc1Es2mXsjfQLhSdrpBTqMV+vBEjyNQ56n2RhcpDjhQ==
X-Received: by 2002:a05:600c:22d2:b0:393:f4be:ea1f with SMTP id 18-20020a05600c22d200b00393f4beea1fmr8751670wmg.51.1651067444860;
        Wed, 27 Apr 2022 06:50:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c9c:b0:393:ef44:c49d with SMTP id
 bg28-20020a05600c3c9c00b00393ef44c49dls1118646wmb.2.canary-gmail; Wed, 27 Apr
 2022 06:50:43 -0700 (PDT)
X-Received: by 2002:a05:600c:2e16:b0:393:e950:4e35 with SMTP id o22-20020a05600c2e1600b00393e9504e35mr16815696wmf.90.1651067443873;
        Wed, 27 Apr 2022 06:50:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651067443; cv=none;
        d=google.com; s=arc-20160816;
        b=HKzcmh99XB6mUwYKvi0FrgnnH0Kfc7yFsRe1ifWjaqsZmoN0BofMSQdiQXNvTz7z/0
         Ror5nL+v2xiSV0DFMXPCQLeaUUBwW74CIekKM1nDq8o9q8vBOB9HmQiy8fF//x1oUEPV
         OaajE03CjnZ5dJXbRYYFc+/DBoPCszX+r6cGWGhn4p5DLWvADYV8mh+pcxlrD/ezqzU9
         ZT4AgpnDwDC/DQhamrdDyqCGg5Jw5aSZs6Tr8RrrDo+m3QJRCwO5fGoFMSv8LQjNtT6v
         u4g6lCkx5nfQpRxqV4XiKOEuNyZfJWtKqXnO3lWHVTbD3JmDXLxRD0ftehr69WFw2fGJ
         463g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=hj/DkZtca5+QEBACAVJiGqM41odxhA/p1iN7Al7NCrc=;
        b=dZWlvcn4YRSHZIr1qI/3oCIO9QPbk4YTJZySVy0hFHkYTQd6NsR3Fe+KL1yb8P3hwy
         2dnEEH1ubNmQP9FZKKfGog6MMdoiLHMeWghyM5+S3zSiDpvK1zg/Sidbg4lNDZ7CsHVq
         gouR1DXHpPhW3YuXJWCovhrnnDVk6Q600V8OxFBe74pozuw1Q5raxsjbz/lwgk/5j/yg
         q14XuLm8tTFKF2wpfQg9f/fDTpaP6jUk2ZA3tCNGeH9IBNuCUNwhTA+J5fM/3t2XbSWo
         KsfEdTDq9YlQp5nUZZAJgFk8Olh4lSBCL3wTSu4/cqLhegbo/Jgj3mhHIR/2jZMNMOiU
         VlcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UIgoIHZS;
       spf=pass (google.com: domain of jun.miao@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=jun.miao@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga17.intel.com (mga17.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id m14-20020a05600c4f4e00b003920a4a27e9si181624wmq.0.2022.04.27.06.50.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Apr 2022 06:50:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of jun.miao@intel.com designates 192.55.52.151 as permitted sender) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6400,9594,10329"; a="246493860"
X-IronPort-AV: E=Sophos;i="5.90,293,1643702400"; 
   d="scan'208";a="246493860"
Received: from orsmga005.jf.intel.com ([10.7.209.41])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Apr 2022 06:50:41 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,293,1643702400"; 
   d="scan'208";a="730808148"
Received: from ubuntu.bj.intel.com ([10.238.155.108])
  by orsmga005.jf.intel.com with ESMTP; 27 Apr 2022 06:50:39 -0700
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
Subject: [PATCH] irq_work: Make irq_work_queue_on() NMI-safe again
Date: Wed, 27 Apr 2022 21:50:50 +0800
Message-Id: <20220427135050.20566-1-jun.miao@intel.com>
X-Mailer: git-send-email 2.32.0
MIME-Version: 1.0
X-Original-Sender: jun.miao@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=UIgoIHZS;       spf=pass
 (google.com: domain of jun.miao@intel.com designates 192.55.52.151 as
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
carfted to be exactly that.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220427135050.20566-1-jun.miao%40intel.com.

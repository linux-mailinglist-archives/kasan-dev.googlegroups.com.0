Return-Path: <kasan-dev+bncBDR6TU6L2YORBHEFQ2QQMGQENDUUNZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 498A36CA2C7
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Mar 2023 13:48:46 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id h16-20020a0565123c9000b004e83f2f56e2sf3367576lfv.22
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Mar 2023 04:48:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679917725; cv=pass;
        d=google.com; s=arc-20160816;
        b=k94wgvLkhshU4y+NIi/E6A5VoGvVG2xS0Ss1Ph4NWEZyYQgljSiZIdrfaLQOpoE/Py
         8nGPZkZelpAoyS1+eoVMIKNK94u/2NYQpmjacb3m+CIwqB0lDknA4NPLwTjWkR+rOyvR
         o+dL28l5opNdhNrQ0jUfzsm7AosJiwRViPeDkpkn0kYQKD2wCALCRZoA5WRgXYSX7g2d
         vUwhpKZLK8LUpH27jSK4IU2YeAtsR3dd5vTJpvM+I7ud5KY5yZd/PJCZBQvjyH4tX4zD
         1izjaMag8hkF23g8HL0l6YEqntNCXiLjW5Q67LDCwmuPyY0xIhIjo+qbc41sEzDL1tF3
         HS7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=pD1LjAkKzI1WY1Qm1zwjlr/6fQVuhl+U3QDLxDXcDFg=;
        b=zRwu6mRSQ8HYB3a77GCNUlRUZ69tVkCGqJvdOq0RSV3tms8PgMtta5foYRdtdkNYIV
         PXDHqGaVMPf4Cz6I6KJ7P4WDo6FzY1s38daQ9dpccmyZpzKDyMI8gtPIAk9zE3wb0Z1A
         y8WQOEGsWfx5F4pSatGDDhDBbkChCXDe6kcdcIa649xH3rVpXSyQzBY/Pla+1fAghYxq
         ZmLxHAWXJA7hWcl+i1Klao5wBj6V7VUWqfcsUae58lNgmfoVdW9U0XlmwFGlxMIJEUvX
         ctO8sPbXEcejttGANZAvLbCiVlgljgcTPui7FrNndUo+2GBDjIFhGf2chdt+2tY0Lej5
         VW2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=NMpqkPK5;
       spf=pass (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=qiang1.zhang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679917725;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pD1LjAkKzI1WY1Qm1zwjlr/6fQVuhl+U3QDLxDXcDFg=;
        b=Nl+3N9uiDFb8bIwRxJmNyKicBqLGZTOCWGjE0RmmPADhry42B3SRxbWrLQM6KMenVr
         EfvNsgWvykDjtuyEQxUMnRsW5LXQ9Nq1y64zOl6KTvQ1NtZ4cmhiIT1zzLoH0gPRHXZA
         5qfiAoBGZ2WvNpBD70yntt8MHouwCYcRLPeEEvlpQFT6z9Awy8+UkwDPKwzHbGvhwlCW
         q4rScXpi0d1z4tVcOt9D2NZjcBQafCJghPboXb7rswxSnn+TQNzsJjrAg4edonm9eCBa
         TwJh1maqC+CKjzI6NuDPLH7iQuAuXmvKzseA+7Dxn86nQvAQwMgO6TdnUen/JoVF27Ph
         r5iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679917725;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=pD1LjAkKzI1WY1Qm1zwjlr/6fQVuhl+U3QDLxDXcDFg=;
        b=COa3LBKAlY86dI6jgFE7PE+u9c0zd4CNJdsq8fpGdfIwH5T5z0ysJBS2KM5F1JVdJl
         fW9x71d06jLWwLkdVAhn3KhsoGMR735lyEJGY5gxliDGGn0B+Rxg4zVl0+pXXnzr0DHE
         2Z0z8tqECj42SngJP1gU0N3CisEanETL22bs5oBd3u9IyyRd7FlpYNBq8p6M2JxMSLRp
         YZCRCqWJJ11HoSgjO7DGNkyPbc3O4Lq16l/BJpOHCWLTPi1meFHtGxC5rdX+aNOFOGIn
         bqavVbxvIQ7Thr35cFxI4c8yHbrhC+fPeiH6NGJ9CZpkh4nPrExuArU4Gxb4JzxoxCOB
         9Hsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXKIB5oa8R1k3qGblqEKgOhapZss+SBtrKFd0CV4Gqtr+rqU5GU
	5VHHMPcPJdIbKEiVeit3lDM=
X-Google-Smtp-Source: AK7set90etb5QEq5bTkxr08BRxEjSPYmlDoyc/JLg76MVeR4JEzV/sbldTMQGwf+/c61+aKPOzTC0w==
X-Received: by 2002:a2e:2a84:0:b0:293:4ba5:f626 with SMTP id q126-20020a2e2a84000000b002934ba5f626mr7938202ljq.2.1679917725113;
        Mon, 27 Mar 2023 04:48:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:220a:b0:4e8:c8b4:347a with SMTP id
 h10-20020a056512220a00b004e8c8b4347als1127231lfu.1.-pod-prod-gmail; Mon, 27
 Mar 2023 04:48:43 -0700 (PDT)
X-Received: by 2002:ac2:43b3:0:b0:4dc:537c:9230 with SMTP id t19-20020ac243b3000000b004dc537c9230mr3576655lfl.8.1679917723666;
        Mon, 27 Mar 2023 04:48:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679917723; cv=none;
        d=google.com; s=arc-20160816;
        b=hy/S7TSIvn0DMMxDqw9AWpfvdab/Qz26rRoMkIXt0eNwvU7a3HLmzbRmS5sosCPJpO
         +E47TKZQylLDMJcYy/Kzl3AIE9yvAjfGK8V3KWdl3VT1AlVHN9dG4cMkgsAfY99wtXBp
         PZKJVNbS12k+MKP8pbfyxCicioqYO+kaTUtL7LT7/FiNLyn0FmGzzOpOuyWjPWYmeaG/
         R18T5J3pMZSDV6D4Tm9nvutbC+pk1h1VjPiQbROsbDT5XqS74XXG26zGUGocZaEjkY47
         a0Yhr18goh+EJrUHFYNwGXRnV1twrPFZ722SvDVhqg3sKRNhsnd8wG4NaRV5QRUR/070
         Hb0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=dRBep5lc51rHinPLsYgIdaYCBvQ2OFUEgPoX9GAnIl4=;
        b=WyaEGSGeFCllG9FV+Ckv2xH0WuVrnUqCW6g1gOuHi5asPF+o3hgLBsGMqyntZ5G6QN
         jHkidhH85lgQ2fWqsxZJ/0Gv1+aSXmzCMREsUCqfuEm0Xc4YP37PhK9CHa/sl50dXdvV
         MmORWueE9qV3aQr7q9tg4xL3X/9Dlyqx9VHpLTAyFlZkPuW4yR3EMnttcCaURmzZyq75
         7MPjIWaLFGghgTu8g7mjFqwx+3Ecsp6cx+qjvu2fdsx6zlWUZNLt8nJnQrX8qJM4Ry7x
         nihBtWmfTWH3m7YB5MpVkSFkxTncfSwV4flhLXiMFqK0PtJHSBFhzFYCvJo/vmcuo0KG
         TdtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=NMpqkPK5;
       spf=pass (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=qiang1.zhang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga05.intel.com (mga05.intel.com. [192.55.52.43])
        by gmr-mx.google.com with ESMTPS id be9-20020a056512250900b004e83bb20554si1529900lfb.3.2023.03.27.04.48.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Mar 2023 04:48:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.43 as permitted sender) client-ip=192.55.52.43;
X-IronPort-AV: E=McAfee;i="6600,9927,10661"; a="426505740"
X-IronPort-AV: E=Sophos;i="5.98,294,1673942400"; 
   d="scan'208";a="426505740"
Received: from orsmga004.jf.intel.com ([10.7.209.38])
  by fmsmga105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Mar 2023 04:48:40 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10661"; a="807446061"
X-IronPort-AV: E=Sophos;i="5.98,294,1673942400"; 
   d="scan'208";a="807446061"
Received: from zq-optiplex-7090.bj.intel.com ([10.238.156.129])
  by orsmga004-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Mar 2023 04:48:38 -0700
From: Zqiang <qiang1.zhang@intel.com>
To: elver@google.com,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2] kasan: Fix lockdep report invalid wait context
Date: Mon, 27 Mar 2023 20:00:19 +0800
Message-Id: <20230327120019.1027640-1-qiang1.zhang@intel.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: qiang1.zhang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=NMpqkPK5;       spf=pass
 (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.43 as
 permitted sender) smtp.mailfrom=qiang1.zhang@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

For kernels built with the following options and booting

CONFIG_SLUB=y
CONFIG_DEBUG_LOCKDEP=y
CONFIG_PROVE_LOCKING=y
CONFIG_PROVE_RAW_LOCK_NESTING=y

[    0.523115] [ BUG: Invalid wait context ]
[    0.523315] 6.3.0-rc1-yocto-standard+ #739 Not tainted
[    0.523649] -----------------------------
[    0.523663] swapper/0/0 is trying to lock:
[    0.523663] ffff888035611360 (&c->lock){....}-{3:3}, at: put_cpu_partial+0x2e/0x1e0
[    0.523663] other info that might help us debug this:
[    0.523663] context-{2:2}
[    0.523663] no locks held by swapper/0/0.
[    0.523663] stack backtrace:
[    0.523663] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 6.3.0-rc1-yocto-standard+ #739
[    0.523663] Call Trace:
[    0.523663]  <IRQ>
[    0.523663]  dump_stack_lvl+0x64/0xb0
[    0.523663]  dump_stack+0x10/0x20
[    0.523663]  __lock_acquire+0x6c4/0x3c10
[    0.523663]  lock_acquire+0x188/0x460
[    0.523663]  put_cpu_partial+0x5a/0x1e0
[    0.523663]  __slab_free+0x39a/0x520
[    0.523663]  ___cache_free+0xa9/0xc0
[    0.523663]  qlist_free_all+0x7a/0x160
[    0.523663]  per_cpu_remove_cache+0x5c/0x70
[    0.523663]  __flush_smp_call_function_queue+0xfc/0x330
[    0.523663]  generic_smp_call_function_single_interrupt+0x13/0x20
[    0.523663]  __sysvec_call_function+0x86/0x2e0
[    0.523663]  sysvec_call_function+0x73/0x90
[    0.523663]  </IRQ>
[    0.523663]  <TASK>
[    0.523663]  asm_sysvec_call_function+0x1b/0x20
[    0.523663] RIP: 0010:default_idle+0x13/0x20
[    0.523663] RSP: 0000:ffffffff83e07dc0 EFLAGS: 00000246
[    0.523663] RAX: 0000000000000000 RBX: ffffffff83e1e200 RCX: ffffffff82a83293
[    0.523663] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffffff8119a6b1
[    0.523663] RBP: ffffffff83e07dc8 R08: 0000000000000001 R09: ffffed1006ac0d66
[    0.523663] R10: ffff888035606b2b R11: ffffed1006ac0d65 R12: 0000000000000000
[    0.523663] R13: ffffffff83e1e200 R14: ffffffff84a7d980 R15: 0000000000000000
[    0.523663]  default_idle_call+0x6c/0xa0
[    0.523663]  do_idle+0x2e1/0x330
[    0.523663]  cpu_startup_entry+0x20/0x30
[    0.523663]  rest_init+0x152/0x240
[    0.523663]  arch_call_rest_init+0x13/0x40
[    0.523663]  start_kernel+0x331/0x470
[    0.523663]  x86_64_start_reservations+0x18/0x40
[    0.523663]  x86_64_start_kernel+0xbb/0x120
[    0.523663]  secondary_startup_64_no_verify+0xe0/0xeb
[    0.523663]  </TASK>

The local_lock_irqsave() is invoked in put_cpu_partial() and happens
in IPI context, due to the CONFIG_PROVE_RAW_LOCK_NESTING=y (the
LD_WAIT_CONFIG not equal to LD_WAIT_SPIN), so acquire local_lock in
IPI context will trigger above calltrace.

This commit therefore move qlist_free_all() from hard-irq context to
task context. 

Signed-off-by: Zqiang <qiang1.zhang@intel.com>
---
 v1->v2:
 Modify the commit information and add Cc.

 mm/kasan/quarantine.c | 34 ++++++++--------------------------
 1 file changed, 8 insertions(+), 26 deletions(-)

diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 75585077eb6d..152dca73f398 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -99,7 +99,6 @@ static unsigned long quarantine_size;
 static DEFINE_RAW_SPINLOCK(quarantine_lock);
 DEFINE_STATIC_SRCU(remove_cache_srcu);
 
-#ifdef CONFIG_PREEMPT_RT
 struct cpu_shrink_qlist {
 	raw_spinlock_t lock;
 	struct qlist_head qlist;
@@ -108,7 +107,6 @@ struct cpu_shrink_qlist {
 static DEFINE_PER_CPU(struct cpu_shrink_qlist, shrink_qlist) = {
 	.lock = __RAW_SPIN_LOCK_UNLOCKED(shrink_qlist.lock),
 };
-#endif
 
 /* Maximum size of the global queue. */
 static unsigned long quarantine_max_size;
@@ -319,16 +317,6 @@ static void qlist_move_cache(struct qlist_head *from,
 	}
 }
 
-#ifndef CONFIG_PREEMPT_RT
-static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
-{
-	struct kmem_cache *cache = arg;
-	struct qlist_head to_free = QLIST_INIT;
-
-	qlist_move_cache(q, &to_free, cache);
-	qlist_free_all(&to_free, cache);
-}
-#else
 static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
 {
 	struct kmem_cache *cache = arg;
@@ -340,7 +328,6 @@ static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
 	qlist_move_cache(q, &sq->qlist, cache);
 	raw_spin_unlock_irqrestore(&sq->lock, flags);
 }
-#endif
 
 static void per_cpu_remove_cache(void *arg)
 {
@@ -362,6 +349,8 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
 {
 	unsigned long flags, i;
 	struct qlist_head to_free = QLIST_INIT;
+	int cpu;
+	struct cpu_shrink_qlist *sq;
 
 	/*
 	 * Must be careful to not miss any objects that are being moved from
@@ -372,20 +361,13 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
 	 */
 	on_each_cpu(per_cpu_remove_cache, cache, 1);
 
-#ifdef CONFIG_PREEMPT_RT
-	{
-		int cpu;
-		struct cpu_shrink_qlist *sq;
-
-		for_each_online_cpu(cpu) {
-			sq = per_cpu_ptr(&shrink_qlist, cpu);
-			raw_spin_lock_irqsave(&sq->lock, flags);
-			qlist_move_cache(&sq->qlist, &to_free, cache);
-			raw_spin_unlock_irqrestore(&sq->lock, flags);
-		}
-		qlist_free_all(&to_free, cache);
+	for_each_online_cpu(cpu) {
+		sq = per_cpu_ptr(&shrink_qlist, cpu);
+		raw_spin_lock_irqsave(&sq->lock, flags);
+		qlist_move_cache(&sq->qlist, &to_free, cache);
+		raw_spin_unlock_irqrestore(&sq->lock, flags);
 	}
-#endif
+	qlist_free_all(&to_free, cache);
 
 	raw_spin_lock_irqsave(&quarantine_lock, flags);
 	for (i = 0; i < QUARANTINE_BATCHES; i++) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230327120019.1027640-1-qiang1.zhang%40intel.com.

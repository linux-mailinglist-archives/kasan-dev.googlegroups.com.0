Return-Path: <kasan-dev+bncBDR6TU6L2YORBEGEQGQQMGQE4VSHO2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id CC1636C9615
	for <lists+kasan-dev@lfdr.de>; Sun, 26 Mar 2023 17:17:37 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id z20-20020a195e54000000b004e9609a300csf2396795lfi.2
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Mar 2023 08:17:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679843857; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nf56vHKGMqXhDUY6hragrrNYSzgX8IdDzXESKYZ33Tvsu29X3U5TEgMb2AVUBdBfss
         REPFyrRJGDPAlf5lObB9eYvEaBYtdZXOWNfAbflDpYr4TnpxJMdWd9jjYvnHO0H3CZlC
         3mFM7fZMekbXIj7zES4gmod9TAbKEmLmWTcUrGkYn/JEEOnPZW8SR6tSkDEIPdRDY7HY
         F8ZeGd0mqNOdyDFSCfqh4r6OjG2+5xqzA9BF7zWHxrf3OFheOlnmG94JCNuLU8d1oWWy
         oxHrLoizQ4ckHExWWQ0FGwsXh0OOfaS8Ax8ZeyeUJUkm1BXW3GozsSdxAXkxWxaTjuAv
         W16Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=CV5FoovZsrmlgjXpMIgvBIZI6BJUtZts4DBFVVWedXQ=;
        b=zw0bSfE8s1kbFz06Rs7jWIsjOcr50toIeib34Ja6LxUIIyl0sqK9MJm65sS2LyHkuw
         kG2mcIpRTnplnTgaXQW8v1G6sGt3xvQsc3Yh+/ep7uN3eyisSMwUxAZrPiLy20suHbnm
         +Y4F9yCcMQ81yZKnniLWNsetMctJpfE3ECAo3n693ZNyg0ejrrzYyPSdnVouaGtVFVDk
         MtCj7X1Ago0j0yabQTjNfE9rmZQXgeFkmKHrsKU+kqdXchFmg3zXrUDIDKd3a4iK34c9
         NXsPwXJdUVJblAyX/XfpOc69bZ/7J68Dfha//ecS2mdKDsNeJmgWGbpYykTdvl9dgzk3
         84wA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=gh5keFjM;
       spf=pass (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=qiang1.zhang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679843857;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CV5FoovZsrmlgjXpMIgvBIZI6BJUtZts4DBFVVWedXQ=;
        b=l4KnriPjbGDoxaRKNLvxJPMNueH7qtLusY79CpnVC69gQG5+Nk54pezmG50L5lEuNx
         RUyxvldplB02yFcVt1bYC7oR1Nys2A03MiJX6OW88UPOdRxMgax2B9vODt3yCP+JgqqV
         A1AV1rXDNIKZ4vcXsx9IB+vfSbeJBCeoPsCUGDZ6FM8t+9BF4gJRXlHs+FULboA0rUk1
         1+6u9bbDSQi2/s2ewKfaRBHeyZSKf3maOuXGcuAo3qzIy+jX54ZCzXwz0fbUAZii+Z8R
         wkTnz1n07LVJo9XQYRg29pkbMsy3wQQ/cfoPa2pSIQ0U4HLrRRs9BkSA5rWTeYXdQdpP
         dOig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679843857;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=CV5FoovZsrmlgjXpMIgvBIZI6BJUtZts4DBFVVWedXQ=;
        b=W+iTTY59UFA6PWyxBgtiGA0byIKslAi0V/EBzI780A6bMaFpZRdF3bI0mBPSb3Getk
         cBQIfIZESTTEg1/H2CijG0leyEsG8aDkvi9KtfOr4bW+ozXPkdWtkfPhU1C4aSkswIdN
         bDIeA+C5h3TE4Lu4LUix1IBBTEpV+ixIKONp6hEc7nqKaFXmM3nP9sYrOHgIibdYcKra
         V4qzD3wmkkXeMDHg+nVKGRKhp75ajzD64NCo8kXAQJCWukLAL87MmrnKQEsYWkmPito8
         gTcKVAkNs2jLeZTc10gW57lCesXbJkwWe90C2aSmaRXy9dPYfpAEEiYPeV1WHNpTSdQx
         3PAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9esmwLmFNon7Ckimb3Q86hGioynuZcH5M2LqZACJmvHr/Ggb8YL
	b7UQSi2vM1i28OIz1w5vITc=
X-Google-Smtp-Source: AKy350ZLVsZ49rxR/Sy9Z0UI2u91XIdcFiTD9OReUzRCr63Nw3wqiqcjpGOUvX2JLOGCTRvJiVx++A==
X-Received: by 2002:ac2:5610:0:b0:4dd:a4e1:4861 with SMTP id v16-20020ac25610000000b004dda4e14861mr2466564lfd.3.1679843856803;
        Sun, 26 Mar 2023 08:17:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3da0:b0:4e8:3ee1:db1a with SMTP id
 k32-20020a0565123da000b004e83ee1db1als318018lfv.0.-pod-prod-gmail; Sun, 26
 Mar 2023 08:17:35 -0700 (PDT)
X-Received: by 2002:a19:c208:0:b0:4b5:2ef3:fd2a with SMTP id l8-20020a19c208000000b004b52ef3fd2amr3287980lfc.47.1679843855285;
        Sun, 26 Mar 2023 08:17:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679843855; cv=none;
        d=google.com; s=arc-20160816;
        b=NbmJPdTfy2k3Ks0M1RFj0x46EV4/HtlwNsp0GSpXL99XYjY33rfui8g7qGTcHRIVwo
         0DIPhYgyR5/lFK6SfjJRAhQrkbRBnggwRdiPVSOeTHC49Rzx+pvsrym3hMkekECSol0w
         CmpxFIXfwxqfu4RiNGzYAxX/1geLpaTvKLpssfiIeOVTj8lwYx+N59av09yjqA1Tof0E
         PGdKY5nOPj7NnQcTYw7/oKQu0+DPzEv6KFlZCkC3Ntc+wUe/p+bZDzIqJBYosv4BQYlt
         H7Vmzr5dIu5zX3D2vXtq+rTi6XsHdnWG0zRrnc3uv8ozES9KiwLff38pCNW1gqVnvtc8
         FVRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=tLhxb7IYtvrE0VJpOEV96TXX3ZZqWXP/wgw/UEPcVHM=;
        b=rp3E83pa5R9vzXl0ILosdyOGoob94dnjPViKKUc1lSQ8L0vy/w5dupvdFndkNykjiZ
         XYx7v50WX2oaRh+md/e5ZfvEDjQlHIIzYBNQTSyZdW1aQOBUFf1UKmtc/BRpkrDdk2lN
         jYCPoTlco+puKFR+yIXB0Drbzl544YtWBbQwRL5jZWqMGaXy+xY0P+GmJj5o7RCYQLWz
         juY/S20H4EKGf9jjcDQuEEA4AhURiF/BlsfIN/thkiV/MHllhPmd3VKJ6qjfC3U7Sn5s
         VWo/uO30A86I8JTWGGlzZjbwkSnScp0VMBptU68vKa8KEeUlahYGB+jHwIzDh8Az8Ol+
         2CzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=gh5keFjM;
       spf=pass (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=qiang1.zhang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga11.intel.com (mga11.intel.com. [192.55.52.93])
        by gmr-mx.google.com with ESMTPS id h1-20020a2ebc81000000b00299a6cef333si1264551ljf.0.2023.03.26.08.17.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 26 Mar 2023 08:17:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.93 as permitted sender) client-ip=192.55.52.93;
X-IronPort-AV: E=McAfee;i="6600,9927,10661"; a="337602082"
X-IronPort-AV: E=Sophos;i="5.98,292,1673942400"; 
   d="scan'208";a="337602082"
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by fmsmga102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Mar 2023 08:17:32 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10661"; a="713598738"
X-IronPort-AV: E=Sophos;i="5.98,292,1673942400"; 
   d="scan'208";a="713598738"
Received: from zq-optiplex-7090.bj.intel.com ([10.238.156.129])
  by orsmga008-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Mar 2023 08:17:29 -0700
From: Zqiang <qiang1.zhang@intel.com>
To: ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	qiang.zhang1211@gmail.com
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kasan: Fix lockdep report invalid wait context
Date: Sun, 26 Mar 2023 23:29:11 +0800
Message-Id: <20230326152911.830609-1-qiang1.zhang@intel.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: qiang1.zhang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=gh5keFjM;       spf=pass
 (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.93 as
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
in IPI context, due to the CONFIG_PROVE_RAW_LOCK_NESTING=y, the local_lock
wait_type_inner is LD_WAIT_CONFIG, so acquire local_lock in IPI context
(wait_type_inner is LD_WAIT_SPIN) will trigger above calltrace.

This commit therefore move qlist_free_all() from hard-irq context to
task context. 

Signed-off-by: Zqiang <qiang1.zhang@intel.com>
---
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230326152911.830609-1-qiang1.zhang%40intel.com.

Return-Path: <kasan-dev+bncBDR6TU6L2YORBV4CTOJAMGQEB3LIXII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 00E554EEA1E
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Apr 2022 11:09:44 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id t10-20020a2e2d0a000000b002496423e4adsf680786ljt.16
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Apr 2022 02:09:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648804183; cv=pass;
        d=google.com; s=arc-20160816;
        b=EAGSDOqYPNsjdQ466nh5vkmavXWqbSlBofA5oJJf03SSv0Mjg7PLV/FTK7Yy/hTr8/
         WovqcUMaWOJoAofP50XHGcYV5ubYOpQqzL/jWeQv/FhdWjMFF5bWPH/uLgHcvHbidTSY
         EeYPy5UxMAXq3D39JGanqJyCVEMKJRbgyLUqVsg772nTy3M3bVE6Q9WJP5lAJ5ZjHAuO
         De97Qq6IRR45AZHngmZevQ1N2wNkMJDqagP/pKmvLxmyU9vpRhyJxCYePNRrJkXnLHQo
         WtdIHMT3JDI0FMnagHrT+bFEztFxYkSHAMNBzIihwSTLn5Sz3qh0HMn6kIf08qc0YD6B
         IUPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=uN89pKxzSdV8wpAvTBb1l5zFwRujgmb1zuSik1BLhdU=;
        b=AFiJ0QeOuSSKzeWoQ3I4LSJnWUX90eiknWtJymRGJmKK7w/fXRzt9TR17VqxUSWmOO
         C61q7RK1XAog9oYro/ZHjaixTxbsWcSL0jhro1CP7oGeQWy1AB9HG1ggzP+PbP+DXpHL
         w0pVUuzZ25Hl+3ZJ2aUZo7MPimWymV7SnZpOtmJQQiQ6Wh3z80XMzH32ZVv6TAkmlv9u
         EXQ/QgGca0li2/avUsOlDMmGOuwQn8irlJImvO30YAm4ZEpCIo0QHw0SpX+q43VNvFCk
         xhAT0OMWa3HKcZDaSuzCr0HkFLtfhsKB3uetm8vjXE3dArmpzeFg5swSRf4+MD4zuX3d
         70dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=P0OCssp6;
       spf=pass (google.com: domain of qiang1.zhang@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=qiang1.zhang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uN89pKxzSdV8wpAvTBb1l5zFwRujgmb1zuSik1BLhdU=;
        b=W+08+/DZ062aw7Hmbcl0HZtSIrXRGA0AIof0q6xEZp9H7lr1PvKet1uSp3qlalCSi0
         mUiBmAKLgRd/oDZKoVSVUzZEH19PVAQ1dfODkEIsUwjnP9ScXBphZFcWiAuSuXHeA4Ff
         x0qUfoiFEfjpT3m2PBA3UIBVW9vV1d1oGtZ7pvqTp/nx+tyc6As5hSmzF+8lEhMhnEc7
         GSF7n9y5X6UKJ/cKNQrjQrmSJGX/E0dKI0kp6qOz8467bc1M/tK+YdrlUqciJ66cuI50
         qgnaVXZBa/aJysC3cjKN0kvlFUqHoHDxNNt6NH6W5tV3JbUqKHPYh+JOIqziYedGnEVf
         LJYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uN89pKxzSdV8wpAvTBb1l5zFwRujgmb1zuSik1BLhdU=;
        b=7CtegZfYKU94QvsAj/bZzNGxcO+rMxLISRZ4gWQ0UApbQYS7CvGUlw+zOkWdvUk4aO
         8rmcv5OsfW6KJ/UDOfbT1Qiu237nnw9DqQznm/UBHL/NalJosgdrLWHvpns6GOu1Xey9
         VdQhQBhIZQur2qg6/7ZeeU7+VdIAPvJ3Y2ExfK3qRYFtANR9MDGaB0x6pWApwZrfG1vV
         WPnYAF34GugVqLHHuiJzlJmxejrgukPwBQrVT22hPNY1+bI6IKJtArC5L50LPda3QQMb
         WbjXTmbt1+oO+SC7IRTO+QmW5Nai8v3bETSMP9DGcxHoXmC6ciYA7LMCvVmiMHcXW4LA
         AVCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5300qfkBd2CNj6NWwIhrfRYGSL2+K8MVwrZ0d1dWkuKEpBz4rkCJ
	U41fTwd2X7go40rL1X8i4iw=
X-Google-Smtp-Source: ABdhPJzCo2Pzs/c1SGuVm4zATonwyruqbrVlBDWSkLQDCPSPXyeRolxwKb5pQNIlqCbrC5BY5V+erw==
X-Received: by 2002:a19:f50f:0:b0:44a:1a61:e3ca with SMTP id j15-20020a19f50f000000b0044a1a61e3camr12943344lfb.311.1648804183328;
        Fri, 01 Apr 2022 02:09:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:892:b0:249:a5b7:d97e with SMTP id
 d18-20020a05651c089200b00249a5b7d97els237585ljq.10.gmail; Fri, 01 Apr 2022
 02:09:42 -0700 (PDT)
X-Received: by 2002:a05:651c:1195:b0:249:8398:c6ac with SMTP id w21-20020a05651c119500b002498398c6acmr12594414ljo.503.1648804182148;
        Fri, 01 Apr 2022 02:09:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648804182; cv=none;
        d=google.com; s=arc-20160816;
        b=uynnCZkzsIYuWyxoYrutqISW6xizSQR91yRimYWmO85gq3SSIBXX6aBLle/M3tvJk0
         7cId0JCddOeWKuNzj8ZwWU/XvI+tMure6TGTqHacRLfuw5KEZIjAmKcUuyXojuDXOlZx
         289sR2YmAkoSNOgkmfD70+TaaJJk0IGXx+Xq97wRu3w8CiPyPi/+gg2P4K+LbaEsr5We
         8b7RB4QumXogA5GZ8OVaz5/UR9nGqx+8louq8nJZOUOJRsIHGwA5y4zgHV8gZUy8US5R
         DY6+7/YFZfA129A1c9ow/UKoRoha4mZxfMHgqfIVYekooztKSjn0BYM1iIeMHSAsoujP
         +gxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=bNHHN0PXiQgE959bornnyeR+W498qfDh9loTHqu3ztE=;
        b=E355ho65K4qxb36aEe3T7w2a9kM971w4gL2ZCCPvXIyVsKE4Nd9oGKJbNvw34KW5Hu
         ciBh4/X0DdBxUceKVgmrF0BrG5UchUS8SuQFr2Gkt2aCuc9R/QqBk3t7z4qQL7GfJz2C
         PAAaohUDnaew3Nhj9WnkneOQiX1GJzIi4vd/ziI6+PxEsRH8htqOKkltVj7PJDpcR0eX
         TMnNziwd1XUWNwvwL7TG+4QQyln5VMaAtNlUnLWcbVWza86nEHcJx0pcNSSVtAIwf4V/
         GMdHlwAjgRPliMvn3YNJcQCouYzHjw8UUiBpEW8V9Ogk9Mgeo2OM/0p/UGGQjoYa4Sm4
         NMeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=P0OCssp6;
       spf=pass (google.com: domain of qiang1.zhang@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=qiang1.zhang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga18.intel.com (mga18.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id i3-20020a056512340300b0044a2d961b74si114578lfr.4.2022.04.01.02.09.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 01 Apr 2022 02:09:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiang1.zhang@intel.com designates 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-IronPort-AV: E=McAfee;i="6200,9189,10303"; a="242233357"
X-IronPort-AV: E=Sophos;i="5.90,226,1643702400"; 
   d="scan'208";a="242233357"
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 01 Apr 2022 02:09:38 -0700
X-IronPort-AV: E=Sophos;i="5.90,226,1643702400"; 
   d="scan'208";a="567317605"
Received: from zq-optiplex-7090.bj.intel.com ([10.238.156.125])
  by orsmga008-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 01 Apr 2022 02:09:35 -0700
From: Zqiang <qiang1.zhang@intel.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	bigeasy@linutronix.de,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-rt-users@vger.kernel.org
Subject: [PATCH] kasan: Fix sleeping function called from invalid context in PREEMPT_RT
Date: Fri,  1 Apr 2022 17:10:06 +0800
Message-Id: <20220401091006.2100058-1-qiang1.zhang@intel.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: qiang1.zhang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=P0OCssp6;       spf=pass
 (google.com: domain of qiang1.zhang@intel.com designates 134.134.136.126 as
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

BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:46
in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 1, name: swapper/0
preempt_count: 1, expected: 0
...........
CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.17.1-rt16-yocto-preempt-rt #22
Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
BIOS rel-1.15.0-0-g2dd4b9b3f840-prebuilt.qemu.org 04/01/2014
Call Trace:
<TASK>
dump_stack_lvl+0x60/0x8c
dump_stack+0x10/0x12
 __might_resched.cold+0x13b/0x173
rt_spin_lock+0x5b/0xf0
 ___cache_free+0xa5/0x180
qlist_free_all+0x7a/0x160
per_cpu_remove_cache+0x5f/0x70
smp_call_function_many_cond+0x4c4/0x4f0
on_each_cpu_cond_mask+0x49/0xc0
kasan_quarantine_remove_cache+0x54/0xf0
kasan_cache_shrink+0x9/0x10
kmem_cache_shrink+0x13/0x20
acpi_os_purge_cache+0xe/0x20
acpi_purge_cached_objects+0x21/0x6d
acpi_initialize_objects+0x15/0x3b
acpi_init+0x130/0x5ba
do_one_initcall+0xe5/0x5b0
kernel_init_freeable+0x34f/0x3ad
kernel_init+0x1e/0x140
ret_from_fork+0x22/0x30

When the kmem_cache_shrink() be called, the IPI was triggered, the
___cache_free() is called in IPI interrupt context, the local lock
or spin lock will be acquired. on PREEMPT_RT kernel, these lock is
replaced with sleepbale rt spin lock, so the above problem is triggered.
fix it by migrating the release action from the IPI interrupt context
to the task context on RT kernel.

Signed-off-by: Zqiang <qiang1.zhang@intel.com>
---
 mm/kasan/quarantine.c | 15 ++++++++++++---
 1 file changed, 12 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 08291ed33e93..c26fa6473119 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -90,6 +90,7 @@ static void qlist_move_all(struct qlist_head *from, struct qlist_head *to)
  */
 static DEFINE_PER_CPU(struct qlist_head, cpu_quarantine);
 
+static DEFINE_PER_CPU(struct qlist_head, cpu_shrink_qlist);
 /* Round-robin FIFO array of batches. */
 static struct qlist_head global_quarantine[QUARANTINE_BATCHES];
 static int quarantine_head;
@@ -311,12 +312,14 @@ static void qlist_move_cache(struct qlist_head *from,
 static void per_cpu_remove_cache(void *arg)
 {
 	struct kmem_cache *cache = arg;
-	struct qlist_head to_free = QLIST_INIT;
+	struct qlist_head *to_free;
 	struct qlist_head *q;
 
+	to_free = this_cpu_ptr(&cpu_shrink_qlist);
 	q = this_cpu_ptr(&cpu_quarantine);
-	qlist_move_cache(q, &to_free, cache);
-	qlist_free_all(&to_free, cache);
+	qlist_move_cache(q, to_free, cache);
+	if (!IS_ENABLED(CONFIG_PREEMPT_RT))
+		qlist_free_all(to_free, cache);
 }
 
 /* Free all quarantined objects belonging to cache. */
@@ -324,6 +327,7 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
 {
 	unsigned long flags, i;
 	struct qlist_head to_free = QLIST_INIT;
+	int cpu;
 
 	/*
 	 * Must be careful to not miss any objects that are being moved from
@@ -334,6 +338,11 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
 	 */
 	on_each_cpu(per_cpu_remove_cache, cache, 1);
 
+	if (IS_ENABLED(CONFIG_PREEMPT_RT)) {
+		for_each_possible_cpu(cpu)
+			qlist_free_all(per_cpu_ptr(&cpu_shrink_qlist, cpu), cache);
+	}
+
 	raw_spin_lock_irqsave(&quarantine_lock, flags);
 	for (i = 0; i < QUARANTINE_BATCHES; i++) {
 		if (qlist_empty(&global_quarantine[i]))
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220401091006.2100058-1-qiang1.zhang%40intel.com.

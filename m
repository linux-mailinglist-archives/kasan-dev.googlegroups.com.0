Return-Path: <kasan-dev+bncBAABBKGWW77AKGQEVKU7JWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 222912D0BE6
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 09:43:22 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id hg11sf6937727pjb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 00:43:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607330600; cv=pass;
        d=google.com; s=arc-20160816;
        b=KathFoFhD3acLkjlo98tJeQrhQNVdA4aVi3GK/LKary45ynNs1+XqtU9d5bKjX6Nb6
         RdwOWDuXHq8yx9yHIiJJ//LPBQIUyyoc5AwRduD78VCL19XBO8BH6J1EIbO6l9yZX7gA
         s0OFyqqIpJpGJ9cauuWnmeLz1mMc6l46S0H8i8QGwAgVXuXaN1tcBUGoAHNb8l45Q5Mp
         JA4dhK2actizdmKCJCFEzyIsvnwQeLIPpqCm9wPBWN8jrUy1Q4uhXk+/pdiJRuaU1loW
         JDyVDCJn4VjuFFeMc6RsRxAFPI5L4E+3lJ5uNVRITBBM4pfvLjrMo0PmQj9s9pUOYpL9
         +adg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JXyXSzJj4fGrRETY8kFyn1oSiEcKp8EMGDc2XCYAYlE=;
        b=zXBQzP3s3KBFnnDNDvt4PVDJJOvc0qY49q5WNKGitbhY4q4maG0qIpxGfhaS4W/MLb
         fZ58mkOfZc8BtMcYstxCDdsm6zOMJsM+ETMnnYFGOXmsTKoW/uwy3y4eDhmtkP2Dc5DZ
         ZHOc5q2MnnkdVJcesnQyPbZ920vkhGKr6xlWQIxeczByKQUWRwBEnfeFhceA3O1mRhIt
         11M1yXcVTYZqo/Ky9KSYQXaJ/R37rZATuCNpYcqiYhxlcfZK77DToCA7NX9WOlxRvgZ6
         RmuCqZkggB7ffD0pOThni9fTNUnZTg0uozPhaNcFOnqY2sM6OjtTSgZE/YrnjbkwXSiW
         JWkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JXyXSzJj4fGrRETY8kFyn1oSiEcKp8EMGDc2XCYAYlE=;
        b=E5vzlI/Au0+asakukWXaOdjgpFLRt8rViBtz/32pgw3MWw0GqKCsGE1XMP7eqKVHKS
         CjTUpe/unUXrBX75UTwP506on2N8Vx5Stkf6Z6y8GDqzeZP6Dkmigj8Mhti+1m7nrtq5
         6PBUeh/WBXCX0wfkXW2nWXCE/ho2xor2a8vb/4eyi6EDh7ALcRjnPjLq16iTnILzfmIf
         s5Kzqk0jlm+A+sxR2w10uSGiC2x7lVjn5Rtjr5j2oH1kqxp0EwntVvlP+FOS56TiWGiz
         xvJ7hTJS8Ghy3p4qnlB+uB1AhQZrqTrcqTgkRtFdYp+fp/gb2HCU2MgzZg8S7KL/kZnZ
         l5AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JXyXSzJj4fGrRETY8kFyn1oSiEcKp8EMGDc2XCYAYlE=;
        b=F8qu3dwQyRga2hbDuXcH6VGpFXjoHqUsvFsLAizUFWubM9eNE0l+bR2RWocg3g0lWM
         Bk/zPhPgH3SI/IYJAQMbb0tEcK5wXM5aUknREVEmopa/HvH87sRxW5BlzaZrDljHavOE
         ENCPJO5rBc2P1R9RK2k+YuaugwFCMZJAP5rjkLM58+wjROLyNvGtjB4cgFisK7SDnDu0
         gU3UKcbbdMeMQhVRtebkYZzaN7ToaxIIAQm41cfDZ5xc4nHHJMODkbz1pdbjXjoTi1rt
         dyN6YKMMTdmrsY9B1Gm9cXPOIGNj2rRsnoko9n4LM8tKDiqPe4D6GHMPV2DQgxSJnBD2
         x6ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532AMkUmeuZ36grp893YYmzMwcIjHGYXxOzzZvmIHYtnrQ3F2knw
	oDRZtiIgmAd9PCId4ZzaYS8=
X-Google-Smtp-Source: ABdhPJzKV837XleCGX0cM1LqXTrp9YHeguiT+u/Gtq6c8TaOjXGxzDdXVi/PkYd9c14FSaV410xMKQ==
X-Received: by 2002:a62:1716:0:b029:19d:b78b:ef02 with SMTP id 22-20020a6217160000b029019db78bef02mr15098294pfx.11.1607330600458;
        Mon, 07 Dec 2020 00:43:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:548:: with SMTP id 66ls7715617plf.6.gmail; Mon, 07
 Dec 2020 00:43:20 -0800 (PST)
X-Received: by 2002:a17:90a:e287:: with SMTP id d7mr15483914pjz.62.1607330600067;
        Mon, 07 Dec 2020 00:43:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607330600; cv=none;
        d=google.com; s=arc-20160816;
        b=yuQv8j6JiBznjOr3kezpRueEC1wO2IFd0QRSZOKaFfxfdHi2zuPdvPfv+EainEkxY0
         TS+nZMtBGRFbjDKKZ0gqkfrp4e27a4TtD+FCZyaHiZr0MLXX+7cZ7jp9BjG5tfv4rB2p
         +E5HfGF47m+8srJiwPSxzPg8+Z58NhZj+35eF6qPZDCsUI54kF+xd4WNL5QNcZCeeSLK
         lrg3ZECgGXlfG3mpuJZXW8LwRpgFFidJH9CAGY+cXWlofXQ5Hq+FrhWWMW+Xt0qyVjG7
         V9ZRSy2L7BfVJXRhNrdCJ9QkdvNiAx6VXLML+epFrN1AQ/T7n6amUWwGGC1AnVJOp4lg
         /Qqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=rLjX9Hw9aQyIgMfFb2JmIrqFJsgjExanqZrXuZLnEKY=;
        b=LeiUn9S1JgHcZSdEGmpXn0/OBfDm3W/sV6wolvZD+9voSaXxO4tA3icZRu+QNJ95J+
         PIZSugmJIqpTc89e9OxMqa3UYtQfIaICsgNALAjQ7CWRO4534UMOMZFg+GetZ2C+2RII
         a4BTYb18X6XsGLLKQtLdc7WOTg/jeKOiT69kxrKKxo2Ok98gLHl2qR+dDksjgdn6x0qh
         X/unb7LCfWJ7cD1ANhTc/98hdBhV5VxADUeZuXWrjOa1hMuf8T0Czv37kNQMSfIJhSCq
         XY0cvbhtmE/ul1n20+ZmVRVKDcSRpDbLu/srV4bPou62QLcCZHIVhipADYHGfoXaapJ1
         jZ1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id f14si901909pfe.3.2020.12.07.00.43.19
        for <kasan-dev@googlegroups.com>;
        Mon, 07 Dec 2020 00:43:19 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: ec42a9eb35114c3c9cac96d0c82bc287-20201207
X-UUID: ec42a9eb35114c3c9cac96d0c82bc287-20201207
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 480189470; Mon, 07 Dec 2020 16:43:17 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 7 Dec 2020 16:43:14 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 7 Dec 2020 16:43:13 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Zqiang <qiang.zhang@windriver.com>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>,
	Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Kuan-Ying
 Lee <Kuan-Ying.Lee@mediatek.com>, Andrey Konovalov <andreyknvl@google.com>,
	Nicholas Tang <nicholas.tang@mediatek.com>, Miles Chen
	<miles.chen@mediatek.com>, Qian Cai <qcai@redhat.com>, Stephen Rothwell
	<sfr@canb.auug.org.au>
Subject: [PATCH v4 1/1] kasan: fix object remain in offline per-cpu quarantine
Date: Mon, 7 Dec 2020 16:42:58 +0800
Message-ID: <1607330578-417-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 1.9.1
In-Reply-To: <1607330578-417-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
References: <1607330578-417-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: C16DCC12230BA6B4BDF99DDD0101C59782C26CF3814D12337F1858DEAB8FA5CD2000:8
X-MTK: N
X-Original-Sender: kuan-ying.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

We hit this issue in our internal test.
When enabling generic kasan, a kfree()'d object is put into per-cpu
quarantine first. If the cpu goes offline, object still remains in
the per-cpu quarantine. If we call kmem_cache_destroy() now, slub
will report "Objects remaining" error.

[   74.982625] =============================================================================
[   74.983380] BUG test_module_slab (Not tainted): Objects remaining in test_module_slab on __kmem_cache_shutdown()
[   74.984145] -----------------------------------------------------------------------------
[   74.984145]
[   74.984883] Disabling lock debugging due to kernel taint
[   74.985561] INFO: Slab 0x(____ptrval____) objects=34 used=1 fp=0x(____ptrval____) flags=0x2ffff00000010200
[   74.986638] CPU: 3 PID: 176 Comm: cat Tainted: G    B             5.10.0-rc1-00007-g4525c8781ec0-dirty #10
[   74.987262] Hardware name: linux,dummy-virt (DT)
[   74.987606] Call trace:
[   74.987924]  dump_backtrace+0x0/0x2b0
[   74.988296]  show_stack+0x18/0x68
[   74.988698]  dump_stack+0xfc/0x168
[   74.989030]  slab_err+0xac/0xd4
[   74.989346]  __kmem_cache_shutdown+0x1e4/0x3c8
[   74.989779]  kmem_cache_destroy+0x68/0x130
[   74.990176]  test_version_show+0x84/0xf0
[   74.990679]  module_attr_show+0x40/0x60
[   74.991218]  sysfs_kf_seq_show+0x128/0x1c0
[   74.991656]  kernfs_seq_show+0xa0/0xb8
[   74.992059]  seq_read+0x1f0/0x7e8
[   74.992415]  kernfs_fop_read+0x70/0x338
[   74.993051]  vfs_read+0xe4/0x250
[   74.993498]  ksys_read+0xc8/0x180
[   74.993825]  __arm64_sys_read+0x44/0x58
[   74.994203]  el0_svc_common.constprop.0+0xac/0x228
[   74.994708]  do_el0_svc+0x38/0xa0
[   74.995088]  el0_sync_handler+0x170/0x178
[   74.995497]  el0_sync+0x174/0x180
[   74.996050] INFO: Object 0x(____ptrval____) @offset=15848
[   74.996752] INFO: Allocated in test_version_show+0x98/0xf0 age=8188 cpu=6 pid=172
[   75.000802]  stack_trace_save+0x9c/0xd0
[   75.002420]  set_track+0x64/0xf0
[   75.002770]  alloc_debug_processing+0x104/0x1a0
[   75.003171]  ___slab_alloc+0x628/0x648
[   75.004213]  __slab_alloc.isra.0+0x2c/0x58
[   75.004757]  kmem_cache_alloc+0x560/0x588
[   75.005376]  test_version_show+0x98/0xf0
[   75.005756]  module_attr_show+0x40/0x60
[   75.007035]  sysfs_kf_seq_show+0x128/0x1c0
[   75.007433]  kernfs_seq_show+0xa0/0xb8
[   75.007800]  seq_read+0x1f0/0x7e8
[   75.008128]  kernfs_fop_read+0x70/0x338
[   75.008507]  vfs_read+0xe4/0x250
[   75.008990]  ksys_read+0xc8/0x180
[   75.009462]  __arm64_sys_read+0x44/0x58
[   75.010085]  el0_svc_common.constprop.0+0xac/0x228
[   75.011006] kmem_cache_destroy test_module_slab: Slab cache still has objects

Register a cpu hotplug function to remove all objects in the offline
per-cpu quarantine when cpu is going offline. Set a per-cpu variable
to indicate this cpu is offline.

Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Signed-off-by: Zqiang <qiang.zhang@windriver.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Reported-by: Guangye Yang <guangye.yang@mediatek.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Nicholas Tang <nicholas.tang@mediatek.com>
Cc: Miles Chen <miles.chen@mediatek.com>
Cc: Qian Cai <qcai@redhat.com>
Cc: Stephen Rothwell <sfr@canb.auug.org.au>
---
 mm/kasan/quarantine.c | 39 +++++++++++++++++++++++++++++++++++++++
 1 file changed, 39 insertions(+)

diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index a598c3514e1a..55783125a767 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -19,6 +19,7 @@
 #include <linux/srcu.h>
 #include <linux/string.h>
 #include <linux/types.h>
+#include <linux/cpuhotplug.h>
 
 #include "../slab.h"
 #include "kasan.h"
@@ -33,6 +34,7 @@ struct qlist_head {
 	struct qlist_node *head;
 	struct qlist_node *tail;
 	size_t bytes;
+	bool offline;
 };
 
 #define QLIST_INIT { NULL, NULL, 0 }
@@ -191,6 +193,10 @@ bool quarantine_put(struct kmem_cache *cache, void *object)
 	local_irq_save(flags);
 
 	q = this_cpu_ptr(&cpu_quarantine);
+	if (q->offline) {
+		local_irq_restore(flags);
+		return false;
+	}
 	qlist_put(q, &meta->quarantine_link, cache->size);
 	if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
 		qlist_move_all(q, &temp);
@@ -333,3 +339,36 @@ void quarantine_remove_cache(struct kmem_cache *cache)
 
 	synchronize_srcu(&remove_cache_srcu);
 }
+
+static int kasan_cpu_online(unsigned int cpu)
+{
+	this_cpu_ptr(&cpu_quarantine)->offline = false;
+	return 0;
+}
+
+static int kasan_cpu_offline(unsigned int cpu)
+{
+	struct qlist_head *q;
+
+	q = this_cpu_ptr(&cpu_quarantine);
+	/* Ensure the ordering between the writing to q->offline and
+	 * qlist_free_all. Otherwise, cpu_quarantine may be corrupted
+	 * by interrupt.
+	 */
+	WRITE_ONCE(q->offline, true);
+	barrier();
+	qlist_free_all(q, NULL);
+	return 0;
+}
+
+static int __init kasan_cpu_quarantine_init(void)
+{
+	int ret = 0;
+
+	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
+				kasan_cpu_online, kasan_cpu_offline);
+	if (ret < 0)
+		pr_err("kasan cpu quarantine register failed [%d]\n", ret);
+	return ret;
+}
+late_initcall(kasan_cpu_quarantine_init);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1607330578-417-2-git-send-email-Kuan-Ying.Lee%40mediatek.com.

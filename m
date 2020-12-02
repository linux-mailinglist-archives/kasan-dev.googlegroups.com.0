Return-Path: <kasan-dev+bncBAABBOMSTX7AKGQEWBM62KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id F07AD2CB606
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Dec 2020 08:58:50 +0100 (CET)
Received: by mail-vs1-xe37.google.com with SMTP id 1sf159399vsj.21
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 23:58:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606895930; cv=pass;
        d=google.com; s=arc-20160816;
        b=oq+KZ+aow5V7ZbCPnhV8iQxZWLm8G2LzwDflDmHDJmI9u21Jpz1d2Jxuztb5Hb2IXw
         diFp9eg5v9PcuYJ/EsZyq/cGcwnms5Q0Rx410zL5Avzp1EbIPaORFVzl8gOd7SiG+H9a
         CmJrL/DbI8RVArsZTOxHE6mjsmq/zxSKBdunQ4SKXJUJCwTMJ38zIOF5CwJbsk1qS60J
         Ph5abX1yz3JHTBoQB1Je7ChkAnFJiAxuT11aZso6yvTT2BRb76B7MipaB5IL0AJOCy9L
         vsOfFPwT8CdZ4OkZmeCt5D2YSIdtMb2mSUDWvdT8X7JxPk7h+6P02nWXPCMPw0Zuc/wD
         RYcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HRNtzTUijhhQ8JKzBKVjh50RRNuwVSxp+/oP7I7/EN4=;
        b=GCCkns+/Y3EK8J3e4XM8JELxzaY2ZF49327oaMAoWOMeABCAu5bHHRtp0G3h6ZkT/4
         hJ4mgEY+QPqsD/asuFyXSQjlpCUMWKcSQGNmd2Ue+4PNrRXsy1GpkNEp6VMxJdTM/h+a
         e8b7nhKfIcWH/MFzo81lW1QGRmp5X8lxzXg5J6yivs637DHbZpVK9lLMDwrxhjY/LTSA
         Y78i7F7xsWjE9qYL7OFrHmQ16bPpzaQBxFgpwFq0i8uX3jtUEKC8ntXaL/U6giw15X7s
         mT1iBWjU5a2vW9TYgTAjXfqkdXFpNiQVdavzo0OTYopoeGj6li52m9bkFbZN6h+3KAhw
         Zq/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HRNtzTUijhhQ8JKzBKVjh50RRNuwVSxp+/oP7I7/EN4=;
        b=tE33AVjXcxGObziKURJ5Z0ne7QPkz7SVqVi3j614oUJP6P0Nu9nR9JcZhr2hKe22zH
         AD+hXd/AnO1flsEU/14RoqcO040N8x1SkJlf0693yCeydY7eiB1dHWbm07+forR3EnkP
         eqI0TyAkLOLl0Xq1lP7IGmjMS9KNOv0ELz98xS8Qgrkj74UKA077Gb9AEiIcm5G4BJaH
         aHfYy+xey6IyxvI/jaMgdfMEViFhiBNtLF/dkqjMC8zJp/ipgTMG4hNNaBzW5ApfEXjV
         V+gGnIqf4hflbOCWbSXNdOryXYL/2fkJ1ybiXJPWDfQMnp9co06nSFIFRDwVNiVF/2oh
         Dg7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HRNtzTUijhhQ8JKzBKVjh50RRNuwVSxp+/oP7I7/EN4=;
        b=I3lZMhSDRGlzU13atyThsvPxy+VbmhzZ6lLsLHYo0+L3BbDfROxHzO8dhT8Tb59rOA
         gIqXy6o5I7bCe15zbsoSqN13SYdREBQd+Wy6jiQpfOI8Fi8RB/1P/nnMR/tn+d+nuskU
         //YHLcpX87HgA1VEvvTU3ia//g4G12LzpzlGLkvJUpwKR60pZQlp/0IJFEFD1RakJhjf
         fgezAVYn8K5Inf67TD4BKTpQpRKVZRuB0cFVbv3TDKxXwf7lLyE/RM6hcTyxq24jYEAf
         k8qBlVkZQ6kItCk3DrIHGupSS0J7WZ468c+ejhjI4meWtyPY5qr2Dje8trzcNzKwod8o
         /NUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533cUlBhs2Xa3uT3MrGDBa1ZEUEwRFn/uYatACkbB6eEdDgiwcvM
	nsyB65qSxyxjkXj1teNOTs8=
X-Google-Smtp-Source: ABdhPJzo0NKqUsJi2V9JOBE5xtH647kwNd4lOd41PHjLU0SZ+1Xzqq+U9Rg6azhCm2MkysznkII8pg==
X-Received: by 2002:a67:88c2:: with SMTP id k185mr709662vsd.29.1606895930058;
        Tue, 01 Dec 2020 23:58:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:382:: with SMTP id m2ls105667vsq.8.gmail; Tue, 01
 Dec 2020 23:58:49 -0800 (PST)
X-Received: by 2002:a67:f643:: with SMTP id u3mr827780vso.48.1606895929633;
        Tue, 01 Dec 2020 23:58:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606895929; cv=none;
        d=google.com; s=arc-20160816;
        b=tojT8xf53FVr0KVGJJX1DFE3gM8yJg7s6VCSOBFiiFLfY/28QaPkEQYiR1Jl3M9gP6
         cRMo6CST/crTNwa5HBthKqOprCArvXnfATT+DudDV8KYOilfygu/Ps2+OaV4RRQpp8T0
         BXJaJbbn4kp7rNzPzsqwFgeLdwDuixblObj0IbLGIiYQ15DJk1421Dy62YQT4uHabYbI
         dElklJ3/VQZbkof57o88orvxCO8xRG8Z9Bdl7zWinsP/0/BfM6XFrWMJRkibhmFbmFVt
         3adq7RNZ9geuQ5HSJvGJnFandJtYiYa7LvPWnGxwmwM65/BBSoRe+AL9tSsDwkVs81rP
         Fmpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=R5Qe1vdnWQJcGbKwQs+qnsQBaoygHribC2zJEwWIHyk=;
        b=VDtX/B2zMw8WoxgVVISpzmTEoUY/ntQTWLTKTJNIDxc4Jc+1erO4CEGUGxbJFvpXmd
         tJfpfvVlDOmFRvny1rpgi5qb/2qOkunClbxpu6+xA+AaGbE5RJ87hO/ON9x35R4MAvTs
         xBq3r4k9zriU9HYVyIFG9v1zrllfqMIWnPm/LFPxrvOolAF4lglNAuTxbclwjEpDihu4
         DEmaatxItAYEWM8/wz32jCXuvoL31gsUe3YeMcwnneWjbR0ftwy1z9I8qzCaD121FAFO
         LkOxVZYqvK0sA9faSI8/PfRCTPyRXYxk3BVJTfoKYOvjxu3OronOCXu79D4UD36oIQ/Z
         l4DA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id p17si111339vki.0.2020.12.01.23.58.48
        for <kasan-dev@googlegroups.com>;
        Tue, 01 Dec 2020 23:58:49 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 4d191b8f57ed483bafda945ab8e28ebc-20201202
X-UUID: 4d191b8f57ed483bafda945ab8e28ebc-20201202
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1547161469; Wed, 02 Dec 2020 15:53:31 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 2 Dec 2020 15:53:30 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 2 Dec 2020 15:53:30 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>,
	Nicholas Tang <nicholas.tang@mediatek.com>, Miles Chen
	<miles.chen@mediatek.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Kuan-Ying
 Lee <Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v3 1/1] kasan: fix object remain in offline per-cpu quarantine
Date: Wed, 2 Dec 2020 15:53:05 +0800
Message-ID: <1606895585-17382-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 1.9.1
In-Reply-To: <1606895585-17382-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
References: <1606895585-17382-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
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
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Reported-by: Guangye Yang <guangye.yang@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
---
 mm/kasan/quarantine.c | 40 ++++++++++++++++++++++++++++++++++++++++
 1 file changed, 40 insertions(+)

diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 4c5375810449..cac7c617df72 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -29,6 +29,7 @@
 #include <linux/srcu.h>
 #include <linux/string.h>
 #include <linux/types.h>
+#include <linux/cpuhotplug.h>
 
 #include "../slab.h"
 #include "kasan.h"
@@ -43,6 +44,7 @@ struct qlist_head {
 	struct qlist_node *head;
 	struct qlist_node *tail;
 	size_t bytes;
+	bool offline;
 };
 
 #define QLIST_INIT { NULL, NULL, 0 }
@@ -188,6 +190,11 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
 	local_irq_save(flags);
 
 	q = this_cpu_ptr(&cpu_quarantine);
+	if (q->offline) {
+		qlink_free(&info->quarantine_link, cache);
+		local_irq_restore(flags);
+		return;
+	}
 	qlist_put(q, &info->quarantine_link, cache->size);
 	if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
 		qlist_move_all(q, &temp);
@@ -328,3 +335,36 @@ void quarantine_remove_cache(struct kmem_cache *cache)
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1606895585-17382-2-git-send-email-Kuan-Ying.Lee%40mediatek.com.

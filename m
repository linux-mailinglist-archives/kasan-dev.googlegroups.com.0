Return-Path: <kasan-dev+bncBAABBPNKWP6QKGQE6HLFC5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id EE7292AFF9D
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 07:25:02 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id j10sf3142250iog.22
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 22:25:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605162302; cv=pass;
        d=google.com; s=arc-20160816;
        b=KrHPL1nOlPRWPbMZcrNiaOLTpr2gFRED1DXtLJymjwjYZjInkoiSZ5W+WhFgNti44X
         LMuqyP9eyKlkKuF4P+cNgdHTqIG5Yq+aw7xl+c/jttNNbhpOIX8kafupDpVAxwILKocB
         F15lapeQkIHegntkc9iAxu5muPUM/kaH/AVCfF3Yt4DeRbPDORBN6XiC0Cy+wD3RYPQE
         ulBasCd6kSuozet9gLfkR6b9k92J4rnMkH4O+d48PQIHdsPi6DzOngOafRb7GWCn4Msp
         jadi2LybSJv9YjCMW0b7H9RSugpYbSH6sm6iPBtgtIB4T+wfVSyDKCV6Um0dGx+OVvwk
         /sTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WUtjwTlQJlZI91SZ2cVC2w3pyVmIREYI6g1mlc/ehRU=;
        b=CuHe611vUlse1qxN+WC1CFp/QaKeRHhT2naoDOGfkLKZwDFT7loHscikeq6ZEeahvZ
         h1FmfpTGllJvAU8ceA6dFsiIp8Z8ZykTj6PsntWYuc4ThCOT13gKlLW9R/rWYmQIONbl
         zBlQkxMdyn8tTvnlZb9ldzfVcz50Uj7l4Yrx5OsFdyW9C5drgpks1eipxXj2FB5qnbcF
         XGB7lIU3a9DvNIbCRNrmaiCYxJNklqHGTz24gHzB3igdmOe+1BmmZuOt9loLmJFsD7/l
         d1DqMnGjbjnBIt06qk/S8jFrnp5Gk3xhbYsAT5qpPfo72hT2UIdLB774W40SQRQhC+Oo
         RE5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WUtjwTlQJlZI91SZ2cVC2w3pyVmIREYI6g1mlc/ehRU=;
        b=otOs5oOD2w1IWoIeBm46j319+/k3nR1bbHkqq0mAhdn3Xh//VMEMhkCDWz8EX19ul0
         RdYklhDWJN7BoIhz1q2WXyORyHt4ttUKNL9jqFy24tm4HUW/Jn/HHwhuKPp9+Abd6bIe
         LCOQzsfc/nKC3joT9+6vdZjiXOmamr/GDnKcTq91qv9QXhGkqAoF+8XQ1psX/T3aUYbg
         vajCKWTbwN1WRDJU4uW9umEqnLa8g9av+NNDSYFZ+PEzv7AFjrbjZDb+T2UJ6ze5vmWD
         OySASh07fEOdvRAGlvVJ2G5pw25LjAz7sLw49ezfBZcYRVfzDD2LYSmuKlrQQr9Ekj+a
         vcdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WUtjwTlQJlZI91SZ2cVC2w3pyVmIREYI6g1mlc/ehRU=;
        b=Cxddi0oEICwohkAHnG51Cf1YorSQGQDiQMAuM1eKlPZ4bsnRCjPEu18Rxx9iGevk+Q
         r7fVbNGd/J2WTlEgAuQwSw4qDb3lL71mwjQrq6jEu+KD8yl9qCWEiaHqPZQnJaV2i3Ax
         x/vPNJ4Oasc7rKJ7n6CDXVfrLEcvwCWVY7sbxPVq+pJVp57a+ImqTc2aTMvP3Er+5cJJ
         RYdRgryD8a3wb2ru766TUxOsIO/QhDaBECtKCq4tt5STxHEv9++bo+vzIBIO/ttajIDS
         rugnIBYFKwDb4YPSx/xLmxikU/xNqt4n83pb4NhnX6d4INhnmhYJx3bSuHnqAbFz2/SI
         M8lw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530KBHu9ldmq8OXOCkUccwGGar1CVmES9YLyh4tEcjstqOuJ0Gq/
	GcvsZFguM2kxWXfJZ5xsY+0=
X-Google-Smtp-Source: ABdhPJy4J7SqdzELMeJu+LSY/AJi7y2j5AOmIU5s2m15YnPU39T4wusEIioQ4VPK5NGBIFdyjSXJ0Q==
X-Received: by 2002:a05:6e02:4aa:: with SMTP id e10mr20803823ils.58.1605162301932;
        Wed, 11 Nov 2020 22:25:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:63c:: with SMTP id h28ls237977jar.6.gmail; Wed, 11
 Nov 2020 22:25:01 -0800 (PST)
X-Received: by 2002:a02:ce30:: with SMTP id v16mr24010910jar.33.1605162301582;
        Wed, 11 Nov 2020 22:25:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605162301; cv=none;
        d=google.com; s=arc-20160816;
        b=ORdrgn8zW9Mk7ouTVtE7BzF6UohtrflJML2wnyypND4EeZpTtRz198emkOvSWov8Hv
         eYEbrBXaNTFtbqNuWFSz1C1OJ8ym//2N3CsiaOzpVb+FIpkRi10CZAb7AZSRWQVDpCej
         uHy4BJImFs2nwYf0zv4GGuMZY1LVk7ipWJ5EbY/TRYscpy0Jdc3Y+ofKBBVSvdlQPMxl
         hmC1+2FglrrqjvZl/eC7ZHDsbr2F5B/BtYGOLMJeSUFIPvl6jQ9aYX3FGl+5MlHzurB3
         hHi/sQlQiG2b9xhf/lgYzivegtqT3A0sG3NrO0Blkv+bJnetq63Yq+S5dLt59MJmnxfk
         zsCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=BfUMHVmx1CILYlnGS91zWBeGM1eOJ1eUOU1r62tCAO4=;
        b=DHI4VDtrmDLzGshv14f1ajbmz9QWATIakkL/ra+F3zJUHCpv1HOLPU39nSrKEr+vKe
         XMgV0tl3R5M00MjXqn+9l8dlaMFemkjhrbDbX+QhShZ3/SthYF/m3pJyJXB3g/NciwcC
         dq58hNVzMowHYG3mA8VV3uzFSq8hra8vuUg+jrHy5MiDfVLPbBr+q3arCBkp4TarobRr
         3adg/OrdRsUusvUoyaVAgX8T9W027IQHOeQaTdowdU4jWikVMP27qv0+5Nt/FOFjVqX8
         wwLLD6WoMluG/iUwQNMDyOC3ZF83iKr4KyWfEDemd739gfQNyqSS9yta6Xmto0L1i4vR
         76Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id k16si244071ilr.2.2020.11.11.22.25.00
        for <kasan-dev@googlegroups.com>;
        Wed, 11 Nov 2020 22:25:01 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 1c246289433b411ab8b8bbbd71049fac-20201112
X-UUID: 1c246289433b411ab8b8bbbd71049fac-20201112
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1548991305; Thu, 12 Nov 2020 14:24:56 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs02n2.mediatek.inc (172.21.101.101) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 12 Nov 2020 14:24:54 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 12 Nov 2020 14:24:54 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>,
	<miles.chen@mediatek.com>, <nicholas.tang@mediatek.com>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH 1/1] kasan: fix object remain in offline per-cpu quarantine
Date: Thu, 12 Nov 2020 14:24:12 +0800
Message-ID: <1605162252-23886-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 1.9.1
In-Reply-To: <1605162252-23886-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
References: <1605162252-23886-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 67384A22CCD6B964F43E25ACEF468208F53342DEE61F90588F13A8A98858F2982000:8
X-MTK: N
X-Original-Sender: kuan-ying.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
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
---
 mm/kasan/quarantine.c | 59 +++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 57 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 4c5375810449..67fb91ae2bd0 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -29,6 +29,7 @@
 #include <linux/srcu.h>
 #include <linux/string.h>
 #include <linux/types.h>
+#include <linux/cpuhotplug.h>
 
 #include "../slab.h"
 #include "kasan.h"
@@ -97,6 +98,7 @@ static void qlist_move_all(struct qlist_head *from, struct qlist_head *to)
  * guarded by quarantine_lock.
  */
 static DEFINE_PER_CPU(struct qlist_head, cpu_quarantine);
+static DEFINE_PER_CPU(int, cpu_quarantine_offline);
 
 /* Round-robin FIFO array of batches. */
 static struct qlist_head global_quarantine[QUARANTINE_BATCHES];
@@ -176,6 +178,8 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
 	unsigned long flags;
 	struct qlist_head *q;
 	struct qlist_head temp = QLIST_INIT;
+	int *offline;
+	struct qlist_head q_offline = QLIST_INIT;
 
 	/*
 	 * Note: irq must be disabled until after we move the batch to the
@@ -187,8 +191,16 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
 	 */
 	local_irq_save(flags);
 
-	q = this_cpu_ptr(&cpu_quarantine);
-	qlist_put(q, &info->quarantine_link, cache->size);
+	offline = this_cpu_ptr(&cpu_quarantine_offline);
+	if (*offline == 0) {
+		q = this_cpu_ptr(&cpu_quarantine);
+		qlist_put(q, &info->quarantine_link, cache->size);
+	} else {
+		qlist_put(&q_offline, &info->quarantine_link, cache->size);
+		qlist_free_all(&q_offline, cache);
+		local_irq_restore(flags);
+		return;
+	}
 	if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
 		qlist_move_all(q, &temp);
 
@@ -328,3 +340,46 @@ void quarantine_remove_cache(struct kmem_cache *cache)
 
 	synchronize_srcu(&remove_cache_srcu);
 }
+
+static int kasan_cpu_online(unsigned int cpu)
+{
+	int *offline;
+	unsigned long flags;
+
+	local_irq_save(flags);
+	offline = this_cpu_ptr(&cpu_quarantine_offline);
+	*offline = 0;
+	local_irq_restore(flags);
+	return 0;
+}
+
+static int kasan_cpu_offline(unsigned int cpu)
+{
+	struct kmem_cache *s;
+	int *offline;
+	unsigned long flags;
+
+	local_irq_save(flags);
+	offline = this_cpu_ptr(&cpu_quarantine_offline);
+	*offline = 1;
+	local_irq_restore(flags);
+
+	mutex_lock(&slab_mutex);
+	list_for_each_entry(s, &slab_caches, list) {
+		per_cpu_remove_cache(s);
+	}
+	mutex_unlock(&slab_mutex);
+	return 0;
+}
+
+static int __init kasan_cpu_offline_quarantine_init(void)
+{
+	int ret = 0;
+
+	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
+				kasan_cpu_online, kasan_cpu_offline);
+	if (ret)
+		pr_err("kasan offline cpu quarantine register failed [%d]\n", ret);
+	return ret;
+}
+late_initcall(kasan_cpu_offline_quarantine_init);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1605162252-23886-2-git-send-email-Kuan-Ying.Lee%40mediatek.com.

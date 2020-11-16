Return-Path: <kasan-dev+bncBAABBFFZZD6QKGQE65JIGSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 636142B3D24
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 07:30:46 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id q199sf1216992pfc.21
        for <lists+kasan-dev@lfdr.de>; Sun, 15 Nov 2020 22:30:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605508244; cv=pass;
        d=google.com; s=arc-20160816;
        b=OcxxOm19g794tWz0R7RTmJ2myKScB0ejinEo0sLcGlwVVZM3lC87QX3jwm5acJom+S
         MvNG94LJf6xFxsd98aYVlQx61adlYeYJCLd/Zs+FD69mkcuKWNcARUUutwUtczchjU4J
         vyEBuatVzBvG35+hziyEZ6A7Eezmm6OSaFNaSV/zsVRPZcyXQuwUoVbL6Y3cANleVCXk
         2MuYsp8KgqDZDGx5cKKPGnAI15K0r/63N030xBdtGceUj7lyHL5GmMPPHNAHpJzEbhXO
         E6oka+5emZB8mXeJtp+OUwIJcrHTL1b5yHTFypaSOq/O+SDxm8uHnHVjZLSXw5cmYBcG
         4b/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JkB+fwrtRmNCc+WbMxPocDSA/Pxd+7wItKEuDPscAvk=;
        b=l33RXNIAkQlF9r9r5BddQ8xV33ww7p8nA3vo45tgTOK827Sp+nYRuLT387eq9/UnGn
         yMMk+RNWyTqgtHBXQrtuQl/pJZjvIG0c9AkfQfeRHd0tCBFRhEZLxkIVAMkfHp7yOCH9
         FNGNbavGuq/baWHQwCzpdspRNr81NJgersjSvflzNuoqXnIZF6trcR7+TT6wgrnOnpqt
         DJScdL+rE4IcYatcU1kf8Yuz7zkPMAlyA3YP2aYwUptiO57bJyq3q3jwgD5YQC/Uj8yQ
         F4FYhkKdsWL0mHFtpyr+KhQ8xhoEKkBzHug17UiNqYopUxVjoqIO+r3Br7wmebmWXb3T
         4G1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JkB+fwrtRmNCc+WbMxPocDSA/Pxd+7wItKEuDPscAvk=;
        b=dLKQoZXnfnCpkk3icsnwZBPqLrNRle7hVfkMuyT7kz1yO8kBV7uuxw+bC4fEicag8O
         1+XCgdL+WB1HYSVZPTvNmWZtRqplM7U/WmWxoLaiWjeL6msA8EbmtauiF3lHo144DJ+t
         awHdWLnmmmBqhSO19y82lOwjCsoONl2yruag6fF01SWfOB6D7gyGF00ldJTKQHJmM4sJ
         UufsGukdHlbyzdJVmlHTrgsApRcGTJmvH6e9wJ5ndaWqrUy00ogqAHGFHKjT551tQjkR
         /6F8s4YCvKOimsppgBbcNikBlEPgG1fPPtWjL4EWizdwS/pKC3KkBGz/2/S5vGkRaAgM
         H2hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JkB+fwrtRmNCc+WbMxPocDSA/Pxd+7wItKEuDPscAvk=;
        b=FQqfIsuyIQ7aR5hrpri2FYxuJsfRotumd8HPs3WQyZY5Y9xs1DiSJ0zF9WOsG9dGcI
         K8NX+Ym41xG6mHye7KJzAjY56dAuvi05/BdeVChj0A2DYJCIfM7wJ2wxET2dVWCZ0mtI
         +sOHMlbMLfO13cNKt1gg7yZln9tKwhRO1hXOzFpP+X17e9w4wLRrASeKA8o7UROhvRSa
         6E5AfSVJ62U6nHoTrbGcDnPxvA5AXDeE+ctjQgHNPfNRuQ5mOMwIYN1pQuvCObpVss8u
         XOx9cKPoet3BfP7vYfzg0jESWLxiO/SHIR0x+IltI/q78GDTVQyCzOcEDaJmEShxT40a
         19MQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ZU5wwJcTYf1heZ3Va4ETiT83x9L9/q0+Yg6ef8QLEqrHj3Ebx
	qVwEcj6M6B7zuT/DRLgR+as=
X-Google-Smtp-Source: ABdhPJzJGquI2GrkVXuLX02tyPkvqqccLkDOVLH+nSdr7ONczOaDTBzSkgSiZ972lFH6BAkD0EPlvw==
X-Received: by 2002:a17:90a:f314:: with SMTP id ca20mr15152424pjb.191.1605508244733;
        Sun, 15 Nov 2020 22:30:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9a47:: with SMTP id x7ls3624184plv.1.gmail; Sun, 15
 Nov 2020 22:30:44 -0800 (PST)
X-Received: by 2002:a17:90a:f3d1:: with SMTP id ha17mr15094008pjb.164.1605508244219;
        Sun, 15 Nov 2020 22:30:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605508244; cv=none;
        d=google.com; s=arc-20160816;
        b=eRcuSZXSEjR4b1SOEAW0Y5kcleCasUFvIfl3zwTF/qg42QRR8QD7juRg0fQBZJeS7Q
         Ktk+IuONtZ5MtIkYrngv07dvLWfjzbWvAvXdb7mWzb2f+vHCWwJVgmlP0TyaldE55hGI
         vJM05s0txjXTk0GypGqekPv4s2yGl/QX1MVsiw2eFysg/r3oy8myw5IA8/UPLDEaoF2L
         NswvNYu/I5GdXWNCW3PnYCbgklkRWOs7m+MWx9hNtlb2VQq7s1YeT+tjts/jiNutCNWp
         cy9S1MdVaJ5eGyPk7rG2EQea43EgYWIlodPYnmWJz8ebOniPFvjR/9mahzNQHY5FCp2D
         f2Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=Kpr09BSp+M/0UUjnce83NHwmyRadaxrvruxMiIs4aTg=;
        b=Bxl5Q4ESELlOSfsMv5yeLehWqMROAONY+4dE9werBgtOqVYamlRHjOH9Gi2Z/S1oSS
         dVMkSKpVzhaNQW7/a8l4saCSzOdahzkFUPHSeYm6vdT732FBU3057PcBRVbgu85AhlF9
         weMGAIfFCnxLcYTOUvQadf0nwyV6+40/0vEy5jS6vY6Q/iy5qP9MGtse309uCdPU+x2u
         7CLU8gbpUzrqY4DzWM5PM8nKg1zwZ2IqYcLDClyrNJ0MAGP3KpMN7Iwx/FT+8bcmkE27
         nDnM9QFb7tZ7ohlIY89dzh1mvvdhs8C53gOcfFfIo9WeNYKGYEudxbcEp+JQa5Rm2kgS
         +AgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id ne10si1792235pjb.0.2020.11.15.22.30.43
        for <kasan-dev@googlegroups.com>;
        Sun, 15 Nov 2020 22:30:44 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: b689c852d7e743d89e7642bc5d8fd752-20201116
X-UUID: b689c852d7e743d89e7642bc5d8fd752-20201116
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1326448162; Mon, 16 Nov 2020 14:30:40 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 16 Nov 2020 14:30:08 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 16 Nov 2020 14:30:08 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <nicholas.tang@mediatek.com>,
	<miles.chen@mediatek.com>, <guangye.yang@mediatek.com>,
	<wsd_upstream@mediatek.com>, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v2 1/1] kasan: fix object remain in offline per-cpu quarantine
Date: Mon, 16 Nov 2020 14:29:28 +0800
Message-ID: <1605508168-7418-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 1.9.1
In-Reply-To: <1605508168-7418-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
References: <1605508168-7418-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
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
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Reported-by: Guangye Yang <guangye.yang@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
---
 mm/kasan/quarantine.c | 35 +++++++++++++++++++++++++++++++++++
 1 file changed, 35 insertions(+)

diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 4c5375810449..16e618ea805e 100644
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
@@ -328,3 +335,31 @@ void quarantine_remove_cache(struct kmem_cache *cache)
 
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
+	q->offline = true;
+	qlist_free_all(q, NULL);
+	return 0;
+}
+
+static int __init kasan_cpu_offline_quarantine_init(void)
+{
+	int ret = 0;
+
+	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
+				kasan_cpu_online, kasan_cpu_offline);
+	if (ret < 0)
+		pr_err("kasan offline cpu quarantine register failed [%d]\n", ret);
+	return ret;
+}
+late_initcall(kasan_cpu_offline_quarantine_init);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1605508168-7418-2-git-send-email-Kuan-Ying.Lee%40mediatek.com.

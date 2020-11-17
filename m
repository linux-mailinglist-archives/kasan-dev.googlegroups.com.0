Return-Path: <kasan-dev+bncBAABBRPDZX6QKGQEEWZ4ZQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id DD8B12B59D6
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 07:46:30 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id b11sf9160238pfi.7
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 22:46:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605595589; cv=pass;
        d=google.com; s=arc-20160816;
        b=xAruoqRnMCn6CaVUNT8IgXowbwqp3vWPJTk5+hHaLOEEdVPWzI04BtyXIMmacgtRbu
         4/kwq3y0dN2tXsVHGqT5sky+6RDrrDv92x9eIabZmgwFVFfidFi0QM1MQVsH0OgP23hJ
         p5jUG7zIUCKd2nmytt283RRFqCqT37eIsdIBSwNhTLAWkeXQVnWqPqQYfzbx09nlVnzg
         C+P4fiVWT9qSKDJtvdSZx/IM9KbWfmybKc0UZxMTTrBmQ/p2ov784EppjBXav5qqqo5d
         CPXg3tPNzNR6WduZ2DQXPoIaeonzonfkyHo1OMHpxyBfv1fYAzpBPZ9nTrr77R2vJ/xH
         38gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=8mAt2Nw6G5Eb033itn0K1bTPm2ciNgYkEX7siAFUXpQ=;
        b=vfANisrRTFVgIF3W3+03yAjVvAp5I79+XEMPdFYAVkx5I371xd+6Qt6HlblO11lC5+
         JO3sDTSWNbsPhB8wjx61hqFViI1nbZx7p2tinhqAA2TypKORB0PmA8WxzvYlwBQxhHqz
         y+APJvkqWFj/YvFnJ1QdX2N7dy3CJ89wdL2LMhG6CeWgvIuEBFtXPJgUXakz5N9dKhch
         CflHs+Gw4bVJDPIrbhrxNDB+mOecSGEotx8e4XXKeHyaEzEOSG2AdQMJYXObZE5XRzrT
         KlEDHRdVZKBMWXsmjspGXKXGdJi6iiHr9VXrLda4g+bbOCey0w1372NuQ7cYNMKOwP9Z
         x7sg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=jd9X6gOg;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8mAt2Nw6G5Eb033itn0K1bTPm2ciNgYkEX7siAFUXpQ=;
        b=ONVbCmPGfxLeFshVT4V3p/FoMxRYuUsvkhblSaPGo4c8ORNxc6HrECcWZakHCOXpF5
         K2YKa8QQjzZHw6wZbYai/eju5MgUESbkr2TfQQjL3RI9P9LljMjNf21KzEPXqlaVRQ8T
         3tzhTdJTT0fSuwUqNodyhcv9hcnWx3dRBtvbvhP52FHk2ksaEHrgO9rexBHlxmQTNJ8I
         vzpD6MmczaoR8B/pvjgbbKGRv/VWqguoUTR5KOWKWNYhaCKb2/UrmCNuURowQCcvzpZp
         vSGDcqCLjOFT9yt590jHCF/HeyZdIiHJ2azi34Rk+5XcB4q6tCBtFCXVYPrQzpdSTuLF
         VWFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8mAt2Nw6G5Eb033itn0K1bTPm2ciNgYkEX7siAFUXpQ=;
        b=FPbOeKK/vhqhOBebndZTi7PlV98sh0MoOmN31YqpoFqbOLxW4Nk3VZWK2s5JIosn2k
         I3NJotsGDqsn77T9Lc5nDhHw5Tzfp/MFnUmaYTx+tvE+AXXgLiEVHtDCK7VF6sWusQXT
         Cz44SXb7Q2k67/D8Zu0Y95KNLYPai2c/Ogll1HcBK8dGlyphQVQxyootUP86g6k50FDg
         P1blr3f5AN0gjHEJbUdxN/dLxDzttxzH/QeNd0nFgEwG2qrNzPf2WBZ/RXBBp4aEQzyR
         xKBglz7oZ64KQw+RIMXx2SIHQWSa8ME1T/aYxMTm1WM/yrjDGwaLQrTJ5Pap35IS1Dmd
         uM4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530aJqZGsN7Wa9Atat+RVIofKT3Z2vabKhm+r15wOEhgfGGjm3aN
	bQ/55ZaY26P8XOyDlyCmy4g=
X-Google-Smtp-Source: ABdhPJwKFz7UuWTg5sXfXiIRYGoTnu6oUrL5lYG8lD4LCNEWP7PX7b49yID0LAFMqPjUvg1DvzhlBw==
X-Received: by 2002:a63:d46:: with SMTP id 6mr2375098pgn.227.1605595589567;
        Mon, 16 Nov 2020 22:46:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:524:: with SMTP id 33ls6141964plf.6.gmail; Mon, 16
 Nov 2020 22:46:29 -0800 (PST)
X-Received: by 2002:a17:90a:940c:: with SMTP id r12mr3148082pjo.201.1605595589159;
        Mon, 16 Nov 2020 22:46:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605595589; cv=none;
        d=google.com; s=arc-20160816;
        b=Qk473/PCi3QRrvet7vt7uZNc6DMdWsbZxaU+qx+lAa23J9dcVL/GZ+3jj2Fimimir2
         f4j+LeRK5tHVRl9S6zbAtaLAvZhGqBBi4SrTxxJhYEIEoCcFoAvarMqz8YPvKdCYUmwp
         sz02QEaojApdDkj0HuRT2R2THSRq0Yz3LU6W2Ovv2ZJRf/6/+EDC1nXe0WHaCVI3eDqF
         oYRF849foS5WBDxYxinbAyAkPnFQYApfrO2mwPQGZUuh6A6bgklI8MZec3WoTa2cmpQW
         6oWGi3aKmdM8s5gYdlrlNANQc+D+aboXyc9hM7fSIxp336E55X5xGWVerAbV/BPSYZUd
         QlFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=P0hBz/eNIE1si2tntwhLbvvsKCxvPoGSYMCr0jXLKx8=;
        b=tiAxPDd30AQMdr5ZLnKzDJ7q9AFsoG6s7ooaNZoSGDugcC/Q8CX7ih1ZcLWkhl3Fap
         CtvjGuPSxA9Ww7Fzl948Zh3SLa/ai9gtFcMbtsHRtNWUTq/hE9c/p2oYGdJ03TempLBy
         dws4L6g1RvzCLcc1fhv5rPD7BUHNGdzW3uuQnHjkSaFUBPzoveP/bGEH2eBMYJXK+d1o
         qmPtQXS+gMcZI3Ev8eyAcaQ1B/PznGLPkLR/SPAClsz79kUTyrkmwZR4f6eE+jRwckjj
         zAjXTWmk41gX8gc/8LL2YDorZd6AyVwWIEntzFkeHuHPkAhy23U6Tnbk/PxECJ308Ca+
         e6BA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=jd9X6gOg;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id o24si144247pjt.3.2020.11.16.22.46.28
        for <kasan-dev@googlegroups.com>;
        Mon, 16 Nov 2020 22:46:29 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 4319619206784ed88c895eb25ae18e31-20201117
X-UUID: 4319619206784ed88c895eb25ae18e31-20201117
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 636884911; Tue, 17 Nov 2020 14:46:24 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 17 Nov 2020 14:46:22 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 17 Nov 2020 14:46:22 +0800
Message-ID: <1605595583.29084.24.camel@mtksdccf07>
Subject: Re: [PATCH v2 1/1] kasan: fix object remain in offline per-cpu
 quarantine
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, "Matthias
 Brugger" <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, "Linux
 ARM" <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <nicholas.tang@mediatek.com>, Miles
 Chen <miles.chen@mediatek.com>, <guangye.yang@mediatek.com>, wsd_upstream
	<wsd_upstream@mediatek.com>
Date: Tue, 17 Nov 2020 14:46:23 +0800
In-Reply-To: <CACT4Y+Zy_JQ3y7_P2NXffiijTuxcnh7VPcAGL66Ks2LaLTj-eg@mail.gmail.com>
References: <1605508168-7418-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
	 <1605508168-7418-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
	 <CACT4Y+Zy_JQ3y7_P2NXffiijTuxcnh7VPcAGL66Ks2LaLTj-eg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: kuan-ying.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=jd9X6gOg;       spf=pass
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

On Mon, 2020-11-16 at 10:26 +0100, Dmitry Vyukov wrote:
> On Mon, Nov 16, 2020 at 7:30 AM Kuan-Ying Lee
> <Kuan-Ying.Lee@mediatek.com> wrote:
> >
> > We hit this issue in our internal test.
> > When enabling generic kasan, a kfree()'d object is put into per-cpu
> > quarantine first. If the cpu goes offline, object still remains in
> > the per-cpu quarantine. If we call kmem_cache_destroy() now, slub
> > will report "Objects remaining" error.
> >
> > [   74.982625] =============================================================================
> > [   74.983380] BUG test_module_slab (Not tainted): Objects remaining in test_module_slab on __kmem_cache_shutdown()
> > [   74.984145] -----------------------------------------------------------------------------
> > [   74.984145]
> > [   74.984883] Disabling lock debugging due to kernel taint
> > [   74.985561] INFO: Slab 0x(____ptrval____) objects=34 used=1 fp=0x(____ptrval____) flags=0x2ffff00000010200
> > [   74.986638] CPU: 3 PID: 176 Comm: cat Tainted: G    B             5.10.0-rc1-00007-g4525c8781ec0-dirty #10
> > [   74.987262] Hardware name: linux,dummy-virt (DT)
> > [   74.987606] Call trace:
> > [   74.987924]  dump_backtrace+0x0/0x2b0
> > [   74.988296]  show_stack+0x18/0x68
> > [   74.988698]  dump_stack+0xfc/0x168
> > [   74.989030]  slab_err+0xac/0xd4
> > [   74.989346]  __kmem_cache_shutdown+0x1e4/0x3c8
> > [   74.989779]  kmem_cache_destroy+0x68/0x130
> > [   74.990176]  test_version_show+0x84/0xf0
> > [   74.990679]  module_attr_show+0x40/0x60
> > [   74.991218]  sysfs_kf_seq_show+0x128/0x1c0
> > [   74.991656]  kernfs_seq_show+0xa0/0xb8
> > [   74.992059]  seq_read+0x1f0/0x7e8
> > [   74.992415]  kernfs_fop_read+0x70/0x338
> > [   74.993051]  vfs_read+0xe4/0x250
> > [   74.993498]  ksys_read+0xc8/0x180
> > [   74.993825]  __arm64_sys_read+0x44/0x58
> > [   74.994203]  el0_svc_common.constprop.0+0xac/0x228
> > [   74.994708]  do_el0_svc+0x38/0xa0
> > [   74.995088]  el0_sync_handler+0x170/0x178
> > [   74.995497]  el0_sync+0x174/0x180
> > [   74.996050] INFO: Object 0x(____ptrval____) @offset=15848
> > [   74.996752] INFO: Allocated in test_version_show+0x98/0xf0 age=8188 cpu=6 pid=172
> > [   75.000802]  stack_trace_save+0x9c/0xd0
> > [   75.002420]  set_track+0x64/0xf0
> > [   75.002770]  alloc_debug_processing+0x104/0x1a0
> > [   75.003171]  ___slab_alloc+0x628/0x648
> > [   75.004213]  __slab_alloc.isra.0+0x2c/0x58
> > [   75.004757]  kmem_cache_alloc+0x560/0x588
> > [   75.005376]  test_version_show+0x98/0xf0
> > [   75.005756]  module_attr_show+0x40/0x60
> > [   75.007035]  sysfs_kf_seq_show+0x128/0x1c0
> > [   75.007433]  kernfs_seq_show+0xa0/0xb8
> > [   75.007800]  seq_read+0x1f0/0x7e8
> > [   75.008128]  kernfs_fop_read+0x70/0x338
> > [   75.008507]  vfs_read+0xe4/0x250
> > [   75.008990]  ksys_read+0xc8/0x180
> > [   75.009462]  __arm64_sys_read+0x44/0x58
> > [   75.010085]  el0_svc_common.constprop.0+0xac/0x228
> > [   75.011006] kmem_cache_destroy test_module_slab: Slab cache still has objects
> >
> > Register a cpu hotplug function to remove all objects in the offline
> > per-cpu quarantine when cpu is going offline. Set a per-cpu variable
> > to indicate this cpu is offline.
> >
> > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > Reported-by: Guangye Yang <guangye.yang@mediatek.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: Matthias Brugger <matthias.bgg@gmail.com>
> > ---
> >  mm/kasan/quarantine.c | 35 +++++++++++++++++++++++++++++++++++
> >  1 file changed, 35 insertions(+)
> >
> > diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> > index 4c5375810449..16e618ea805e 100644
> > --- a/mm/kasan/quarantine.c
> > +++ b/mm/kasan/quarantine.c
> > @@ -29,6 +29,7 @@
> >  #include <linux/srcu.h>
> >  #include <linux/string.h>
> >  #include <linux/types.h>
> > +#include <linux/cpuhotplug.h>
> >
> >  #include "../slab.h"
> >  #include "kasan.h"
> > @@ -43,6 +44,7 @@ struct qlist_head {
> >         struct qlist_node *head;
> >         struct qlist_node *tail;
> >         size_t bytes;
> > +       bool offline;
> >  };
> >
> >  #define QLIST_INIT { NULL, NULL, 0 }
> > @@ -188,6 +190,11 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
> >         local_irq_save(flags);
> >
> >         q = this_cpu_ptr(&cpu_quarantine);
> > +       if (q->offline) {
> > +               qlink_free(&info->quarantine_link, cache);
> > +               local_irq_restore(flags);
> > +               return;
> > +       }

I think we need to make sure objects will not be put in per-cpu
quarantine which is offline.

> >         qlist_put(q, &info->quarantine_link, cache->size);
> >         if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
> >                 qlist_move_all(q, &temp);
> > @@ -328,3 +335,31 @@ void quarantine_remove_cache(struct kmem_cache *cache)
> >
> >         synchronize_srcu(&remove_cache_srcu);
> >  }
> > +
> > +static int kasan_cpu_online(unsigned int cpu)
> > +{
> > +       this_cpu_ptr(&cpu_quarantine)->offline = false;
> > +       return 0;
> > +}
> > +
> > +static int kasan_cpu_offline(unsigned int cpu)
> > +{
> > +       struct qlist_head *q;
> > +
> > +       q = this_cpu_ptr(&cpu_quarantine);
> > +       q->offline = true;
> > +       qlist_free_all(q, NULL);
> 
> Looks much nicer now!
> 
> What is the story with interrupts in these callbacks?
> In the previous patch you mentioned that this CPU can still receive
> interrupts for a brief period of time. If these interrupts also free
> something, can't we corrupt the per-cpu quarantine? In quarantine_put
> we protect it by disabling interrupts I think.
> 

Here is a situation.
After we freed all objects from the per-cpu quarantine which is going
offline, the interrupts happened. These interrupts free something and
put objects into this per-cpu quarantine. If we call
kmem_cache_destroy() now, slub still detect objects remain in
the per-cpu quarantine and report "Object remaining" error.

Thus, we need to check q->offline in quarantine_put and make sure
the offline per-cpu quarantine is not corrupted.

> 
> > +       return 0;
> > +}
> > +
> > +static int __init kasan_cpu_offline_quarantine_init(void)
> > +{
> > +       int ret = 0;
> > +
> > +       ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
> > +                               kasan_cpu_online, kasan_cpu_offline);
> > +       if (ret < 0)
> > +               pr_err("kasan offline cpu quarantine register failed [%d]\n", ret);
> > +       return ret;
> > +}
> > +late_initcall(kasan_cpu_offline_quarantine_init);
> > --
> > 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1605595583.29084.24.camel%40mtksdccf07.

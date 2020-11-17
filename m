Return-Path: <kasan-dev+bncBCMIZB7QWENRBHPQZX6QKGQE3SCS54Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B5762B5A1A
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 08:13:34 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id w10sf14006650ila.22
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 23:13:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605597213; cv=pass;
        d=google.com; s=arc-20160816;
        b=eYdUNn+DXp+/vrOjOMNk8rj/oEHvf4At69TJX4W+iAy1bPgST8Yj5xopx6X5DSHbaY
         PQb70ew3P6zCq84QcDKxaiArOisISkC96cHAlSV+Nowitfw3iM3lQmTgRLvQ9guQV5NY
         5G96+tYlmhTIqLb2FZupv159AGdnmSt+i6XeSh2FOWAocRqR/Ssq7qId9gB8/yQBntbc
         REYuHkCJTg/VpEVHSUseQKWgMZ3znCyOWvZn1tzMvFDpbhZot0XFVS+biA8gTFAiMXG4
         6Pnda0fYSOcm8gLc9SQa+169N/5kS53Ty+6USk5EspH2uiUsoVgIz0ZECF3eE0d/wJGX
         WXDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nqmgZNli6Hhn4zicBiODnDzk7OwbiWq5HfzuSK/Dx7c=;
        b=EBLUFhksSOFZaIkDd8JqSkv+VyXWQqRPG9Z7dSnpmZUGOaveo8JIsUBc21GMR446G5
         gT9pATlD9unWZGdNULqe29G8i6vWsBMv6QwxQ2Q50eW/BcoDISaFIcfsmJfnW56PvtrV
         wcQ9KvYRk5Q1GAtcgRh062pk1oXUDVwe5NiEkHFf5KBvhvyraSLycVZbV4YI+e9sbsWe
         C3jRb8NSVeY6UcRUigRt3cENgd2nICVvDGEUba/g9781h7zbJO/ePGzO6JA64HpX+YJu
         2ceb36OYmuEHn4mBls1IxpRMgg62zHpPJ5UpetP8y4VATWUjgZLC+0lT2UJ5jmcGR5Wc
         wyOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZMRHKDiu;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nqmgZNli6Hhn4zicBiODnDzk7OwbiWq5HfzuSK/Dx7c=;
        b=KQFj678ke+vtXSeKWsms8MNVTTf7QCLtSOIJB4uRKGiTI00d6/EFz/4sH48+7i+7/9
         JtL27Qb2jW7na3BUOmd+5zWHC5rO0wJM9WNe1XOdeGkWv5S/5zaDd3Ae3Gxdu+w4IF3c
         sV+6xtQ7qjYBK+kvyC5X/K/lgcBRoQiQVqezZ9K62ntQXg8NXoJeUuu5zwnjy2FBb0ge
         QrJ5ZYsazsHAwt1LqtI84ado1i7sIT5qkT19w/rPfRMgrveVsMShzp/Dmt+YO66AaLsw
         Ka29zsq3no80NZd+tx56D2WoQxtkXG9PlNsVbwXrkE6HjKMS3EXFVzGKo8hyFgM7COk6
         +1dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nqmgZNli6Hhn4zicBiODnDzk7OwbiWq5HfzuSK/Dx7c=;
        b=QbEu+Yv85KIOZ4iK6nGRKO4yJcXQR0t3bfH0338ERWdQvWPNDqBKXhHasBL4OicNMt
         xe7Oemm4ye5yUA6OCyR/eGOvZl9OIvmMLjAW0cCe5qSSvDseUykYhr0ta7rlZMt0VyLq
         HuAQ5uM+8oxtQ0mzNi8Z38bZOn/Y1A1rc1AZMsK1flhaM27QbmUWsd5s4s6KpW4WkLO/
         JKHbuJtIi4Kae2u43UcSA3hrFYBrKzLpcCC83gP/2uI0RReon9EMGfui0jkQsxsBOdeb
         KSzumEPkDIhBJz8WYuxuyoe3rVB/SMMLGCnngnwuEQCGyyLCLoVcICpQx79DntAeP4xv
         QQIw==
X-Gm-Message-State: AOAM531OYikLyL1ya8w0VaBcKrMoDjtwL2gsWvawIfbti7JdDVnX3c0O
	1VDzzK/zq4dw8q9kQ9UdQyM=
X-Google-Smtp-Source: ABdhPJymTxBj/A9/fJ7o5j/ynSeXkKroORDnARaqDRvh7MFkh5hKSDYVPs2Lcd49UWbaVpSvzwWo3A==
X-Received: by 2002:a92:cd0d:: with SMTP id z13mr11794149iln.39.1605597213143;
        Mon, 16 Nov 2020 23:13:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d247:: with SMTP id v7ls3666999ilg.0.gmail; Mon, 16 Nov
 2020 23:13:32 -0800 (PST)
X-Received: by 2002:a92:b504:: with SMTP id f4mr10691092ile.34.1605597212814;
        Mon, 16 Nov 2020 23:13:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605597212; cv=none;
        d=google.com; s=arc-20160816;
        b=aHRdcbJseqqawncCCzR/HmvAEwo1wIYcuFxcX0vnhsyH2H+8+biZHu2tiul/oULn7z
         xoa9sscRhKP3uDeVOYCoOcWaHmZnWzyP6ip1KRTW5GO3tTjUA8qByCPjjDSHrwuXNSf1
         MyyDlR097SP+aUVc1fpXatsKFoaVNzMM2x00N482+EY9I7g34p1C2OJWPkZd4vymqudH
         qmK+n5iQw2czaYf1/I+7DyknLvycJpyTeOBM1GvB8Dr5ZfOffUxY+XK8D3myoNj4M7/u
         xMFJNeBmc11bqi5OXou4wll8oYEX2jy4F/NG3Z/0W+jjSeC66lUBrLkTUN71X7F8LoEZ
         2t4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Zr5Zwdnm9g0v0RoWFdb/Hft1niHdwCm4sqYnYTlZRA0=;
        b=O0lBXDsORoG2aDDrLDNhgww7/dQiWZwJgLPAvvVuJEwNx3DHB5VNop//laGqOZ1ISI
         Oq1a3xTwpletpF5ahyc8O+CMbriNCkFOpzkD0ZUhP8kiTlnI+EeanHmnWw4PdgiLDupx
         ud5MClCGrK3quDskmipL7qwvbkzkacBP1J/nm6AJUVecz235vJllYPCf/sWsg02xsjaC
         J/J5WDPAjbXFrpI6/9EXFoO0MXQt1SXqfajbsdS0H/KfJlXbwQwCHZfUQ5ji1MEc6Xro
         qdR92Me8zzG2FmMuD5t9po7TjOZl5o+d7qA8huCog+0lBx+UPg7TnoSmqYfgqDyWdjcy
         itLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZMRHKDiu;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id k16si1099380ilr.2.2020.11.16.23.13.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 23:13:32 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id r7so19575465qkf.3
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 23:13:32 -0800 (PST)
X-Received: by 2002:a05:620a:15ce:: with SMTP id o14mr19106447qkm.231.1605597212067;
 Mon, 16 Nov 2020 23:13:32 -0800 (PST)
MIME-Version: 1.0
References: <1605508168-7418-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
 <1605508168-7418-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
 <CACT4Y+Zy_JQ3y7_P2NXffiijTuxcnh7VPcAGL66Ks2LaLTj-eg@mail.gmail.com> <1605595583.29084.24.camel@mtksdccf07>
In-Reply-To: <1605595583.29084.24.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Nov 2020 08:13:20 +0100
Message-ID: <CACT4Y+ZpK5YKLrN_jvaD60YFKQ-kVHc=91NTBzhX5PZRTHVd7g@mail.gmail.com>
Subject: Re: [PATCH v2 1/1] kasan: fix object remain in offline per-cpu quarantine
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org, 
	nicholas.tang@mediatek.com, Miles Chen <miles.chen@mediatek.com>, 
	guangye.yang@mediatek.com, wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZMRHKDiu;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Nov 17, 2020 at 7:46 AM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> On Mon, 2020-11-16 at 10:26 +0100, Dmitry Vyukov wrote:
> > On Mon, Nov 16, 2020 at 7:30 AM Kuan-Ying Lee
> > <Kuan-Ying.Lee@mediatek.com> wrote:
> > >
> > > We hit this issue in our internal test.
> > > When enabling generic kasan, a kfree()'d object is put into per-cpu
> > > quarantine first. If the cpu goes offline, object still remains in
> > > the per-cpu quarantine. If we call kmem_cache_destroy() now, slub
> > > will report "Objects remaining" error.
> > >
> > > [   74.982625] =============================================================================
> > > [   74.983380] BUG test_module_slab (Not tainted): Objects remaining in test_module_slab on __kmem_cache_shutdown()
> > > [   74.984145] -----------------------------------------------------------------------------
> > > [   74.984145]
> > > [   74.984883] Disabling lock debugging due to kernel taint
> > > [   74.985561] INFO: Slab 0x(____ptrval____) objects=34 used=1 fp=0x(____ptrval____) flags=0x2ffff00000010200
> > > [   74.986638] CPU: 3 PID: 176 Comm: cat Tainted: G    B             5.10.0-rc1-00007-g4525c8781ec0-dirty #10
> > > [   74.987262] Hardware name: linux,dummy-virt (DT)
> > > [   74.987606] Call trace:
> > > [   74.987924]  dump_backtrace+0x0/0x2b0
> > > [   74.988296]  show_stack+0x18/0x68
> > > [   74.988698]  dump_stack+0xfc/0x168
> > > [   74.989030]  slab_err+0xac/0xd4
> > > [   74.989346]  __kmem_cache_shutdown+0x1e4/0x3c8
> > > [   74.989779]  kmem_cache_destroy+0x68/0x130
> > > [   74.990176]  test_version_show+0x84/0xf0
> > > [   74.990679]  module_attr_show+0x40/0x60
> > > [   74.991218]  sysfs_kf_seq_show+0x128/0x1c0
> > > [   74.991656]  kernfs_seq_show+0xa0/0xb8
> > > [   74.992059]  seq_read+0x1f0/0x7e8
> > > [   74.992415]  kernfs_fop_read+0x70/0x338
> > > [   74.993051]  vfs_read+0xe4/0x250
> > > [   74.993498]  ksys_read+0xc8/0x180
> > > [   74.993825]  __arm64_sys_read+0x44/0x58
> > > [   74.994203]  el0_svc_common.constprop.0+0xac/0x228
> > > [   74.994708]  do_el0_svc+0x38/0xa0
> > > [   74.995088]  el0_sync_handler+0x170/0x178
> > > [   74.995497]  el0_sync+0x174/0x180
> > > [   74.996050] INFO: Object 0x(____ptrval____) @offset=15848
> > > [   74.996752] INFO: Allocated in test_version_show+0x98/0xf0 age=8188 cpu=6 pid=172
> > > [   75.000802]  stack_trace_save+0x9c/0xd0
> > > [   75.002420]  set_track+0x64/0xf0
> > > [   75.002770]  alloc_debug_processing+0x104/0x1a0
> > > [   75.003171]  ___slab_alloc+0x628/0x648
> > > [   75.004213]  __slab_alloc.isra.0+0x2c/0x58
> > > [   75.004757]  kmem_cache_alloc+0x560/0x588
> > > [   75.005376]  test_version_show+0x98/0xf0
> > > [   75.005756]  module_attr_show+0x40/0x60
> > > [   75.007035]  sysfs_kf_seq_show+0x128/0x1c0
> > > [   75.007433]  kernfs_seq_show+0xa0/0xb8
> > > [   75.007800]  seq_read+0x1f0/0x7e8
> > > [   75.008128]  kernfs_fop_read+0x70/0x338
> > > [   75.008507]  vfs_read+0xe4/0x250
> > > [   75.008990]  ksys_read+0xc8/0x180
> > > [   75.009462]  __arm64_sys_read+0x44/0x58
> > > [   75.010085]  el0_svc_common.constprop.0+0xac/0x228
> > > [   75.011006] kmem_cache_destroy test_module_slab: Slab cache still has objects
> > >
> > > Register a cpu hotplug function to remove all objects in the offline
> > > per-cpu quarantine when cpu is going offline. Set a per-cpu variable
> > > to indicate this cpu is offline.
> > >
> > > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > > Reported-by: Guangye Yang <guangye.yang@mediatek.com>
> > > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > Cc: Alexander Potapenko <glider@google.com>
> > > Cc: Andrew Morton <akpm@linux-foundation.org>
> > > Cc: Matthias Brugger <matthias.bgg@gmail.com>
> > > ---
> > >  mm/kasan/quarantine.c | 35 +++++++++++++++++++++++++++++++++++
> > >  1 file changed, 35 insertions(+)
> > >
> > > diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> > > index 4c5375810449..16e618ea805e 100644
> > > --- a/mm/kasan/quarantine.c
> > > +++ b/mm/kasan/quarantine.c
> > > @@ -29,6 +29,7 @@
> > >  #include <linux/srcu.h>
> > >  #include <linux/string.h>
> > >  #include <linux/types.h>
> > > +#include <linux/cpuhotplug.h>
> > >
> > >  #include "../slab.h"
> > >  #include "kasan.h"
> > > @@ -43,6 +44,7 @@ struct qlist_head {
> > >         struct qlist_node *head;
> > >         struct qlist_node *tail;
> > >         size_t bytes;
> > > +       bool offline;
> > >  };
> > >
> > >  #define QLIST_INIT { NULL, NULL, 0 }
> > > @@ -188,6 +190,11 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
> > >         local_irq_save(flags);
> > >
> > >         q = this_cpu_ptr(&cpu_quarantine);
> > > +       if (q->offline) {
> > > +               qlink_free(&info->quarantine_link, cache);
> > > +               local_irq_restore(flags);
> > > +               return;
> > > +       }
>
> I think we need to make sure objects will not be put in per-cpu
> quarantine which is offline.
>
> > >         qlist_put(q, &info->quarantine_link, cache->size);
> > >         if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
> > >                 qlist_move_all(q, &temp);
> > > @@ -328,3 +335,31 @@ void quarantine_remove_cache(struct kmem_cache *cache)
> > >
> > >         synchronize_srcu(&remove_cache_srcu);
> > >  }
> > > +
> > > +static int kasan_cpu_online(unsigned int cpu)
> > > +{
> > > +       this_cpu_ptr(&cpu_quarantine)->offline = false;
> > > +       return 0;
> > > +}
> > > +
> > > +static int kasan_cpu_offline(unsigned int cpu)
> > > +{
> > > +       struct qlist_head *q;
> > > +
> > > +       q = this_cpu_ptr(&cpu_quarantine);
> > > +       q->offline = true;
> > > +       qlist_free_all(q, NULL);
> >
> > Looks much nicer now!
> >
> > What is the story with interrupts in these callbacks?
> > In the previous patch you mentioned that this CPU can still receive
> > interrupts for a brief period of time. If these interrupts also free
> > something, can't we corrupt the per-cpu quarantine? In quarantine_put
> > we protect it by disabling interrupts I think.
> >
>
> Here is a situation.
> After we freed all objects from the per-cpu quarantine which is going
> offline, the interrupts happened. These interrupts free something and
> put objects into this per-cpu quarantine. If we call
> kmem_cache_destroy() now, slub still detect objects remain in
> the per-cpu quarantine and report "Object remaining" error.
>
> Thus, we need to check q->offline in quarantine_put and make sure
> the offline per-cpu quarantine is not corrupted.

If an interrupt can happen later, can't it happen right during our
call to qlist_free_all and corrupt the per-cpu cache?
Perhaps we need something like:

// ... explain the subtleness ...
WRITE_ONCE(q->offline, true);
barrier();
qlist_free_all(q, NULL);

?

> > > +       return 0;
> > > +}
> > > +
> > > +static int __init kasan_cpu_offline_quarantine_init(void)
> > > +{
> > > +       int ret = 0;
> > > +
> > > +       ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
> > > +                               kasan_cpu_online, kasan_cpu_offline);
> > > +       if (ret < 0)
> > > +               pr_err("kasan offline cpu quarantine register failed [%d]\n", ret);
> > > +       return ret;
> > > +}
> > > +late_initcall(kasan_cpu_offline_quarantine_init);
> > > --
> > > 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZpK5YKLrN_jvaD60YFKQ-kVHc%3D91NTBzhX5PZRTHVd7g%40mail.gmail.com.

Return-Path: <kasan-dev+bncBCMIZB7QWENRBUO7XD6QKGQEH25QAXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id E580C2B1629
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 08:03:46 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id c2sf5227637qtx.3
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 23:03:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605251026; cv=pass;
        d=google.com; s=arc-20160816;
        b=WeQLiBATViNUXTm3f881MPo79gcyhhppFWW8sxYju8jV2dMu9R+WnRT48Mz+dZrzAQ
         yA0hrS+vV7rJq2Ye8+L7eHtO9jGAGsk+J88Jy0be1B1eNgM8QgIrzDwyC7ikBRMV5mJK
         RQzl0UCZK7LghDezeeweaEXqUrLeMktoJL0BrNTprcg6lym0gt4TZwao9bZUH288SKfO
         lQEQriiKhujIEtfrignIiMHl3KkkTfh49dTnyKkD/QpwFuYsVgJmzpWFnA0fDNZRbG44
         QFuQX4OLSHjM1gR+TNYzVJhYMpfZkYI89NDLH3/VBm5qnHnW2P+OYE4UCfzvbrwIxOyu
         MbyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pKE8+P9w8cvlHm2EBD+z15s8r2qrSsSYCW9BDOOVDNM=;
        b=zHqYVTVko7wFamfSCWTqVGfw8nGzIuhnyaaIah/P072P07HNthYDfKp1uanh0lysBS
         kTOQ2zNWTKBoKvUeyhLJfQ1xvOAGpIEzvftceTVAAXg4DqlLHXsEG2EUzRqh4dGKfkgj
         3VCj37Zoa6zvxgSkvv5M+mmTyOVlOtFWsX5dbKZ5rtu68XsXEvJdfWRKebx5Rheyribc
         u0Jf2wz5pzU+nmX6OHn9eNT5rS6eTsQFJbrGfefit8nih1hGGKTh+060RaYKZstjFY1F
         TvpDFk1fK/g3qbFm0sR2ZdQ/3BA2iwZTmkgvMQiGRR1c4vgko2VIveU1NCTSIVRpljA+
         f1EA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vTA7EHji;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pKE8+P9w8cvlHm2EBD+z15s8r2qrSsSYCW9BDOOVDNM=;
        b=JsU9Xb1SItNS8FBMn26aKZBc8izURTT1k+vaHee39TiI9EWH+B0V/PYJWz82bMwT9s
         eRu6vhpGo7RcsYlW/g4JzE7cNj/mm2T4RKPfNmm/dAfRZEjd90wlL0Sz8kHV3QcTsuhj
         e8hRJov0MnBPa++Dn+0h8bD4mfNYORGUU9IuyTORqzuy4fxbGQ24jcCyIGDA8ejQ8yBK
         clKIGYsAQHnF75fjYuE2PNDgh0ipXn8IoDSkiSmzIVIwcql3XldWjyy2TjdSXEwZABBE
         UijUlp8yu0uAKMjcwjJZUm5xowWjRhEKMzbnEmC1UPBuPElDz8UeyRpOKL9MUqoHEu2e
         fr6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pKE8+P9w8cvlHm2EBD+z15s8r2qrSsSYCW9BDOOVDNM=;
        b=bTbFEsVw9X2kWceShb8VZte/sI4l148rP4g3mNBwpy2CLKjAy88zIS0/9vyHkbYg2E
         VvwYcSubCTUbJtUMNI55oZl1KLXnirci4ApUmj41cN0Z55j9HxeoDzMYSWRpC+vwi8hy
         evBBywkcypETnD8RGsBGEzeGPovkLbBkUjRJZj8bKqzUpe4yw00irhxvbyiBKnD2haQi
         OWij0PZcrXOv4sGGaQsY29IQw1j326Ub/O3xQyrkgkRJfsxh4pqJ/pB01RvNY+al0KKq
         8g8VFDgORwo4I8iO93Fa84H2fpOv3FOQ09GLL+cfjcR4VbpZUP4CgS/PLLhf8L3+H189
         r9fQ==
X-Gm-Message-State: AOAM532PkVoqABJzKcd+iwzHEK8/ga3st2dhrEYOaPW39jNWRVFtssKh
	xQYRvml1JfdXOQTiY0211Jk=
X-Google-Smtp-Source: ABdhPJwAxd7RTuLMGzCCQ9Cg7DGxPe9nG1go/O2ovuzfdTXrwNn+1eE13o2r4Lx8mTdgf1gZPy+aow==
X-Received: by 2002:a05:6214:a0d:: with SMTP id dw13mr1024493qvb.54.1605251025759;
        Thu, 12 Nov 2020 23:03:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:43c1:: with SMTP id w1ls1891050qtn.5.gmail; Thu, 12 Nov
 2020 23:03:45 -0800 (PST)
X-Received: by 2002:aed:2986:: with SMTP id o6mr777736qtd.55.1605251025305;
        Thu, 12 Nov 2020 23:03:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605251025; cv=none;
        d=google.com; s=arc-20160816;
        b=TOuHe3xluTyiIXDEXBS05qE3fUTjmqA4HxON8hI25m7R/NBmUMltXNiLH+f6Zxn6+y
         0sZpPzJ8d5uWzKkSv3Em6cPpYYMBT0bVP9eDBmreatS5D4CnHAnUuD+gYaJqcWktqFuL
         Ww4uNu3GFVJeZF4KPelvQ6TuoIigiQxPa/twjBLKCXd3hXp6BXey6rCKH/R5XyRsTpWa
         gmVx6uqvwKEyaIeQLN8WYJ69Zx0Okq/vhGNtX4Z7oNf6cNZwyjP0EeV9j5FYxXliXeKJ
         7WMC7ElRHJhJVa0WsT+iWHMrzKDOZvdrv63MaWB6+oNmcecbw98+vFLb5WAoVzJKGiaw
         nTkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2PkncTpQIdgHDydrhX/SeaNm5Vy35yKSw0V2poc3sOE=;
        b=wt4K4OyTGC6MSg6tsRs8HiAk+mwL/CNJuXtUSk2KH6qb/s2z/MYSUhTELGAks/RgYH
         Kc99Klkng04cd4A0vDIIoC4vmLMJWFoM4P9gCzChGWwKAa4EKK+lJSt7ipeaOt5t2Sk8
         v6BetOY5lYxMziuM2zfpfVpYFjboQrAkT9YaOXHBHrOtFI2q9b7lZ/uCos2pzl0OZvt0
         FSdUNkNLvbNI+yHFu3gZdVxvicmdJ4uEs4Wk0Ts5zT9ubtc/kL+fBZkoGTnRoLwFhUkM
         drNc8i7oWm537vFBc0TkgTcftnHdMfFuvQMm/5Q3RbOHGyJtwyqquDjPX+IAxCACfszp
         RLVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vTA7EHji;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id n21si281323qkh.0.2020.11.12.23.03.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 23:03:45 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id g17so6075470qts.5
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 23:03:45 -0800 (PST)
X-Received: by 2002:ac8:1288:: with SMTP id y8mr763877qti.177.1605251024620;
 Thu, 12 Nov 2020 23:03:44 -0800 (PST)
MIME-Version: 1.0
References: <1605162252-23886-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
 <1605162252-23886-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
 <CACT4Y+bpDTqQRRdV0_O07H=Kczj3nXUY9ngQgX5K=BtT=Y60RQ@mail.gmail.com> <1605234714.30076.18.camel@mtksdccf07>
In-Reply-To: <1605234714.30076.18.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 13 Nov 2020 08:03:32 +0100
Message-ID: <CACT4Y+b7F_A1E_FMKQMK4cg2SwpniLjq9Nr988J6BVSF5rkDGg@mail.gmail.com>
Subject: Re: [PATCH 1/1] kasan: fix object remain in offline per-cpu quarantine
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org, 
	wsd_upstream <wsd_upstream@mediatek.com>, Miles Chen <miles.chen@mediatek.com>, 
	nicholas.tang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vTA7EHji;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Fri, Nov 13, 2020 at 3:32 AM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> On Thu, 2020-11-12 at 09:39 +0100, Dmitry Vyukov wrote:
> > On Thu, Nov 12, 2020 at 7:25 AM Kuan-Ying Lee
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
> > > ---
> > >  mm/kasan/quarantine.c | 59 +++++++++++++++++++++++++++++++++++++++++--
> > >  1 file changed, 57 insertions(+), 2 deletions(-)
> > >
> > > diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> > > index 4c5375810449..67fb91ae2bd0 100644
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
> > > @@ -97,6 +98,7 @@ static void qlist_move_all(struct qlist_head *from, struct qlist_head *to)
> > >   * guarded by quarantine_lock.
> > >   */
> >
> > Hi Kuan-Ying,
> >
> > Thanks for fixing this.
> >
> > >  static DEFINE_PER_CPU(struct qlist_head, cpu_quarantine);
> > > +static DEFINE_PER_CPU(int, cpu_quarantine_offline);
> >
> > I think cpu_quarantine_offline is better be part of cpu_quarantine
> > because it logically is and we already obtain a pointer to
> > cpu_quarantine in quarantine_put, so it will also make the code a bit
> > shorter.
> >
>
> Ok. Got it.
>
> >
> > >  /* Round-robin FIFO array of batches. */
> > >  static struct qlist_head global_quarantine[QUARANTINE_BATCHES];
> > > @@ -176,6 +178,8 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
> > >         unsigned long flags;
> > >         struct qlist_head *q;
> > >         struct qlist_head temp = QLIST_INIT;
> > > +       int *offline;
> > > +       struct qlist_head q_offline = QLIST_INIT;
> > >
> > >         /*
> > >          * Note: irq must be disabled until after we move the batch to the
> > > @@ -187,8 +191,16 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
> > >          */
> > >         local_irq_save(flags);
> > >
> > > -       q = this_cpu_ptr(&cpu_quarantine);
> > > -       qlist_put(q, &info->quarantine_link, cache->size);
> > > +       offline = this_cpu_ptr(&cpu_quarantine_offline);
> > > +       if (*offline == 0) {
> > > +               q = this_cpu_ptr(&cpu_quarantine);
> > > +               qlist_put(q, &info->quarantine_link, cache->size);
> > > +       } else {
> > > +               qlist_put(&q_offline, &info->quarantine_link, cache->size);
> > > +               qlist_free_all(&q_offline, cache);
> >
> > This looks like a convoluted way to call qlink_free. I think it will
> > be better to call qlink_free directly here.
> >
> > And why do we need this? Because CPU shutdown code can still free some
> > objects afterwards?
> >
>
> Yes, it is because IRQ can happen during CPU shutdown and free some
> objects into offline CPU quarantine.
>
> > > +               local_irq_restore(flags);
> > > +               return;
> >
> > You add both if/else and early return, this looks like unnecessary
> > code complication. It would be simpler with:
> >
> > if (*offline) {
> >     qlink_free(...);
> >     return;
> > }
> > ... all current per-cpu local ...
> >
> >
>
> Thank you for reminder. v2 Will do it.
>
> > > +       }
> > >         if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
> > >                 qlist_move_all(q, &temp);
> > >
> > > @@ -328,3 +340,46 @@ void quarantine_remove_cache(struct kmem_cache *cache)
> > >
> > >         synchronize_srcu(&remove_cache_srcu);
> > >  }
> > > +
> > > +static int kasan_cpu_online(unsigned int cpu)
> > > +{
> > > +       int *offline;
> > > +       unsigned long flags;
> > > +
> > > +       local_irq_save(flags);
> >
> > I assume this local_irq_save/restore is to prevent some warnings from
> > this_cpu_ptr.
> > But CPU online/offline callbacks should run without preemption already
> > (preempting/rescheduling on other CPUs does not make sense for them,
> > right?), so I would assume that is already at least preemption
> > disabled or something. Is there this_cpu_ptr variant that won't
> > produce warnings on its own in cpu online/offline callbacks?
> > This whole function could be a 1-liner:
> > this_cpu_ptr(&cpu_quarantine)->offline = true;
> > So I am trying to understand if we could avoid all this unnecessary danse.
> >
>
> Yes, it's unnecessary. v2 will fix it.
>
> >
> > > +       offline = this_cpu_ptr(&cpu_quarantine_offline);
> > > +       *offline = 0;
> > > +       local_irq_restore(flags);
> > > +       return 0;
> > > +}
> > > +
> > > +static int kasan_cpu_offline(unsigned int cpu)
> > > +{
> > > +       struct kmem_cache *s;
> > > +       int *offline;
> > > +       unsigned long flags;
> > > +
> > > +       local_irq_save(flags);
> > > +       offline = this_cpu_ptr(&cpu_quarantine_offline);
> > > +       *offline = 1;
> > > +       local_irq_restore(flags);
> > > +
> > > +       mutex_lock(&slab_mutex);
> > > +       list_for_each_entry(s, &slab_caches, list) {
> > > +               per_cpu_remove_cache(s);
> > > +       }
> > > +       mutex_unlock(&slab_mutex);
> >
> > We just want to drop the whole per-cpu cache at once, right? I would
> > assume there should be a simpler way to do this all at once, rather
> > than doing this per-slab.
> >
>
> Yes.
> Is removing objects in per-cpu quarantine directly better?

Yes, single qlist_free_all call looks much better than iteration over
all slabs and removing in parts under the mutex.

> struct qlist_head *q;
> q = this_cpu_ptr(&cpu_quaratine);
> q->offline = true;
> qlist_free_all(q, NULL);
>
> > > +       return 0;
> > > +}
> > > +
> > > +static int __init kasan_cpu_offline_quarantine_init(void)
> > > +{
> > > +       int ret = 0;
> > > +
> > > +       ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
> > > +                               kasan_cpu_online, kasan_cpu_offline);
> > > +       if (ret)
> > > +               pr_err("kasan offline cpu quarantine register failed [%d]\n", ret);
> > > +       return ret;
> > > +}
> > > +late_initcall(kasan_cpu_offline_quarantine_init);
> > > --
> > > 2.18.0
> > >
> > > --
> > > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1605162252-23886-2-git-send-email-Kuan-Ying.Lee%40mediatek.com.
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1605234714.30076.18.camel%40mtksdccf07.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb7F_A1E_FMKQMK4cg2SwpniLjq9Nr988J6BVSF5rkDGg%40mail.gmail.com.

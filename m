Return-Path: <kasan-dev+bncBCMIZB7QWENRBVHJWP6QKGQES253EHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 80A032B014C
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 09:39:50 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id g19sf2008502oib.6
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 00:39:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605170389; cv=pass;
        d=google.com; s=arc-20160816;
        b=lYE/jIt5YwxgoEGs8zaJCohxTHcv2q4T2eyMTmPnMa5hDvZNSoee0jf4jmMTE7kHO6
         JJ6iJDZO5HMwzyRj1Ma8Oj7TGMFkMSOYBh+xdh+p/oajq6oKrRmzzZjcEq/MIWDGUJCF
         gjcr/efjSQ4D0yNPnJ7Mx6Sd4sagF39re5Msl2yffyzeSPQGSBdOLhgwEsGvzxWN3Jaj
         1XH2Otk2gld3kZEY0TkYgJB6IN7CGK5G6M9NvJZzIIKXSH+kXQ1p3DuL5h+N+LmWvYA8
         Aw+tRD5dSCq4RoQG4uh93TEufYW1fRwA5TZk7vLqk4Dt+NmtEGh2lBx5WyTnEujd88pF
         TF/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nUyEWX8541J+CjPUtwBUdZs5CoSC8zUWVyHUF44bzDY=;
        b=mBOvNFX9AUu0Hmze/N7CxlE89OcNpLsLImwBV2w0zcjQKO+iMP2g5cCrA7g6m1bXrm
         M4l0YHPfSvMjTyP6xAZQTPDyHdk8jv5QJ3WmvPAwWkKweQ/qgQwu0gAd9T8ut/3tITRl
         98JIQDAkN6LB5Dyh6skFaP09T7+5w+Ro4lNYl7xLk2Jb0XEdhKdHZSbeBJFsE3YA1AMi
         b02BGM5bEOP9V35oQGK1yM3iw/Fj3arYnXLtJIGP4ZOK2yBsDb5FBa08UR+oplIcuLKl
         585PDQVBvtxfumKZuY9TgsF0jP9kS2H3MBk0l+o+RmvPiHzbE8ok4dDhi6nKDKiFWTu8
         +G2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ES7Ip+66;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nUyEWX8541J+CjPUtwBUdZs5CoSC8zUWVyHUF44bzDY=;
        b=Kf+2Bnoyd0dbdSkX4bGWkxRXHcyUmLhDhIlfJ7Uar322y4qPu0RyR0/KFaaq8l33Ol
         UNyR+7BfktXDR5K3SiYHgF35PoiiGZFekFeJoHSwmsOwLIm18T47pZ/aTyYpWOdFaWmC
         e3cexn6a687Ad1SnYNXu06Yi4mTt2zrHOPbJ4wpW/UIgMCIc7Kut/IbCpmY8phWzIGtO
         aZN2kpJcO26uYYqPD3cZ/A3ZIujk0kVzpQPm+ObnkA7OrsNOIMqHWrGOWp8R834z40VJ
         jOrx/1jIYMRocLIRNMnRceAiA3iT6BBxjwyyVd0FgEPt4NPcE3Cv/ZYVfz+A7/bvKkyT
         7qgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nUyEWX8541J+CjPUtwBUdZs5CoSC8zUWVyHUF44bzDY=;
        b=ANwe4AhUKUjceKBeBRDBLa9iT2qZMDXJ07pEiBJbqmXg2htaAbkSkyXbB2BL9XKpE8
         tb0lRZFT9zsRopAg05zud1wZmVTnq5wDavRplgq9jpfIhnkUteXnLDQ4lgagXwcurF4n
         x02SqHHzEXgpKQkw2HNaSnFQ+LPF68g5pXuIcZ4904wJAB0VIhmkbz81jLOEPnSLEDkR
         qm+GGZ1wNZAIARTWtulOVU9cE/1nEy+6bVjozOOlmxariEbZ7tzl3wuvxc6wkbCoGsVQ
         je1sKR9QNOrUoB/OPJRW62wHoG9GfUBLlwy236tC88YEWcQJDPCvj7ue8QHPnlFfuZuG
         wY6Q==
X-Gm-Message-State: AOAM5300QK8QqB7WIHyd8vzWLgisCgYlqnOzLMZDz+o9YNJe/okz9aF2
	icM7KDSxgjK0a6sVUZC9Ffk=
X-Google-Smtp-Source: ABdhPJzeaWzCL/OchvsZnvqyYn4lNjMpgnVMRGe+gnEZz20DwYICCP0f6ed1/JCFJZ2R5o1VCIdFRQ==
X-Received: by 2002:a9d:760c:: with SMTP id k12mr21176810otl.52.1605170388885;
        Thu, 12 Nov 2020 00:39:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7994:: with SMTP id h20ls548652otm.2.gmail; Thu, 12 Nov
 2020 00:39:48 -0800 (PST)
X-Received: by 2002:a9d:69d5:: with SMTP id v21mr21100343oto.176.1605170388517;
        Thu, 12 Nov 2020 00:39:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605170388; cv=none;
        d=google.com; s=arc-20160816;
        b=EVwlw5s54b7Yx59t059CjHuojUC06bv0WwXSWxDMWc4gwtWWuyQDoO4Hdd5eVGcb8D
         ZxFaoKTBhNEGMVMN693ZVmz9XHfhGx9agGiiPCxmUboTWHdxg4scH+xXSYMxJwq8PVRm
         IdHYtlJSFsAnE4UAiicNb0sF4PXH18FZxmeF+USosWvS+DDeld2qXxjLkKqd7LKETfv9
         oWZQ4ryjmDLMVs7vXJZW5SJXqCPxavG7DDGk3SyoMOaILF0UFoZ1ud2pzp5tX3++3dtm
         2i0py2yHJl12U49XH+iTgxSpdlGNvm1vKeNM+WhS8HaK4CP9u+tCqUE7nefOioHNr6Az
         Telw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=44tChU8hOKh0CYBI3rBAGUumkOlh+n1tK4+x7kNNhRE=;
        b=tvi9zTS55Aeu7xS8KrThB/gUtWsxfgvRaId2hi+YsbXojq0BvMkcTJmFcqHtD2EfLc
         nKlbuI25+uG5OMZCesMlJa/IyHKSFlO2IfnvO1Z/sBAkuzKIzgAOkBOK0Ci3sSqvgYBg
         zTHxL6wQ8Jo3i8J30fzFnt0Ft9Tnnpxq+6KKJtyNCsascmBXciO6HdgJpq5muv/8Z+/n
         S4qzowHn5fUdZ2bX4rkaAQk8F+6uCOOXGmNjIL1z18UGNmsbF/w3tkZbKEj70GwqqDng
         vj+0gkclJY7EWMqBtiL69mYwIoZ2Ett0JespRrOPIU64bX3iGf8hMh/k2MwCOR6SY7jW
         pG6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ES7Ip+66;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id p17si357895oot.0.2020.11.12.00.39.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 00:39:48 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id d28so4529215qka.11
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 00:39:48 -0800 (PST)
X-Received: by 2002:a05:620a:15ce:: with SMTP id o14mr30802446qkm.231.1605170387779;
 Thu, 12 Nov 2020 00:39:47 -0800 (PST)
MIME-Version: 1.0
References: <1605162252-23886-1-git-send-email-Kuan-Ying.Lee@mediatek.com> <1605162252-23886-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <1605162252-23886-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 09:39:36 +0100
Message-ID: <CACT4Y+bpDTqQRRdV0_O07H=Kczj3nXUY9ngQgX5K=BtT=Y60RQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=ES7Ip+66;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Thu, Nov 12, 2020 at 7:25 AM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> We hit this issue in our internal test.
> When enabling generic kasan, a kfree()'d object is put into per-cpu
> quarantine first. If the cpu goes offline, object still remains in
> the per-cpu quarantine. If we call kmem_cache_destroy() now, slub
> will report "Objects remaining" error.
>
> [   74.982625] =============================================================================
> [   74.983380] BUG test_module_slab (Not tainted): Objects remaining in test_module_slab on __kmem_cache_shutdown()
> [   74.984145] -----------------------------------------------------------------------------
> [   74.984145]
> [   74.984883] Disabling lock debugging due to kernel taint
> [   74.985561] INFO: Slab 0x(____ptrval____) objects=34 used=1 fp=0x(____ptrval____) flags=0x2ffff00000010200
> [   74.986638] CPU: 3 PID: 176 Comm: cat Tainted: G    B             5.10.0-rc1-00007-g4525c8781ec0-dirty #10
> [   74.987262] Hardware name: linux,dummy-virt (DT)
> [   74.987606] Call trace:
> [   74.987924]  dump_backtrace+0x0/0x2b0
> [   74.988296]  show_stack+0x18/0x68
> [   74.988698]  dump_stack+0xfc/0x168
> [   74.989030]  slab_err+0xac/0xd4
> [   74.989346]  __kmem_cache_shutdown+0x1e4/0x3c8
> [   74.989779]  kmem_cache_destroy+0x68/0x130
> [   74.990176]  test_version_show+0x84/0xf0
> [   74.990679]  module_attr_show+0x40/0x60
> [   74.991218]  sysfs_kf_seq_show+0x128/0x1c0
> [   74.991656]  kernfs_seq_show+0xa0/0xb8
> [   74.992059]  seq_read+0x1f0/0x7e8
> [   74.992415]  kernfs_fop_read+0x70/0x338
> [   74.993051]  vfs_read+0xe4/0x250
> [   74.993498]  ksys_read+0xc8/0x180
> [   74.993825]  __arm64_sys_read+0x44/0x58
> [   74.994203]  el0_svc_common.constprop.0+0xac/0x228
> [   74.994708]  do_el0_svc+0x38/0xa0
> [   74.995088]  el0_sync_handler+0x170/0x178
> [   74.995497]  el0_sync+0x174/0x180
> [   74.996050] INFO: Object 0x(____ptrval____) @offset=15848
> [   74.996752] INFO: Allocated in test_version_show+0x98/0xf0 age=8188 cpu=6 pid=172
> [   75.000802]  stack_trace_save+0x9c/0xd0
> [   75.002420]  set_track+0x64/0xf0
> [   75.002770]  alloc_debug_processing+0x104/0x1a0
> [   75.003171]  ___slab_alloc+0x628/0x648
> [   75.004213]  __slab_alloc.isra.0+0x2c/0x58
> [   75.004757]  kmem_cache_alloc+0x560/0x588
> [   75.005376]  test_version_show+0x98/0xf0
> [   75.005756]  module_attr_show+0x40/0x60
> [   75.007035]  sysfs_kf_seq_show+0x128/0x1c0
> [   75.007433]  kernfs_seq_show+0xa0/0xb8
> [   75.007800]  seq_read+0x1f0/0x7e8
> [   75.008128]  kernfs_fop_read+0x70/0x338
> [   75.008507]  vfs_read+0xe4/0x250
> [   75.008990]  ksys_read+0xc8/0x180
> [   75.009462]  __arm64_sys_read+0x44/0x58
> [   75.010085]  el0_svc_common.constprop.0+0xac/0x228
> [   75.011006] kmem_cache_destroy test_module_slab: Slab cache still has objects
>
> Register a cpu hotplug function to remove all objects in the offline
> per-cpu quarantine when cpu is going offline. Set a per-cpu variable
> to indicate this cpu is offline.
>
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> ---
>  mm/kasan/quarantine.c | 59 +++++++++++++++++++++++++++++++++++++++++--
>  1 file changed, 57 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 4c5375810449..67fb91ae2bd0 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -29,6 +29,7 @@
>  #include <linux/srcu.h>
>  #include <linux/string.h>
>  #include <linux/types.h>
> +#include <linux/cpuhotplug.h>
>
>  #include "../slab.h"
>  #include "kasan.h"
> @@ -97,6 +98,7 @@ static void qlist_move_all(struct qlist_head *from, struct qlist_head *to)
>   * guarded by quarantine_lock.
>   */

Hi Kuan-Ying,

Thanks for fixing this.

>  static DEFINE_PER_CPU(struct qlist_head, cpu_quarantine);
> +static DEFINE_PER_CPU(int, cpu_quarantine_offline);

I think cpu_quarantine_offline is better be part of cpu_quarantine
because it logically is and we already obtain a pointer to
cpu_quarantine in quarantine_put, so it will also make the code a bit
shorter.


>  /* Round-robin FIFO array of batches. */
>  static struct qlist_head global_quarantine[QUARANTINE_BATCHES];
> @@ -176,6 +178,8 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
>         unsigned long flags;
>         struct qlist_head *q;
>         struct qlist_head temp = QLIST_INIT;
> +       int *offline;
> +       struct qlist_head q_offline = QLIST_INIT;
>
>         /*
>          * Note: irq must be disabled until after we move the batch to the
> @@ -187,8 +191,16 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
>          */
>         local_irq_save(flags);
>
> -       q = this_cpu_ptr(&cpu_quarantine);
> -       qlist_put(q, &info->quarantine_link, cache->size);
> +       offline = this_cpu_ptr(&cpu_quarantine_offline);
> +       if (*offline == 0) {
> +               q = this_cpu_ptr(&cpu_quarantine);
> +               qlist_put(q, &info->quarantine_link, cache->size);
> +       } else {
> +               qlist_put(&q_offline, &info->quarantine_link, cache->size);
> +               qlist_free_all(&q_offline, cache);

This looks like a convoluted way to call qlink_free. I think it will
be better to call qlink_free directly here.

And why do we need this? Because CPU shutdown code can still free some
objects afterwards?

> +               local_irq_restore(flags);
> +               return;

You add both if/else and early return, this looks like unnecessary
code complication. It would be simpler with:

if (*offline) {
    qlink_free(...);
    return;
}
... all current per-cpu local ...


> +       }
>         if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
>                 qlist_move_all(q, &temp);
>
> @@ -328,3 +340,46 @@ void quarantine_remove_cache(struct kmem_cache *cache)
>
>         synchronize_srcu(&remove_cache_srcu);
>  }
> +
> +static int kasan_cpu_online(unsigned int cpu)
> +{
> +       int *offline;
> +       unsigned long flags;
> +
> +       local_irq_save(flags);

I assume this local_irq_save/restore is to prevent some warnings from
this_cpu_ptr.
But CPU online/offline callbacks should run without preemption already
(preempting/rescheduling on other CPUs does not make sense for them,
right?), so I would assume that is already at least preemption
disabled or something. Is there this_cpu_ptr variant that won't
produce warnings on its own in cpu online/offline callbacks?
This whole function could be a 1-liner:
this_cpu_ptr(&cpu_quarantine)->offline = true;
So I am trying to understand if we could avoid all this unnecessary danse.


> +       offline = this_cpu_ptr(&cpu_quarantine_offline);
> +       *offline = 0;
> +       local_irq_restore(flags);
> +       return 0;
> +}
> +
> +static int kasan_cpu_offline(unsigned int cpu)
> +{
> +       struct kmem_cache *s;
> +       int *offline;
> +       unsigned long flags;
> +
> +       local_irq_save(flags);
> +       offline = this_cpu_ptr(&cpu_quarantine_offline);
> +       *offline = 1;
> +       local_irq_restore(flags);
> +
> +       mutex_lock(&slab_mutex);
> +       list_for_each_entry(s, &slab_caches, list) {
> +               per_cpu_remove_cache(s);
> +       }
> +       mutex_unlock(&slab_mutex);

We just want to drop the whole per-cpu cache at once, right? I would
assume there should be a simpler way to do this all at once, rather
than doing this per-slab.

> +       return 0;
> +}
> +
> +static int __init kasan_cpu_offline_quarantine_init(void)
> +{
> +       int ret = 0;
> +
> +       ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
> +                               kasan_cpu_online, kasan_cpu_offline);
> +       if (ret)
> +               pr_err("kasan offline cpu quarantine register failed [%d]\n", ret);
> +       return ret;
> +}
> +late_initcall(kasan_cpu_offline_quarantine_init);
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1605162252-23886-2-git-send-email-Kuan-Ying.Lee%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbpDTqQRRdV0_O07H%3DKczj3nXUY9ngQgX5K%3DBtT%3DY60RQ%40mail.gmail.com.

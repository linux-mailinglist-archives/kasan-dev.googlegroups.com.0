Return-Path: <kasan-dev+bncBCMIZB7QWENRB2ELZH6QKGQETIH4N7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 65D812B3FB3
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 10:27:06 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id n16sf7893900pgk.12
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 01:27:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605518825; cv=pass;
        d=google.com; s=arc-20160816;
        b=mHZSfacRCuKi+PVbmNEFX7WLJNKM49k5rvrugn+LNhoE26/HRH1tADwEybQo6Jr8Yu
         Bs3ily9HGj6PFt0oc5jFo3PvvhQqvYhFgfgZQ4ScbSgcDpvWGB7FblEDfBOYKxaUroPI
         snGKqElnpQLEbNU1Mc7sDsBbT7kjB12KSyRkHmpyVQQh6bYIRiOty8gY96GAYY5uhtSs
         aUvXC44Dy/8geilZZ446j4rL1vyo6bvuj5SSBpJxVti6JFU1i91Slbyc8GeuHN2rTGGo
         g2HPm76BwjeNqQl2idljfZRdYogLfRerRje0TLhWOvSmvraRoPnJZtz/M/eSqHD86/fU
         6ufA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VVeAAg51PQ7M71ONqTW786jh1SGAAcwAvMYhBdCuHi8=;
        b=n7Pf+ybiPaJGVMUpiEqJkTPIgvpNo1tBxu/8B+Ay9fDXq5sL9+yyICUfHwlQ7J4YnB
         4OWKyHQmiPLgc92gU5eOIWrFWBmr6jNI+V8ycssjg1710g7nwkUjKbgjpvwmlWZE9lNh
         HX0K2MarihYJGR/Sb1Pc2fJrVsMdhZaqfVaW6eE4Lbow0tC4giHQmyRWcoK4Om06bh34
         zsafIoU26tU73+grU2orjZV0K1klt19ifza3UNAoY5+GAOp7ENV6XLrG0pW5J99L+QCT
         iPDlOUPRTPtozzNf9Am07EKk908jLE/wLc2vKLCpb4V5hFjLl/rhoNWneRdK2Gr32/DI
         PA+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AYmtyXEd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VVeAAg51PQ7M71ONqTW786jh1SGAAcwAvMYhBdCuHi8=;
        b=kkATj7ou079SeYpTaHwLRRq9Sq5xYIwQx6/QTIZC9dogzkJth3s8PPl+O0sd33HNAN
         nL/aL/oJzekrFplfXec3QPkVM73phvIvvJmoEmJhfuWOQyrflq8EcF+lUnYaLTbmDTU2
         x0kMdPKD5h51qPX5rpm8cgeuvOJkQlH4eKKAPnZDcuS9HjgHz6/ZvuHQatcIidAEkQpw
         C9yMr1FtBKLNwRTk8ytuWfweqGLt/JlAyN7OJQ7EYUm8/9CqbVIzBstBF6s6mOmszCJl
         RqAr1Y4k9hDJLLc1/rTOrGwSC+o2mkzd+QBBg24Nc3nxtDAH7Tv9Gv2G2xxAGQMkTNKy
         NEsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VVeAAg51PQ7M71ONqTW786jh1SGAAcwAvMYhBdCuHi8=;
        b=Q4RC7ZsJuZq5WCl0Kj9fzh53yrjJjxtij3IoseHqUemQq01oWKWLOh94b2oKS75Af7
         +ezC1INwpG4znz0A5XDfb4PJCgKbI4H0XgxRhxafDD3QtbSpzQl+OUiqBSETkMiW/D0+
         VSiolRidPQ0tzJu87tTAaS2Jt8eqnfqY1iJTbm2kD1boOAg7RecyVGs+u5virdmJz65T
         V/xLANrB7Mnp568qh+9P9k37QL5z7Jz0rR2+HIIolDMMGEIa5r6m2KASRAlUUWQzhNWo
         qAmyF8HD549uZWd96blqvrwivd3G/KxmBbSiDka9bDL0kF7MshJN3RYX+89yhS20jA9C
         yYYg==
X-Gm-Message-State: AOAM533y3XsZhOmvvRw+44IfMk19S2Xb9p0C79OIQA29OyesgLs32yr9
	HjJ5ka9KWx/4CfJCSezlmmg=
X-Google-Smtp-Source: ABdhPJx+NiNZ0Zp3mEyRTZGcO9tki4yfEbsOZFoIdLQBZuPDvxut/Yk3Useqyg3tYcyIglIll1CO0A==
X-Received: by 2002:aa7:8a01:0:b029:18b:b71f:ce82 with SMTP id m1-20020aa78a010000b029018bb71fce82mr13862745pfa.52.1605518825088;
        Mon, 16 Nov 2020 01:27:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:784b:: with SMTP id t72ls4855137pfc.1.gmail; Mon, 16 Nov
 2020 01:27:04 -0800 (PST)
X-Received: by 2002:a63:484e:: with SMTP id x14mr12475969pgk.282.1605518824577;
        Mon, 16 Nov 2020 01:27:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605518824; cv=none;
        d=google.com; s=arc-20160816;
        b=vMFew55D9FtV+4tgUhu/dKV51oeqSrPQmnj19TX5E/xitn3IM4ZMtt2IDBD+NNntoF
         z6ZWbkb6tAz4fVVsAKa5eJisgTDAZPnGQ80ORMVGLhGV0UzyFvSwmQWFDKbKjGwrOlyg
         L3DnKMqemprvkEHvtCSuEDNpUuk+2E6cWNswFeTAHR4UlBIo+glegBJip76DQ0cXlF6U
         3kjfskl76iY7sglCOTS728mYl/B8SnR3KlyWI2ySqNeJcmnGUHJt1Rt7yCJnhKjP6FEv
         lkBznYynFIEffBlo0hmSCkZJYEWoU8Rhlog8MvFbShMo79a8CHNGcp+RhAzjq5/gMl5X
         u3LQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xO0juaBQE580WCmD+C2do+lXaG7MUpIc228ombtl2So=;
        b=joujf4eYN6YA1diRgB8hGBENnE2iuNe3akmoVy1aYjxjHQHh9Tt7mA3rzkfKkbV5Yp
         dWO0N/WWbQTxH5MNZqL9FoXmK2R6gLjoScZ2oUj1bRsch5B3+F/S1mjJ0+DZpsINvidW
         +AQ/q21cLdNik+XoxQPnK4taEajViGjcOJ7/CG/iIePa6OGIkbCUtinXnuHem5x/tPZx
         T6/dB8eZNBqY8ZtRJWW1ehi6IR2bjHqKifnLwZxwYI+5tKpJqqvr2VXImhPAXzntFdLk
         IBl8+uMRHQNIAqKZklzDhL+HuVI9bce4mWiIY0MfgvxCsMScvzdYCdCHZMOCWiZB7Hns
         PD2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AYmtyXEd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id g4si1169451pju.0.2020.11.16.01.27.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 01:27:04 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id b16so12162286qtb.6
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 01:27:04 -0800 (PST)
X-Received: by 2002:ac8:37f2:: with SMTP id e47mr13349765qtc.290.1605518823487;
 Mon, 16 Nov 2020 01:27:03 -0800 (PST)
MIME-Version: 1.0
References: <1605508168-7418-1-git-send-email-Kuan-Ying.Lee@mediatek.com> <1605508168-7418-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <1605508168-7418-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 16 Nov 2020 10:26:52 +0100
Message-ID: <CACT4Y+Zy_JQ3y7_P2NXffiijTuxcnh7VPcAGL66Ks2LaLTj-eg@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=AYmtyXEd;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
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

On Mon, Nov 16, 2020 at 7:30 AM Kuan-Ying Lee
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
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Reported-by: Guangye Yang <guangye.yang@mediatek.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Matthias Brugger <matthias.bgg@gmail.com>
> ---
>  mm/kasan/quarantine.c | 35 +++++++++++++++++++++++++++++++++++
>  1 file changed, 35 insertions(+)
>
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 4c5375810449..16e618ea805e 100644
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
> @@ -43,6 +44,7 @@ struct qlist_head {
>         struct qlist_node *head;
>         struct qlist_node *tail;
>         size_t bytes;
> +       bool offline;
>  };
>
>  #define QLIST_INIT { NULL, NULL, 0 }
> @@ -188,6 +190,11 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
>         local_irq_save(flags);
>
>         q = this_cpu_ptr(&cpu_quarantine);
> +       if (q->offline) {
> +               qlink_free(&info->quarantine_link, cache);
> +               local_irq_restore(flags);
> +               return;
> +       }
>         qlist_put(q, &info->quarantine_link, cache->size);
>         if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
>                 qlist_move_all(q, &temp);
> @@ -328,3 +335,31 @@ void quarantine_remove_cache(struct kmem_cache *cache)
>
>         synchronize_srcu(&remove_cache_srcu);
>  }
> +
> +static int kasan_cpu_online(unsigned int cpu)
> +{
> +       this_cpu_ptr(&cpu_quarantine)->offline = false;
> +       return 0;
> +}
> +
> +static int kasan_cpu_offline(unsigned int cpu)
> +{
> +       struct qlist_head *q;
> +
> +       q = this_cpu_ptr(&cpu_quarantine);
> +       q->offline = true;
> +       qlist_free_all(q, NULL);

Looks much nicer now!

What is the story with interrupts in these callbacks?
In the previous patch you mentioned that this CPU can still receive
interrupts for a brief period of time. If these interrupts also free
something, can't we corrupt the per-cpu quarantine? In quarantine_put
we protect it by disabling interrupts I think.


> +       return 0;
> +}
> +
> +static int __init kasan_cpu_offline_quarantine_init(void)
> +{
> +       int ret = 0;
> +
> +       ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
> +                               kasan_cpu_online, kasan_cpu_offline);
> +       if (ret < 0)
> +               pr_err("kasan offline cpu quarantine register failed [%d]\n", ret);
> +       return ret;
> +}
> +late_initcall(kasan_cpu_offline_quarantine_init);
> --
> 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZy_JQ3y7_P2NXffiijTuxcnh7VPcAGL66Ks2LaLTj-eg%40mail.gmail.com.

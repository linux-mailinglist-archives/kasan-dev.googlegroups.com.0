Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUF4UP7AKGQEEWGXGJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C2922CD5B9
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 13:47:13 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id l17sf451444qtj.18
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 04:47:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606999632; cv=pass;
        d=google.com; s=arc-20160816;
        b=oRc7cOTbqodNSeba5NF5CQpnWsw+xeGmqd86L4pwC12AWOcrjY8FlgPrOvJ7Cag8Cs
         pG216P0YehlJsZf8DauBZ83B9ofopTpUjC10x9oLHykSkoqcRcP6xl2cXfsWfmezH2vy
         paE7Gwh7U0YD+VEsMJ2d7ikVfyP19JKvLhlvsVD5oUsfjicXQZ/2MkAjX6eBUqtl/Q/n
         atpje879RG0lk05wGtACQKfBZJh9hMKxfnbICJciKM7UglypJGHHhwOdC+EUBXlNtny8
         hdT/JfT3YluTb+qlT7ueEluzGy2YkxKhIKdUPwujwL1GM1n02EItzyQwe1gjwRFFi9Je
         E0Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9IGy9Kpnl8TxBBu0pqZ9Xo6PO3PH0cNlnh3Y698Jzj8=;
        b=lssr6OZtXKqXo+5pEC/NUpuTfD+fZWDUnY8LFi8S+KyH5frZAlNBlbEql+T2PVY4Ap
         l6UCv8K/pEj9AkG9wVXdzYorrf8fXydkdsGa3ictl24Tl9cS6FWvXJbXgm8bIEzlyxys
         p4psbl612KTo9NQhEyd3zn58Cz++lqInmxmg328eyF8WfsBj5pG7VfplXlRCAt9UaVi/
         6nuY7BodKVrQ8d4LY8d9oM9Lvg4nOuZWIaWCnGwbbtju2CyWODct4rudVEfCPKiqMO/f
         FYjMI5/t0ilWGdqo2dnSnx9FLk/YHoaoniv9a1/F5a1q0d6lOadc3EISiHjRIt+bY+bO
         DEDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RVIUWgPt;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9IGy9Kpnl8TxBBu0pqZ9Xo6PO3PH0cNlnh3Y698Jzj8=;
        b=Dd0OjK0cNe2/NQefP9o8WB6DQrNDfs+wwXSC3LL3m7aSypCWdz8NokzuOQ5l5ICnwb
         irunET2jXoAA1uy8pSCUdpgpKnQA95EbNz2hLmUy9+HmaZU3rb3CRi+JL2smw6aMmTOe
         m4I70CmpMMDt3F9mLbjSjmAogzXps24Wuc/kBKtIes9M3ZPRZSxvx8e05aAOOLR1z+pC
         egR9GScKNtvKY5MrgvyCAEsZyfV4VcT5i5lCi5ZJaeFmqskdqdzouhBUJBSYc6e5+vvQ
         T/H46aEk0TvDZ5pPqLH5oX/d3Ng6c8mdSlWrtJ+wryB3lqxTFGActB4lzdmGPzXQhxE3
         097g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9IGy9Kpnl8TxBBu0pqZ9Xo6PO3PH0cNlnh3Y698Jzj8=;
        b=gNMLGqWW0ch1Bu4jlmUSHBT/Vl7shqBYbp47rMD/M9nov4SXM0YN85DK9rNfa5mIOh
         oSIEhzpvNjbUatQ7nNk1p03v9XQdHK4Hzl21zHMvuUaE02M5EIwvbIaSa8QveTO/qTYb
         hcwMxLCk67x/GhNbr3nrtrwuNO0ev4f49AxfCJAK3gzGphhme026a4bJujBnojEdA5fk
         bB3rI8ZMFM9UuDzOSdGU3Rbl2W+VTXvuIqq4SeZpsO0mcAS8e/Sfj4YOloR9leXDpeR4
         Nk1er6RuJaZM4hPSO3BwwOaIbdK/yU3fD/6fq03bVkxdhXlwWJOSfkvcRv6cDJVu/xIQ
         yYZw==
X-Gm-Message-State: AOAM533Hrwn6coKM4juGKam++VLjPfzQrki8G0AusPenCQXcOsV9lv/8
	62nrLSQ4IJxcJ/8dHLumEM8=
X-Google-Smtp-Source: ABdhPJxdZ5P4H61GuDA5r8+wfytQBqNB+xMYupZf4GvtCS626kCzSpH2v80kxbLnQYf2O4a2Gkg8Mw==
X-Received: by 2002:ad4:4e30:: with SMTP id dm16mr2818551qvb.47.1606999632302;
        Thu, 03 Dec 2020 04:47:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a2d1:: with SMTP id l200ls2455083qke.3.gmail; Thu, 03
 Dec 2020 04:47:11 -0800 (PST)
X-Received: by 2002:a37:aad2:: with SMTP id t201mr2537512qke.61.1606999631858;
        Thu, 03 Dec 2020 04:47:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606999631; cv=none;
        d=google.com; s=arc-20160816;
        b=DvgdKpeBklQXih82S0jpAXrtDF1WZHvxcnGSDQ2E25vnjTKLN+XEETmJoSqpsnDMg5
         BYGA2iwLkkjnwg06j51f3H+D7397MY3VWBj0lWrthg9HjkXs6WBNgFKq+aRDxtQNgZlv
         csiovUm5UK5aQk7Y4i6y7SKkkKcK1AvPeqscAt4tcRCrKbNcGfX+W7I42crqpa50zano
         gvG5VF0hCkKlLoP0MdoqM64wKKoJYqbA86I2kchdUvzXdRPUuCyKwV8hWescSY+w2Knb
         rbbQb03l3nLPlGsmRsvVdXsOOA8uCD5I02mhzBjzpmJvT2RAvnks9WtPg5QohvhXlS3y
         1lJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LyhE2Gh6cABbrVZ7ov6yfexMpJrP0k999yqFA1LYZCc=;
        b=LKbcI2yFYzdxXo9vDdUMYBQFRG7R/FrlSB+Cp3hFsiuxcX3wyCI+s8dkB2yzKY6XWW
         nW+PPTnwYRol4LvQSEhq3kN94OIEpBpfRtTI3Z9wUiu6iRIaCguuzUVz7IpGyHUh3mAT
         G0EWh6PkFtlQZmpl0l0WvPVQ7RQ/wcyPwsB2u293LRtXM7p2euSQ0QvunFQ2X4cVYBvr
         XMbpm8ij6vR1hMMHQ1FIotdXPEqGJR51UCo8Y/3wpyZoHJphnhiA/+d8mTcmfUhUyfVX
         jK8kgbQvV/moYTAn9NnGnX4YJdewU3kRSQPWudHbtCVCKDVyz1bTR9ocp4ShfdX9BX1d
         FSBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RVIUWgPt;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id j44si68272qtc.2.2020.12.03.04.47.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Dec 2020 04:47:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id c79so1220260pfc.2
        for <kasan-dev@googlegroups.com>; Thu, 03 Dec 2020 04:47:11 -0800 (PST)
X-Received: by 2002:a63:f20:: with SMTP id e32mr2860728pgl.130.1606999630819;
 Thu, 03 Dec 2020 04:47:10 -0800 (PST)
MIME-Version: 1.0
References: <1606895585-17382-1-git-send-email-Kuan-Ying.Lee@mediatek.com> <1606895585-17382-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <1606895585-17382-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 3 Dec 2020 13:46:59 +0100
Message-ID: <CAAeHK+z+DPNysrUwfeu27h6sKdn5DDE=BL4t96KiF0mRBNPs+Q@mail.gmail.com>
Subject: Re: [PATCH v3 1/1] kasan: fix object remain in offline per-cpu quarantine
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Matthias Brugger <matthias.bgg@gmail.com>, Nicholas Tang <nicholas.tang@mediatek.com>, 
	Miles Chen <miles.chen@mediatek.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RVIUWgPt;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Dec 2, 2020 at 8:58 AM Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
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
>  mm/kasan/quarantine.c | 40 ++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 40 insertions(+)
>
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 4c5375810449..cac7c617df72 100644
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

Hi Kuan-Ying,

This needs to be rebased onto the mm tree: it has some KASAN patches
that touch this code and rename the info variable to meta.

Thanks!

> +               local_irq_restore(flags);
> +               return;
> +       }
>         qlist_put(q, &info->quarantine_link, cache->size);
>         if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
>                 qlist_move_all(q, &temp);
> @@ -328,3 +335,36 @@ void quarantine_remove_cache(struct kmem_cache *cache)
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
> +       /* Ensure the ordering between the writing to q->offline and
> +        * qlist_free_all. Otherwise, cpu_quarantine may be corrupted
> +        * by interrupt.
> +        */
> +       WRITE_ONCE(q->offline, true);
> +       barrier();
> +       qlist_free_all(q, NULL);
> +       return 0;
> +}
> +
> +static int __init kasan_cpu_quarantine_init(void)
> +{
> +       int ret = 0;
> +
> +       ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
> +                               kasan_cpu_online, kasan_cpu_offline);
> +       if (ret < 0)
> +               pr_err("kasan cpu quarantine register failed [%d]\n", ret);
> +       return ret;
> +}
> +late_initcall(kasan_cpu_quarantine_init);
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1606895585-17382-2-git-send-email-Kuan-Ying.Lee%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz%2BDPNysrUwfeu27h6sKdn5DDE%3DBL4t96KiF0mRBNPs%2BQ%40mail.gmail.com.

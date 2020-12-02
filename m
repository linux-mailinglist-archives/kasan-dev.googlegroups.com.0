Return-Path: <kasan-dev+bncBCMIZB7QWENRBQM7TX7AKGQESHZ75UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E1DA2CB708
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Dec 2020 09:26:43 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id r29sf789841qtu.21
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Dec 2020 00:26:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606897602; cv=pass;
        d=google.com; s=arc-20160816;
        b=dfXWUyhEdGyebMSEkJ8+hJ/WPaahuJNo0yS4ibG0sfvsJV9WZAtXrp1lk7Sd7LL7Oo
         a5CssxiPQAkawUDMUf8cPr5aWFEBzEfdcgQ0oUh6K6G7Mz7/Ffkb6yk1VbjQb3vj6VQo
         cqhDbPtzB9AzfZN7RQSLTO9LPYMPz/H47f/QFg1wN/pza5e2okNmZ9Y6Ic6O1D5CN0yO
         bEAo+q2/5fpuhBcTzYZHiyNXUYzOjJpcmhdkTLwDs3LAJoex8JO1v1XAvlwZmYipZ9Hj
         d+EN4uvuGh/WcDjW+w/tWBLI0tY2tKs4aNCAyLYCpF3dRvx8KP+qQsBnfVowIWsTKEkr
         vHwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vYh0D4SlaRv2U0O7R6yjYbrvH3wYIy9lSnP5JMcVCBQ=;
        b=075Cswo5tYW2qijXDhF4K3a6VQmr93PSDLr8VnWANDlOV7RmQ+ghuI9jWsSeShSlxh
         9zA1yZXOEjCVUiuDpwNpqVsyxWoZMWvf2/hZoi8gHP230KBvde4I5tJZ+hxZcn60/i89
         WgO2KCxqHd0rzUlNK5q9uw8tJ/sd3OdiLdgYA7wNTGQnX/bFK4yahHMPfoGAWu74EAIs
         7Jmo282s23ZYrfj11gmcNpbWigo7o9DafZakh+ZEDAj3mnTeZqSLfLHDZs9qRsaA+YoK
         HxbEtih294wDwlxvY5fv/xcsm/ZRakxpBMecqMx/DvONfgekU6pp+uvcmwa44mIyK9Jq
         4uEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kQMR5gNi;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vYh0D4SlaRv2U0O7R6yjYbrvH3wYIy9lSnP5JMcVCBQ=;
        b=MQpQe8+EVIiIzK6DWXscExEslDzREKSIzxsOj1ejt6B4RpdUBqMz0xF58SRcfMjoiN
         SRBEOUI5qHNjESq7lw8YUalxUieRI/efL/zlgWXc18TQVSypV12Q+bO0n/rBn86tigbC
         YQn6vUFE1KroKdg6bBHjHkJN89sbK6Azm24DN60Ipk1DcM1lrMG1VorPzhnXhEtTS2D9
         R6lcFSfjPHxwevt+OWvixeDMMD5ffQoav6dwX1ZbkpRei0YsMZrLVluXFl2c27c2CfdW
         JU38P8ZQIlKdM/RZJFbkVTBVlOXuwbhUibsI3iiCYa+a7um5t2hiVDtgW6bv2kFGw73w
         eYbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vYh0D4SlaRv2U0O7R6yjYbrvH3wYIy9lSnP5JMcVCBQ=;
        b=VANMRjkibQoLoxmYh5C35y0kOUlizKNLGUuaTL8+b2ucYE7VunlojDle0dxWzbEStA
         zezwMHj7G97a+FnwgmoS1vjoBqi3peDFW4C9Yc2Jx7OatYqJvExGVp6/cONObmXX4pW1
         YFTOMqLOwZ1JfgBZZReg4vEt/5dPwd13aBvpywb5MEJoXcXXNeRBGTb59x6Ie3EAbRb5
         JogbqiJrdP3aPtFZp9MGfLd0d+WKqg3yviiiz2WIJZUT/Z6Fm0KPd/hYdT6xAUq33j1Q
         ZJ7BJjhuQtogQrkcfZHlQPpXvyAGoX9AcyLVlohsRDFC0hdphitKNF3Mugr6HdOiYdVg
         FypQ==
X-Gm-Message-State: AOAM533hd55swa6fKTaZ1UdFypG3W+A45FbWo2/go7AncO6LyJOriESK
	J+5lLvqxBxwseNk/nzmX5Gc=
X-Google-Smtp-Source: ABdhPJyu2VOqksvGGPWOMiOOUdvfDKoooxmW74ty9+pxkZSFhbIpXB9XDnhQlkrZ+TZPra/zQD5riA==
X-Received: by 2002:a0c:b8ae:: with SMTP id y46mr1419522qvf.51.1606897601914;
        Wed, 02 Dec 2020 00:26:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6615:: with SMTP id a21ls425350qkc.10.gmail; Wed, 02 Dec
 2020 00:26:41 -0800 (PST)
X-Received: by 2002:a05:620a:1005:: with SMTP id z5mr240156qkj.350.1606897601492;
        Wed, 02 Dec 2020 00:26:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606897601; cv=none;
        d=google.com; s=arc-20160816;
        b=JVhg4nDGP8A59EdCC+2qxSNcxkpdbEPb0Q1n44101h5DHggJ3ZPGz4ply3ppCFzbx+
         VMrPRDye/XtuWnYI8bW6XXMCsO1KoMl+urP40CtsifrzTGo3sEpLHcSTamGqrUnrdNJe
         GJtJH73BHS6YZrRFfFdUa5wbXeXSMn6veRI4+J8TLmNxbjEv4wIvwhFGv+fwEb9qQhdn
         wZFbhm+NNG45Rut7iXj0DN7Y1lrP9FXdG5Vq86ADYX1e6bdxPbvYh7uKaYN8AuiN1hsN
         JJ9YulbeNyUwYsN8LUjHL8U0Vjg5F/1WSK/OOrzswldOhbBdOOJPVRsmrKvOL1EhVuQb
         rLxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FmY534xqIDhl01APeKsQP14KEWKOgWXllxn9uDK2ABs=;
        b=xD0dWSzu9/179eHaBfVjMSY+mKiySq/s52ms1ArBRc1vH+WRb3GGnJ61Irh1/Uhb/G
         JT1oE97lGbu1nz33zss+eVn1DUExG0hdCkZgZYh8+UvT6OmPgyppT3Tsmx0pwBsRkbG5
         1gQqR3RBrGR4roGidssQDqFJPfDA8ESeKQJot3lwrw6lupFIfE9TD5LMh0dJMpxg2wKr
         4vq2jzCONk1QKKIglffH6zxp7S7PoxTQ2dpRL1OzKYKAnF8fQZo45Zvg3JvLALUPkG2O
         0zWfbSiPn87AxSzgU4BDASdR4VQ9jrFjZSkXI7PNGvudwj/0VJiZlrbp2b2cLv1Qrhup
         OXJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kQMR5gNi;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id h185si80263qke.7.2020.12.02.00.26.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Dec 2020 00:26:41 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id x25so506646qkj.3
        for <kasan-dev@googlegroups.com>; Wed, 02 Dec 2020 00:26:41 -0800 (PST)
X-Received: by 2002:a05:620a:12e4:: with SMTP id f4mr1370416qkl.265.1606897601009;
 Wed, 02 Dec 2020 00:26:41 -0800 (PST)
MIME-Version: 1.0
References: <1606895585-17382-1-git-send-email-Kuan-Ying.Lee@mediatek.com> <1606895585-17382-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <1606895585-17382-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Dec 2020 09:26:29 +0100
Message-ID: <CACT4Y+bvo5Hg1OfXYipdWTJPsBtG265X5wtBaVBqhydBwouMkA@mail.gmail.com>
Subject: Re: [PATCH v3 1/1] kasan: fix object remain in offline per-cpu quarantine
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	Nicholas Tang <nicholas.tang@mediatek.com>, Miles Chen <miles.chen@mediatek.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kQMR5gNi;       spf=pass
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

Looks good to me, thanks.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>


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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bbvo5Hg1OfXYipdWTJPsBtG265X5wtBaVBqhydBwouMkA%40mail.gmail.com.

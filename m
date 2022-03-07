Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7FDTCIQMGQE4GPTDXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 461A34D00BD
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Mar 2022 15:09:01 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id n14-20020a4a848e000000b00320fa3f046csf1107653oog.23
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Mar 2022 06:09:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646662140; cv=pass;
        d=google.com; s=arc-20160816;
        b=J4a9nrt/vhwODVzHoOlvgZm8yUiEvJ23DRhLqWOCMSK0QHGgLYFuyxI8IWu1E/o7LC
         PHQEvOaYB7Ii631QlBV7MT4hHc3gqGvuiB0zqLINXnQNVxUrYRR+Ywz09cL0ZUQS1hlW
         ARL3Vp7mdcenEW8ei96v2+KhDGg0AyyqfJ04Hp/2oQ+j4li3v3RfWE/GK+nQLgt3D9Z2
         B7wH+qaiaF8TQIVzmx0+zsVt6OiAPg0aghMLgeG4+I3gs8dWNWiSZZFSC+rpxFx6onI/
         FOJO7s/s4mL1L0MenhUrs5jr2/Hhj4XKU/joQBmL7FcVDS+IxjBpbwmGJL+D3Ex2howK
         5wOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UPNeAn2Lr+WuB/35UMq0UOzloetjAoZecTH1plhX4sQ=;
        b=VlAYbGqnXO3degf6JoNZxUqA/yhgFBZe20wW60DD0065n1R1+G3CWw2+FWbVw8AA1A
         LNuRbWQi7xY1mD4M5Ljse5Oi7XVVOpxgjyweVMsR7Y90fI1ktnIVDBFsG/zTPhlHJvmz
         5rxbVvIdSBv2znpEPie3mplcpA9wOWxriVsR2T+5XjbqZnIOFGYmvc2VlMoXdmecFfaS
         WdAEt2I/hOo1/nazT9TNqU/VjfHnl5086QYyf2I++uJS/++57YUT+h9bU78uK8impwS4
         BxEzOO74cqdrVtFoZQyFFAKiH2ddgXzV0hOVNb5fEIJZ5x2Myxc6RJ3bfhL5fPpohIeU
         9n1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=B4g1Mvdp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UPNeAn2Lr+WuB/35UMq0UOzloetjAoZecTH1plhX4sQ=;
        b=Dxxbzm7488umlFE+uhoZ6mTmy3vCEFUtBEPDgvZB+5vt5H3Ny4X3YZ/OlIzb/tpVGL
         Hvc8ypokmoGo9v+jpWwMXMHEftMjJK5HrAlVRxaG4q3V2vu4Ql5/X7zCRgy/ibrV84VP
         lhPgcJEsl4foar/BQBWNcXat5As1HyPAkJynpdXObW4xSoOW64dnIPCPr6q3F3m6hwWt
         ZU4aSBxvvS6gMSN1YOBm/ErI/hwr1l/Y0/oLKIw9RNtQSwCH0wDnSf7zHhM0GMeP3x75
         pJfY1tGDgBNpUQ+Tf6lDcOdKVAAIvLoE0LEPGOhQ3NSnGcrKo1KTIKHayjL7RGdSqrWy
         1w3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UPNeAn2Lr+WuB/35UMq0UOzloetjAoZecTH1plhX4sQ=;
        b=kQOmmYjd22F1IWSrI+oPBD7YNGTqqBArUE7IuXV8ueA/+wtTfP7BtYdAkCkTXEyO/Q
         vHXuRsQ6oW0pBNvTMiQ3MDF4WVI71TXIpF+RMflKG+A8wMhhHwNPbZoBd2dTgDZaxNmH
         6/9z0lcHo+fOX/AgfDk8ogUvO+DuF6D6mFlwMgfvta6F5psYm2LQLs16N/E0SuwYd3bj
         qboqJqBO3fDBz9j3tMwRV0aZf4EmPRN+pH2mQJNl598VFrEFl9VclHuVuq6frwN4hStn
         MtPJsv3cb+kJ9dnfbkkI4fsqsYnuZiOAyqxi+7NiG2La/Skic4CCNOq3mom2P9/wTeBy
         qe6Q==
X-Gm-Message-State: AOAM531VX91wtDY+iAqC/irCU+RBnwiVAVBp40jlaz+IBcNs2XVHtmcP
	uKo+x7Rp3JXr3N5aZiuK+fc=
X-Google-Smtp-Source: ABdhPJyIKEpLxipdBxjY5ppmRiKAq2uH+FYhMY14xvk4B53+upEDf5cfEbJOmxjfrvdNOJ+oh/H0vA==
X-Received: by 2002:a05:6870:420f:b0:d9:a032:a120 with SMTP id u15-20020a056870420f00b000d9a032a120mr5708625oac.0.1646662140158;
        Mon, 07 Mar 2022 06:09:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a1a0:b0:d7:1d2b:ec1a with SMTP id
 a32-20020a056870a1a000b000d71d2bec1als4179871oaf.3.gmail; Mon, 07 Mar 2022
 06:08:59 -0800 (PST)
X-Received: by 2002:a05:6870:8186:b0:da:b3f:2b2e with SMTP id k6-20020a056870818600b000da0b3f2b2emr6019540oae.205.1646662139748;
        Mon, 07 Mar 2022 06:08:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646662139; cv=none;
        d=google.com; s=arc-20160816;
        b=c9hoD2DDBwFcpz1KuXvoq+axavZMY7GEPHMd5YQ4rPzBoZEzQml8PuyV+TSidgraQA
         v69WaEn40oNbAor34VqkLRsLXt69lS9UFr0JgfWv3yBh96X9o/SeXYAViugw8iGbhxti
         K6kwL7wg6gphXVtHtKvqLqywAbBm9tNGgBXNpI5gEUKyAvBfrRmPe9YX6pjWQEOtVv7W
         OJQtVEnq0ADWTy9mA7pOYSEBDeNQvzL8v5wZdhl5SIgtQEZIAL001dT/c9fbKJWwUyq6
         nkA3Gfy7DZ+aJUGxRWO3vp+YPEWOk0ESj95xKEUPFyI3LHg3gYHcszR6F6dat8YgBrIW
         8lyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0yk9BdGE0P4qhl7kTJOlzN4O3c8JJe4T1InJDUcBabo=;
        b=bxnqh0O6ZBz61fqOxklTjtaiqqNJzBOWsQ5F3M3TxZJY1zjMwWdZ+CN19DE6bwcv8w
         7GHT9PUTx+z8T8YTsaiOC0+OOgAHdzPNEz/j2KytFQLMqg+cECTeRTTUCkkke2bbH4Q5
         vgnLGUkDEO19rCp0uvUcwQEdzzsCGv5RTaLEqrsQFgMQOAVu1kyI/Z/ISd72r7vxoBTY
         koBHjnQykCS1/TJym0gEVZ1Y+aT4BkT833ujWbgX/dWSWniKl/D59WMdHvSr0o4FthMw
         Ye7jRJva1NgQX46sEpnmLx7SiXNfG129LZqCUCYK1TknQ6W5xM2SWUjgWC0OFTuEjbH/
         kjRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=B4g1Mvdp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id y24-20020a056830071800b005af3a0effdfsi2239024ots.0.2022.03.07.06.08.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Mar 2022 06:08:59 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id g1so31176176ybe.4
        for <kasan-dev@googlegroups.com>; Mon, 07 Mar 2022 06:08:59 -0800 (PST)
X-Received: by 2002:a05:6902:203:b0:628:7b6f:2845 with SMTP id
 j3-20020a056902020300b006287b6f2845mr8118330ybs.533.1646662139111; Mon, 07
 Mar 2022 06:08:59 -0800 (PST)
MIME-Version: 1.0
References: <20220307074516.6920-1-dtcccc@linux.alibaba.com> <20220307074516.6920-3-dtcccc@linux.alibaba.com>
In-Reply-To: <20220307074516.6920-3-dtcccc@linux.alibaba.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Mar 2022 15:08:22 +0100
Message-ID: <CANpmjNPu+4VohTfFn6H-jBgL4zE2uexU3dqmks3LJy_chu34pg@mail.gmail.com>
Subject: Re: [PATCH v3 2/2] kfence: Alloc kfence_pool after system startup
To: Tianchen Ding <dtcccc@linux.alibaba.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=B4g1Mvdp;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 7 Mar 2022 at 08:45, Tianchen Ding <dtcccc@linux.alibaba.com> wrote:
>
> Allow enabling KFENCE after system startup by allocating its pool via the
> page allocator. This provides the flexibility to enable KFENCE even if it
> wasn't enabled at boot time.
>
> Signed-off-by: Tianchen Ding <dtcccc@linux.alibaba.com>

This looks good, thanks!

Reviewed-by: Marco Elver <elver@google.com>
Tested-by: Marco Elver <elver@google.com>


> ---
>  mm/kfence/core.c | 111 ++++++++++++++++++++++++++++++++++++++---------
>  1 file changed, 90 insertions(+), 21 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index caa4e84c8b79..f126b53b9b85 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -96,7 +96,7 @@ static unsigned long kfence_skip_covered_thresh __read_mostly = 75;
>  module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644);
>
>  /* The pool of pages used for guard pages and objects. */
> -char *__kfence_pool __ro_after_init;
> +char *__kfence_pool __read_mostly;
>  EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
>
>  /*
> @@ -537,17 +537,19 @@ static void rcu_guarded_free(struct rcu_head *h)
>         kfence_guarded_free((void *)meta->addr, meta, false);
>  }
>
> -static bool __init kfence_init_pool(void)
> +/*
> + * Initialization of the KFENCE pool after its allocation.
> + * Returns 0 on success; otherwise returns the address up to
> + * which partial initialization succeeded.
> + */
> +static unsigned long kfence_init_pool(void)
>  {
>         unsigned long addr = (unsigned long)__kfence_pool;
>         struct page *pages;
>         int i;
>
> -       if (!__kfence_pool)
> -               return false;
> -
>         if (!arch_kfence_init_pool())
> -               goto err;
> +               return addr;
>
>         pages = virt_to_page(addr);
>
> @@ -565,7 +567,7 @@ static bool __init kfence_init_pool(void)
>
>                 /* Verify we do not have a compound head page. */
>                 if (WARN_ON(compound_head(&pages[i]) != &pages[i]))
> -                       goto err;
> +                       return addr;
>
>                 __SetPageSlab(&pages[i]);
>         }
> @@ -578,7 +580,7 @@ static bool __init kfence_init_pool(void)
>          */
>         for (i = 0; i < 2; i++) {
>                 if (unlikely(!kfence_protect(addr)))
> -                       goto err;
> +                       return addr;
>
>                 addr += PAGE_SIZE;
>         }
> @@ -595,7 +597,7 @@ static bool __init kfence_init_pool(void)
>
>                 /* Protect the right redzone. */
>                 if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
> -                       goto err;
> +                       return addr;
>
>                 addr += 2 * PAGE_SIZE;
>         }
> @@ -608,9 +610,21 @@ static bool __init kfence_init_pool(void)
>          */
>         kmemleak_free(__kfence_pool);
>
> -       return true;
> +       return 0;
> +}
> +
> +static bool __init kfence_init_pool_early(void)
> +{
> +       unsigned long addr;
> +
> +       if (!__kfence_pool)
> +               return false;
> +
> +       addr = kfence_init_pool();
> +
> +       if (!addr)
> +               return true;
>
> -err:
>         /*
>          * Only release unprotected pages, and do not try to go back and change
>          * page attributes due to risk of failing to do so as well. If changing
> @@ -623,6 +637,26 @@ static bool __init kfence_init_pool(void)
>         return false;
>  }
>
> +static bool kfence_init_pool_late(void)
> +{
> +       unsigned long addr, free_size;
> +
> +       addr = kfence_init_pool();
> +
> +       if (!addr)
> +               return true;
> +
> +       /* Same as above. */
> +       free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
> +#ifdef CONFIG_CONTIG_ALLOC
> +       free_contig_range(page_to_pfn(virt_to_page(addr)), free_size / PAGE_SIZE);
> +#else
> +       free_pages_exact((void *)addr, free_size);
> +#endif
> +       __kfence_pool = NULL;
> +       return false;
> +}
> +
>  /* === DebugFS Interface ==================================================== */
>
>  static int stats_show(struct seq_file *seq, void *v)
> @@ -771,31 +805,66 @@ void __init kfence_alloc_pool(void)
>                 pr_err("failed to allocate pool\n");
>  }
>
> +static void kfence_init_enable(void)
> +{
> +       if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))
> +               static_branch_enable(&kfence_allocation_key);
> +       WRITE_ONCE(kfence_enabled, true);
> +       queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
> +       pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
> +               CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
> +               (void *)(__kfence_pool + KFENCE_POOL_SIZE));
> +}
> +
>  void __init kfence_init(void)
>  {
> +       stack_hash_seed = (u32)random_get_entropy();
> +
>         /* Setting kfence_sample_interval to 0 on boot disables KFENCE. */
>         if (!kfence_sample_interval)
>                 return;
>
> -       stack_hash_seed = (u32)random_get_entropy();
> -       if (!kfence_init_pool()) {
> +       if (!kfence_init_pool_early()) {
>                 pr_err("%s failed\n", __func__);
>                 return;
>         }
>
> -       if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))
> -               static_branch_enable(&kfence_allocation_key);
> -       WRITE_ONCE(kfence_enabled, true);
> -       queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
> -       pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
> -               CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
> -               (void *)(__kfence_pool + KFENCE_POOL_SIZE));
> +       kfence_init_enable();
> +}
> +
> +static int kfence_init_late(void)
> +{
> +       const unsigned long nr_pages = KFENCE_POOL_SIZE / PAGE_SIZE;
> +#ifdef CONFIG_CONTIG_ALLOC
> +       struct page *pages;
> +
> +       pages = alloc_contig_pages(nr_pages, GFP_KERNEL, first_online_node, NULL);
> +       if (!pages)
> +               return -ENOMEM;
> +       __kfence_pool = page_to_virt(pages);
> +#else
> +       if (nr_pages > MAX_ORDER_NR_PAGES) {
> +               pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocator\n");
> +               return -EINVAL;
> +       }
> +       __kfence_pool = alloc_pages_exact(KFENCE_POOL_SIZE, GFP_KERNEL);
> +       if (!__kfence_pool)
> +               return -ENOMEM;
> +#endif
> +
> +       if (!kfence_init_pool_late()) {
> +               pr_err("%s failed\n", __func__);
> +               return -EBUSY;
> +       }
> +
> +       kfence_init_enable();
> +       return 0;
>  }
>
>  static int kfence_enable_late(void)
>  {
>         if (!__kfence_pool)
> -               return -EINVAL;
> +               return kfence_init_late();
>
>         WRITE_ONCE(kfence_enabled, true);
>         queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
> --
> 2.27.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPu%2B4VohTfFn6H-jBgL4zE2uexU3dqmks3LJy_chu34pg%40mail.gmail.com.

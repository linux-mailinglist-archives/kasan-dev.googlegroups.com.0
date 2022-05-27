Return-Path: <kasan-dev+bncBCMIZB7QWENRB3H3YKKAMGQE4KXRRWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AF7B53616D
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 14:02:53 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id d2-20020a2e8902000000b00253bba7ce10sf1225104lji.12
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 05:02:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653652972; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mg0trjaelEU0evOyEHNuLoAv1W4JTTfvxYC2ykX+apHw9DMYZB8DX0KbixuxEH/xwt
         uXnknlf5EUiRd+PKox0gseSkugk54W0Pn8YDu2/U6Y/Zk0D35N70MLLaWs2pEgFBBqdr
         fJLZ8jphK+qkaZ10flfOFmHVEgW0dBcTT/dldKCV1/Loe831h4kDilLU+JqiMAsIymlZ
         9Uz/TujHeYU6SR+DaiMAVqGxH9yVJRm7+qnq/dZo9YlDg/+Y+njbz7kS2mGp9B7JmVlD
         ctd8PPK24nXnalpNbONE3TlIo5kjydOG7KMkciwGUGV+zkHh7lHeBZau9wtp7mZUyqoV
         p0Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2fdpCiXonQl5LVbmL0nn4T7+l0jzomDEG6z9VDmML4M=;
        b=GF0RQ7FkRsCIwIBlDnOOIKgLsKXUcJeJKybhQ5SOvMLfo0VD2++TezWHB4D2eA0SGA
         RLK+oWvW322Ryy4GDuvLedF3SvUK+sFNIjVPSvktiVamtQOUzXA2sjbSz/Sc73vQoSlf
         4el53RWpq50MXl87cwPoyAH/PEtr6Hccd/eshOqv9rTqsYWKDWsedna9CKvDhfC/w2ZN
         iluQHSKoN3/hVcOB6UxF2lHnV0GM3ucDFuYxa8sHptGk/MFtogp99jDDJrmjEmNvygXt
         FBQweHJJ1AE1E62rxS7fX4iumFXtO2DdmVWV2n8LyIzYuPJ+7ssxbIU5g6i8gaBQHcU7
         djxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Q0LhMW8Q;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2fdpCiXonQl5LVbmL0nn4T7+l0jzomDEG6z9VDmML4M=;
        b=K/6aqVsiztIAil8H9DRwqRfu4pQK8iaevULHdEMXE25Tixi20uSE8dXX618l7qwmPj
         nBvRUVJleJQQ9v5pTrZnmdufBAvWal6K1w9eqvFtFIjuZsqwzrwR9Ft7Mcu+GhDqP9TL
         Gh2QYs6enYu14xzAzTmYLIqn26bCIhWIciA1ET1R4vjSi4PDCnPypovRZrBMg+/5Bfxk
         OmGa1P9csllgh2M40gMY2EKfOHD3DF5vK5/aYmorA5D//HX6OcUXJLsdWNkT0NXFEuCD
         79QCd8kwcQQC2vOgZk59pRI+Sg2M3HeSTUptvG+vJ0D/QWkmYlix8HV6Ytp4Ddndw9cx
         HdoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2fdpCiXonQl5LVbmL0nn4T7+l0jzomDEG6z9VDmML4M=;
        b=iEuSNNynauR5a5okRKwR4hUndhrYTi4c2dDNcC0kin9T+Lp5cdVdv2Ai5E8+drRy2l
         SULEk3eePy6zc/MDTMgqcPoJUo0UZhb45u68ZvjwoTG1O2fWDQEfjLOX+umJ17sRKbMP
         3g7kDh+85V3id8UM9F30Zo78Ee1noGWhETo1U4I1Pjm6dMkkfTLN1uVGHjR1U8PnIhFh
         KVf9wE0DBpvzUnJrcEwK+2gCa+5BsIjR+KFoihrFl8gxGkIb1/F7rpD9pH2j6hmfJxSI
         qTBgMqEpKCRTItj4W8SFSgoFBDboycaIwKywuZOsPN7sI4Vq8hNGPBskDr7PSGJKwdm6
         qWvw==
X-Gm-Message-State: AOAM533c4RlPmUkFT+pCXKdnv5N8aMXI3E1AWYgRNQGDHMt69O9RoLqY
	LgYStaNrgG/yY3h1BfL5i2o=
X-Google-Smtp-Source: ABdhPJxv7mliGOCofjhkGiveenH21HhvpPhuEgNWx70KJhdm4sASd2LGvUPNN2JZ690MG1ZMMmaW6A==
X-Received: by 2002:a2e:9097:0:b0:253:c84e:e4a6 with SMTP id l23-20020a2e9097000000b00253c84ee4a6mr24392514ljg.529.1653652972427;
        Fri, 27 May 2022 05:02:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als1054609lfa.2.gmail; Fri, 27 May 2022
 05:02:51 -0700 (PDT)
X-Received: by 2002:a05:6512:209:b0:478:99dd:2d2 with SMTP id a9-20020a056512020900b0047899dd02d2mr10569929lfo.44.1653652971153;
        Fri, 27 May 2022 05:02:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653652971; cv=none;
        d=google.com; s=arc-20160816;
        b=A17d/DnTgqsA5NsUiATxHn0Pxcy+Yqudg1iLi2Q8jYgYzI7iJJbh/IAKCxAX1EkVPy
         TUyyWDHa5O5/dev6qRtfWv95sOFMEjVGNycxNQkDtfO8d4n/mf4yX2fF/7YHuHfedydI
         F85B+U/KX891IdMeYHIeyCAbYJw/H1Q5rEKLmPqUDw9Uz4tlxqRd1H7n94JHKq45HIf9
         RrCVtznVzMnotnSZ7scLTpe0c/BhyoqUuz/6QJvx6M7Ncp4367jTev+1YVuSIn5i8i6L
         rdhjgmSvQvMJgmnvpLkqMBb/gcPxk7b2dl7SfDRoDvOezbXYIGfU7leKj6RovRQzdLBr
         0l8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aqvudJmTK1NuR+GVwPWW+sM4XNkpoIxtq49HohR+1C0=;
        b=tKRWwyO8WFvvBkFDG64+34UEw8I/CrVIFkZAVqJfdiLuhMEpv+0ABDTmmOhDDb71mk
         OcQrYt3YfVUuwMAGOtDVFYYBYY2DK76fFRhtCorMoSejVoB4pW4aObKDdd2qOTGuIVlL
         B3R7TpOqf8DR0CuQ8Wr3/2mkHUVxiJc/7DSy8/eHBCBR+HJ5yVn3DjbDEa9K80jwsrQM
         evmk/9PpZqRBsTBcpvbgJc/2hohgdfC7W+Wh33i/zYB8sqycVjldC85K0Iqv48EoWm0E
         sEn+Hc+5KL5Eiex6qly+6XMRDO1zZ0/zlqOmWnXsKuMKVGHYed6ZBZGjbfG6S+UrbpmU
         /g9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Q0LhMW8Q;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x235.google.com (mail-lj1-x235.google.com. [2a00:1450:4864:20::235])
        by gmr-mx.google.com with ESMTPS id bi20-20020a05651c231400b0024c7f087105si192020ljb.8.2022.05.27.05.02.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 May 2022 05:02:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) client-ip=2a00:1450:4864:20::235;
Received: by mail-lj1-x235.google.com with SMTP id v9so4692561lja.12
        for <kasan-dev@googlegroups.com>; Fri, 27 May 2022 05:02:51 -0700 (PDT)
X-Received: by 2002:a05:651c:1797:b0:254:1a3a:801a with SMTP id
 bn23-20020a05651c179700b002541a3a801amr5727591ljb.363.1653652970506; Fri, 27
 May 2022 05:02:50 -0700 (PDT)
MIME-Version: 1.0
References: <20220527113706.24870-1-vbabka@suse.cz> <20220527113706.24870-2-vbabka@suse.cz>
In-Reply-To: <20220527113706.24870-2-vbabka@suse.cz>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 May 2022 14:02:38 +0200
Message-ID: <CACT4Y+Y4GZfXOru2z5tFPzFdaSUd+GFc6KVL=bsa0+1m197cQQ@mail.gmail.com>
Subject: Re: [RFC PATCH 1/1] lib/stackdepot: replace CONFIG_STACK_HASH_ORDER
 with automatic sizing
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@gmail.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Q0LhMW8Q;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235
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

On Fri, 27 May 2022 at 13:37, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> As Linus explained [1], setting the stackdepot hash table size as a
> config option is suboptimal, especially as stackdepot becomes a
> dependency of less specialized subsystems than initially (e.g. DRM,
> networking, SLUB_DEBUG):
>
> : (a) it introduces a new compile-time question that isn't sane to ask
> : a regular user, but is now exposed to regular users.
>
> : (b) this by default uses 1MB of memory for a feature that didn't in
> : the past, so now if you have small machines you need to make sure you
> : make a special kernel config for them.
>
> Ideally we would employ rhashtable for fully automatic resizing, which
> should be feasible for many of the new users, but problematic for the
> original users with restricted context that call __stack_depot_save()
> with can_alloc == false, i.e. KASAN.
>
> However we can easily remove the config option and scale the hash table
> automatically with system memory. The STACK_HASH_MASK constant becomes
> stack_hash_mask variable and is used only in one mask operation, so the
> overhead should be negligible to none. For early allocation we can
> employ the existing alloc_large_system_hash() function and perform
> similar scaling for the late allocation.
>
> The existing limits of the config option (between 4k and 1M buckets)
> are preserved, and scaling factor is set to one bucket per 16kB memory
> so on 64bit the max 1M buckets (8MB memory) is achieved with 16GB
> system, while a 1GB system will use 512kB.

Hi Vlastimil,

We use KASAN with VMs with 2GB of memory.
If I did the math correctly this will result in 128K entries, while
currently we have CONFIG_STACK_HASH_ORDER=20 even for arm32.
I am actually not sure how full the table gets, but we can fuzz a
large kernel for up to an hour, so we can get lots of stacks (we were
the only known users who routinely overflowed default LOCKDEP tables
:)).

I am not opposed to this in general. And I understand that KASAN Is
different from the other users.
What do you think re allowing CONFIG_STACK_HASH_ORDER=0/is not set
which will mean auto-size, but keeping ability to set exact size as
well?
Or alternatively auto-size if KASAN is not enabled and use a large
table otherwise? But I am not sure if anybody used
CONFIG_STACK_HASH_ORDER to reduce the default size with KASAN...



> If needed, the automatic scaling could be complemented with a boot-time
> kernel parameter, but it feels pointless to add it without a specific
> use case.
>
> [1] https://lore.kernel.org/all/CAHk-=wjC5nS+fnf6EzRD9yQRJApAhxx7gRB87ZV+pAWo9oVrTg@mail.gmail.com/
>
> Reported-by: Linus Torvalds <torvalds@linux-foundation.org>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  lib/Kconfig      |  9 ---------
>  lib/stackdepot.c | 47 ++++++++++++++++++++++++++++++++++++-----------
>  2 files changed, 36 insertions(+), 20 deletions(-)
>
> diff --git a/lib/Kconfig b/lib/Kconfig
> index 6a843639814f..1e7cf7c76ae6 100644
> --- a/lib/Kconfig
> +++ b/lib/Kconfig
> @@ -682,15 +682,6 @@ config STACKDEPOT_ALWAYS_INIT
>         bool
>         select STACKDEPOT
>
> -config STACK_HASH_ORDER
> -       int "stack depot hash size (12 => 4KB, 20 => 1024KB)"
> -       range 12 20
> -       default 20
> -       depends on STACKDEPOT
> -       help
> -        Select the hash size as a power of 2 for the stackdepot hash table.
> -        Choose a lower value to reduce the memory impact.
> -
>  config REF_TRACKER
>         bool
>         depends on STACKTRACE_SUPPORT
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 5ca0d086ef4a..f7b73ddfca77 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -145,10 +145,15 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
>         return stack;
>  }
>
> -#define STACK_HASH_SIZE (1L << CONFIG_STACK_HASH_ORDER)
> -#define STACK_HASH_MASK (STACK_HASH_SIZE - 1)
> +/* one hash table bucket entry per 16kB of memory */
> +#define STACK_HASH_SCALE       14
> +/* limited between 4k and 1M buckets */
> +#define STACK_HASH_ORDER_MIN   12
> +#define STACK_HASH_ORDER_MAX   20
>  #define STACK_HASH_SEED 0x9747b28c
>
> +static unsigned int stack_hash_mask;
> +
>  static bool stack_depot_disable;
>  static struct stack_record **stack_table;
>
> @@ -175,8 +180,6 @@ void __init stack_depot_want_early_init(void)
>
>  int __init stack_depot_early_init(void)
>  {
> -       size_t size;
> -
>         /* This is supposed to be called only once, from mm_init() */
>         if (WARN_ON(__stack_depot_early_init_passed))
>                 return 0;
> @@ -186,10 +189,15 @@ int __init stack_depot_early_init(void)
>         if (!__stack_depot_want_early_init || stack_depot_disable)
>                 return 0;
>
> -       size = (STACK_HASH_SIZE * sizeof(struct stack_record *));
> -       pr_info("Stack Depot early init allocating hash table with memblock_alloc, %zu bytes\n",
> -               size);
> -       stack_table = memblock_alloc(size, SMP_CACHE_BYTES);
> +       stack_table = alloc_large_system_hash("stackdepot",
> +                                               sizeof(struct stack_record *),
> +                                               0,
> +                                               STACK_HASH_SCALE,
> +                                               HASH_EARLY | HASH_ZERO,
> +                                               NULL,
> +                                               &stack_hash_mask,
> +                                               1UL << STACK_HASH_ORDER_MIN,
> +                                               1UL << STACK_HASH_ORDER_MAX);
>
>         if (!stack_table) {
>                 pr_err("Stack Depot hash table allocation failed, disabling\n");
> @@ -207,13 +215,30 @@ int stack_depot_init(void)
>
>         mutex_lock(&stack_depot_init_mutex);
>         if (!stack_depot_disable && !stack_table) {
> -               pr_info("Stack Depot allocating hash table with kvcalloc\n");
> -               stack_table = kvcalloc(STACK_HASH_SIZE, sizeof(struct stack_record *), GFP_KERNEL);
> +               unsigned long entries;
> +
> +               entries = nr_free_buffer_pages();
> +               entries = roundup_pow_of_two(entries);
> +
> +               if (STACK_HASH_SCALE > PAGE_SHIFT)
> +                       entries >>= (STACK_HASH_SCALE - PAGE_SHIFT);
> +               else
> +                       entries <<= (PAGE_SHIFT - STACK_HASH_SCALE);
> +
> +               if (entries < 1UL << STACK_HASH_ORDER_MIN)
> +                       entries = 1UL << STACK_HASH_ORDER_MIN;
> +               if (entries > 1UL << STACK_HASH_ORDER_MAX)
> +                       entries = 1UL << STACK_HASH_ORDER_MAX;
> +
> +               pr_info("Stack Depot allocating hash table of %lu entries with kvcalloc\n",
> +                               entries);
> +               stack_table = kvcalloc(entries, sizeof(struct stack_record *), GFP_KERNEL);
>                 if (!stack_table) {
>                         pr_err("Stack Depot hash table allocation failed, disabling\n");
>                         stack_depot_disable = true;
>                         ret = -ENOMEM;
>                 }
> +               stack_hash_mask = entries - 1;
>         }
>         mutex_unlock(&stack_depot_init_mutex);
>         return ret;
> @@ -386,7 +411,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>                 goto fast_exit;
>
>         hash = hash_stack(entries, nr_entries);
> -       bucket = &stack_table[hash & STACK_HASH_MASK];
> +       bucket = &stack_table[hash & stack_hash_mask];
>
>         /*
>          * Fast path: look the stack trace up without locking.
> --
> 2.36.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY4GZfXOru2z5tFPzFdaSUd%2BGFc6KVL%3Dbsa0%2B1m197cQQ%40mail.gmail.com.

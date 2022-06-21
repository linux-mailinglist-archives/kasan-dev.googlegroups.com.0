Return-Path: <kasan-dev+bncBCMIZB7QWENRBOXKYWKQMGQEZDPFPOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D012552C29
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jun 2022 09:37:31 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id b14-20020a056402278e00b004359006fd49sf2052324ede.8
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jun 2022 00:37:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655797050; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dj4ItG9m48yArM/R5vg09Co7mrVi/ujPjG2UfPoSTKM8jdUaZ9fvLIBsHio9Qak6+D
         V30fWs2/P2AI/0eRuWXffEDMUvI8ko/B4IwrvQaIsVe642m7HznyUttjSFSen/4ilJpX
         3n9GhJPrsqt2Ra6pMj46UqyBjRj7L0YgiyULmVrRvyVAeJyrt8Jg7eotWdPcrR0Pk2DM
         nG+zCQV8+yhR+bhwlx1SQFuiEgMjCiQnpPVQqnJPvmfY6TSh/zXUYxFCY70STArNqtgd
         z7NCnz62o7sVDyqmasEMuT50dxkb6e7T3SIMTbi2aTkM5uGrimF/Md6KG9XDgy+jPIv/
         61Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=T/dzhRlW8uHlbS2x15N6d/4Gjdqd0kw7c0Mb3BBzM9k=;
        b=MZQon4Gn3ieP3DCG+lUT47SoqlDnhMaguJ8bEB7SQihXsZBxlQu3hUH4IgwNOeh+Dd
         jExukhT7Roj/4kjepKWpbCbsPAPJkw++ogHX/+XhfOKPmA7urLJxgd16vUaQHAmf2IOx
         8hqys/k0iHe85n2neO8ULrhcr2jONBW0Y0BQwsZtpePS0QW4al7x539w9ZAtJuspTv++
         El4ZyhmRiVteJnkL0MLzCOhKmeGp+H8BClHtDonY0hU1u8tnhKqIhsT85jkHfR9bich3
         xv/0Xs3elsohAbERh8EvJ3O7cDGwKAlLoIiZoA0XcL6TuvwJo1elSGaln+yR8WiJ31dW
         WrYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DsougCXd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T/dzhRlW8uHlbS2x15N6d/4Gjdqd0kw7c0Mb3BBzM9k=;
        b=nI0xa8bgfqtYb28BZWDudcN1sdNuWmaKlr6j1nRrB6/Fg01yID/tkLLXBjUAWwT1Mo
         vpnvlN50yUEOmf4W9HbTnHeF95Uew0ik5E0EklMlzKV3poftoIWn+ip38Z3IV/JMGKfR
         w/XPAshv0QUc1jcR/yqMze8f5+vk9MOhDS91+vFOJ5/LQBdnh2VcbY8txk55Flr9e6a9
         jotaUhzevC4JGb8Mhii8AgGlW7na41xTlI8O43c0vf0YzE80aXYS7WoFBWAYZ740XQUA
         HxmsKVEOEDjxhXCWAD/wpov2Wm22dfjT32ow4d75Bom7n7j+1xCpcYuNNKHm/IuKRmHE
         7XsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T/dzhRlW8uHlbS2x15N6d/4Gjdqd0kw7c0Mb3BBzM9k=;
        b=ucX7l43CYfYMWLSyC/RqTIFFLQ1Vd3DuinTww81SNJ3UkxP921zUp8Ml9rRiXoUKfK
         9jxksTOw2LEnN6CghQRy9Fsi4ldzd5iJwf8y7gKO+g0MKy3y6IVXLWGD0bbb3fT7geh7
         qiCqp9XZP7+ddRxxaWtjNsGOvOB7DPNGy4w5I2YqFtB5VDtDAINRkemwLYN74d9K8vUg
         WxmkqhR88WJtWMan6yh5vqsD+rL0DQcc0YK3uuKAYo+18+3PS1/f9D8tlNsVosOeOmLx
         gVdiZbMSbdRqL49eiSz3RzBsAIFlBj8LPqCpU0lIL8XDhpCo2oGQTMbCpgrAyPtBKVcG
         pr5Q==
X-Gm-Message-State: AJIora/Mst1Lyn87stmONQozaDACAzvI+tChurh48Ko6g8Ad0Sqy+Y6B
	N8CcsDQJNwN2LsTl3c+Fr6Q=
X-Google-Smtp-Source: AGRyM1vZI5fJaxzvjM1kcKruANACL+WXNIWzTguCZZNFd+Lm6ryvBDQ74pdjiKeWkPoZ2dsL/GUvAw==
X-Received: by 2002:a05:6402:3807:b0:435:20fb:318d with SMTP id es7-20020a056402380700b0043520fb318dmr34241952edb.272.1655797050507;
        Tue, 21 Jun 2022 00:37:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5ac1:b0:6ff:ab8:e8f with SMTP id x1-20020a1709065ac100b006ff0ab80e8fls5000620ejs.6.gmail;
 Tue, 21 Jun 2022 00:37:29 -0700 (PDT)
X-Received: by 2002:a17:907:6d91:b0:711:ec13:b7d8 with SMTP id sb17-20020a1709076d9100b00711ec13b7d8mr24559483ejc.565.1655797049390;
        Tue, 21 Jun 2022 00:37:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655797049; cv=none;
        d=google.com; s=arc-20160816;
        b=z+VvCoI3KHoU4sEXahyKvOXBr1RYah0Hix79YYENYDA4WaK87LdGs64kdm7x5ODXl4
         Hyy84XzLVUqM94Ey07d5anE2qvaB8MM7cJBa5YbRNAtHe9IoePsrpNSgDUKEfkSlIMci
         TSgDSd7NYacM33SvIfMjLz+1qYu43549dFX06lGZdT9iPdY+Na4IFE0uTKvUx41vpvPB
         ZuStfqF7E9VF+TZTr6DcGUJh71vInvdhWH8Ok4n79319bhI40WlxFsRSI9rUsA12fhbw
         xuSZef89u1gB+o7eW2DS6ce/hg66t6rDYk+pKXovVIMp/L1J5uyEgVOOH+o1SuplBMVN
         IONA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CyheJD4bAlrZUyrOZt+A8Zzf01u3nd0p7PNq0BkSQPg=;
        b=gDTzlElxBbMN5cSPGhfDzmMr4b7cYfciABBEDyISyxK91jHyzbxrESSYjEiRNLKbdi
         7oZh5TymW+9m8I1/Anbt64C1pUkUv6ntj/EUyNe/KIArBj4zAITXWoSvDiv6LLD63Zrh
         mqOur2RfpMSQ8wnsng7BvMT4LG601ceikykbnUjQTNbRLOzW19MLtxpGFed9PQcA35ed
         3WAQ/86arTOsljuG6CaqQXvEszZYLDSEb127LKMWuN5/RKPn29oRpT/4wA6YAUhueVqh
         W8lq2UJtQgl/HMbZpJZpA5OJ9B9p5ULVXZ0+1yPfbdFOu4oaIJuErXxRHwWxz+SQDzhB
         XDKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DsougCXd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22e.google.com (mail-lj1-x22e.google.com. [2a00:1450:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id z16-20020a056402275000b00435732e1fdesi283269edd.5.2022.06.21.00.37.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jun 2022 00:37:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22e as permitted sender) client-ip=2a00:1450:4864:20::22e;
Received: by mail-lj1-x22e.google.com with SMTP id n15so2784142ljg.8
        for <kasan-dev@googlegroups.com>; Tue, 21 Jun 2022 00:37:29 -0700 (PDT)
X-Received: by 2002:a05:651c:1988:b0:255:b2ef:6a5b with SMTP id
 bx8-20020a05651c198800b00255b2ef6a5bmr13840428ljb.465.1655797048804; Tue, 21
 Jun 2022 00:37:28 -0700 (PDT)
MIME-Version: 1.0
References: <20220527113706.24870-1-vbabka@suse.cz> <20220620150249.16814-1-vbabka@suse.cz>
In-Reply-To: <20220620150249.16814-1-vbabka@suse.cz>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Jun 2022 09:37:17 +0200
Message-ID: <CACT4Y+btgY8-GYZbQOoghgfCEHMTd_S=BmNnMQxMTgCU5JztPQ@mail.gmail.com>
Subject: Re: [PATCH] lib/stackdepot: replace CONFIG_STACK_HASH_ORDER with
 automatic sizing
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Linus Torvalds <torvalds@linux-foundation.org>, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, patches@lists.linux.dev, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DsougCXd;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22e
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

On Mon, 20 Jun 2022 at 17:03, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> As Linus explained [1], setting the stackdepot hash table size as a
> config option is suboptimal, especially as stackdepot becomes a
> dependency of less "expert" subsystems than initially (e.g. DRM,
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
>
> Because KASAN is reported to need the maximum number of buckets even
> with smaller amounts of memory [2], set it as such when kasan_enabled().
>
> If needed, the automatic scaling could be complemented with a boot-time
> kernel parameter, but it feels pointless to add it without a specific
> use case.
>
> [1] https://lore.kernel.org/all/CAHk-=wjC5nS+fnf6EzRD9yQRJApAhxx7gRB87ZV+pAWo9oVrTg@mail.gmail.com/
> [2] https://lore.kernel.org/all/CACT4Y+Y4GZfXOru2z5tFPzFdaSUd+GFc6KVL=bsa0+1m197cQQ@mail.gmail.com/
>
> Reported-by: Linus Torvalds <torvalds@linux-foundation.org>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Acked-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  lib/Kconfig      |  9 --------
>  lib/stackdepot.c | 59 ++++++++++++++++++++++++++++++++++++++++--------
>  2 files changed, 49 insertions(+), 19 deletions(-)
>
> diff --git a/lib/Kconfig b/lib/Kconfig
> index eaaad4d85bf2..986ea474836c 100644
> --- a/lib/Kconfig
> +++ b/lib/Kconfig
> @@ -685,15 +685,6 @@ config STACKDEPOT_ALWAYS_INIT
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
> index 5ca0d086ef4a..e73fda23388d 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -32,6 +32,7 @@
>  #include <linux/string.h>
>  #include <linux/types.h>
>  #include <linux/memblock.h>
> +#include <linux/kasan-enabled.h>
>
>  #define DEPOT_STACK_BITS (sizeof(depot_stack_handle_t) * 8)
>
> @@ -145,10 +146,16 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
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
> +static unsigned int stack_hash_order;
> +static unsigned int stack_hash_mask;
> +
>  static bool stack_depot_disable;
>  static struct stack_record **stack_table;
>
> @@ -175,7 +182,7 @@ void __init stack_depot_want_early_init(void)
>
>  int __init stack_depot_early_init(void)
>  {
> -       size_t size;
> +       unsigned long entries = 0;
>
>         /* This is supposed to be called only once, from mm_init() */
>         if (WARN_ON(__stack_depot_early_init_passed))
> @@ -183,13 +190,23 @@ int __init stack_depot_early_init(void)
>
>         __stack_depot_early_init_passed = true;
>
> +       if (kasan_enabled() && !stack_hash_order)
> +               stack_hash_order = STACK_HASH_ORDER_MAX;
> +
>         if (!__stack_depot_want_early_init || stack_depot_disable)
>                 return 0;
>
> -       size = (STACK_HASH_SIZE * sizeof(struct stack_record *));
> -       pr_info("Stack Depot early init allocating hash table with memblock_alloc, %zu bytes\n",
> -               size);
> -       stack_table = memblock_alloc(size, SMP_CACHE_BYTES);
> +       if (stack_hash_order)
> +               entries = 1UL <<  stack_hash_order;
> +       stack_table = alloc_large_system_hash("stackdepot",
> +                                               sizeof(struct stack_record *),
> +                                               entries,
> +                                               STACK_HASH_SCALE,
> +                                               HASH_EARLY | HASH_ZERO,
> +                                               NULL,
> +                                               &stack_hash_mask,
> +                                               1UL << STACK_HASH_ORDER_MIN,
> +                                               1UL << STACK_HASH_ORDER_MAX);
>
>         if (!stack_table) {
>                 pr_err("Stack Depot hash table allocation failed, disabling\n");
> @@ -207,13 +224,35 @@ int stack_depot_init(void)
>
>         mutex_lock(&stack_depot_init_mutex);
>         if (!stack_depot_disable && !stack_table) {
> -               pr_info("Stack Depot allocating hash table with kvcalloc\n");
> -               stack_table = kvcalloc(STACK_HASH_SIZE, sizeof(struct stack_record *), GFP_KERNEL);
> +               unsigned long entries;
> +               int scale = STACK_HASH_SCALE;
> +
> +               if (stack_hash_order) {
> +                       entries = 1UL << stack_hash_order;
> +               } else {
> +                       entries = nr_free_buffer_pages();
> +                       entries = roundup_pow_of_two(entries);
> +
> +                       if (scale > PAGE_SHIFT)
> +                               entries >>= (scale - PAGE_SHIFT);
> +                       else
> +                               entries <<= (PAGE_SHIFT - scale);
> +               }
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
> @@ -386,7 +425,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbtgY8-GYZbQOoghgfCEHMTd_S%3DBmNnMQxMTgCU5JztPQ%40mail.gmail.com.

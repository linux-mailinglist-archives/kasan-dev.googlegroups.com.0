Return-Path: <kasan-dev+bncBC7OBJGL2MHBBINORGIQMGQE32EGIWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id EC9B64CDBF0
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Mar 2022 19:14:58 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id f18-20020a623812000000b004f6a259bbf4sf2507366pfa.7
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Mar 2022 10:14:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646417697; cv=pass;
        d=google.com; s=arc-20160816;
        b=exGnpIpCWUkfyoMUxnnSa1+lwbjadPfiuA/2UW4WU5KBXnJJfrGkDvR3yOGYJLaubF
         q+0bGJd6IaRe/W4iBkF72Y402ocTXYNp8NEg8Yv/kDdUR4syyYWprJ4XPKFseTRBGrTg
         A6VIzqeGeY1c9utzBzyo1/5hHz8lIN4b0WEIxw7mlKow2qv/gYBZq+OjBl04mmYgP/jW
         sA+46I8UtqBrLXsNi0YUmHCFrJbzlvduNG580rR2t/ib/26LBZMuFMousqaQvOd2hARI
         i0pp8hyCCSUTgVmimiOc/egJGe2U6ZTKCatXuYi7oUDWpqhs9sDq/YEcEx/13ejTuIlz
         simQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bz3DzJlXKBdOb0BnMUo4KPPVN5eLnhfwxBslkLqkPKA=;
        b=jyumZ5+0K6A2ZTiW+pyrAiEguHDo1vuujT3RtdF5GUsI5iXen/RdnxsakyUX4axmkD
         aZPN7ds18rV9AmLzoz/mdMdmMhnarQHCLxm4MNLxPFWfVq04G+OGbE12P3wTt/bnHk9g
         e7qG/Jnewtr0k9YXWwOJACur7j0WObgpU0266+JOx/wDwcbBkSEkX/dDo4KiEfdsEnIq
         XdXVKVX7wQZ+FGMXctVbUwS5MKuGXBqIQTvrbj5+QNMICh8GHfV0U7Mm77x9B9tG3o/X
         BCZRlfwntZBqfeGGyu6fjTpc8F9aeASNqbZHWY99rf9tqH871jIePp/COUjHewt5IvXA
         I3Qw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bbMZ5FUu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bz3DzJlXKBdOb0BnMUo4KPPVN5eLnhfwxBslkLqkPKA=;
        b=XrEFRMY3vZk4DnkHegiXBDVz8uUKsndJUvwPRC9Doj8ZGwY0UBncACJu5BZKHGSaxL
         8UDRgEaPQcykuMQR6/gTV1J8Gi4a7UfmSlEFhsW1YQg76rs8O/m82jTGAg5gllcyQVAr
         h8ABsOuZQuykc8YGSFgGXOfDeJybEGHC4640WnLvq3soIh592uf48SR9Ga21KGnvhJyY
         y0aMFBbgBzHwctSTFSzlol7Moc9SEMa1k1T2pq02LZ8SOY58qeMumECtKGe6XGczTfU7
         sGdSJd9tMT30t4jOcfWp7/WeymHlUjnTeV1nXRxlzMINuKCqpNZEcdfx94VtB0tiMHtn
         YZ4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bz3DzJlXKBdOb0BnMUo4KPPVN5eLnhfwxBslkLqkPKA=;
        b=YpyOioRXplHltSicVxdhA4bKUgUVz9G3Ne7uFZKd3U8H4g/woWhBAhHx0w8pXbaBxO
         23eFAUfNFkR3YoohJ42zV2RBl85X0wONijhkGPfLiUep+D/xHwXaRxCsUTpmavyd4Yl+
         827wdqWi580JVez1x2t7wr1a05t5LO0lIB2BoCictBzysGQVv5BbRDaQzdLTarKJqekz
         TMNLV0podgEN0eB/ezYRrQwXZ+p7XrRvjYhSsRlcw5tXcAb0TW7VHUwfzrN94825Penn
         nCqzWz5UaftJfoXTjdiHa5P6abFDMHLgG/NkNK9kDpG8ZOviuCP57+gyGq5XuFKnWzzN
         eB3Q==
X-Gm-Message-State: AOAM5311PiQFiKG+14LkjW01KntE1kq3lF9z1fL4tYVkFclzmRqx6dQ7
	5J87e4iuJUsIs/dzhRiyAOQ=
X-Google-Smtp-Source: ABdhPJzNC7Ii8HGalNUAERhMfHTPloUGb2VTyKDd7mGaU2Hs6l+cR3DXISeYnl5cpipTaicobqotVQ==
X-Received: by 2002:a17:903:22c5:b0:151:a609:22f1 with SMTP id y5-20020a17090322c500b00151a60922f1mr10642673plg.126.1646417697295;
        Fri, 04 Mar 2022 10:14:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ecce:b0:14f:d9c5:79c0 with SMTP id
 a14-20020a170902ecce00b0014fd9c579c0ls5057662plh.5.gmail; Fri, 04 Mar 2022
 10:14:56 -0800 (PST)
X-Received: by 2002:a17:902:7890:b0:14d:502e:fa64 with SMTP id q16-20020a170902789000b0014d502efa64mr42131285pll.150.1646417696607;
        Fri, 04 Mar 2022 10:14:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646417696; cv=none;
        d=google.com; s=arc-20160816;
        b=h87S6j3BHvVibV5RpquY+Cx1hB563wxxlgg60jcWuqd6yoa++yESegvCEi7orqL5F4
         v5MWfQZX/4OTGxRHlQY7Kg0O8s7e/6SyuQWyKNu4PC99ayjlB2GgvMbAZ8IyVx87SWk2
         0qXfM1Rdc4rpSqe8Ss4uwIdQNgfCdh1bnaKgqk5mq5sQX9OUy2Cj+Hq1XUSDb5mSaTTF
         GXvY0isrqgJYipR1+5f2ZKIeP6EkPjOguorg5NrCenBNGT1Av4ZNj5AHR+k5acZo+f04
         bNbLA/UXI1XNcUgnL4BjsCqDGlO23Jy5duWUxcoKaqP9r/LMTfQQdpZeE0GIYHxyKqON
         bNtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IgmWOr5X+Gju6wLd27yrRRMMaWYlUQXk8HNkXVZFAmo=;
        b=XBoK4UbOMmhoFdj8qw83JbB6bR/aEHUGyEmMVI9lh3R6w+FdvNpwWD5kNdfqXd0a7m
         5fX7rPBQxKTinyOiMjj6EKZcOBglEaszvL96WLKm5Q8NFe8/Px/YXNhdUTuEkHpQAZ4x
         dfD4ser8G4PCxfPxL202eHUvBI95sSupANESFnCDct9ZLcB3Wwu2ei8ydzayo5ARwSZF
         cUsGC70v6H7BsYnroBwvjCBS7BwO+86bWQWvG0XzpXP41KnB4BIn+dAjsz5I9DBzMJzH
         ifDrfqnjBLk/xav67HETjHWhkWrqAPeh7Zzk4QdDwYac0/SAWnexbK2djIX3cXgKMjBc
         fKmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bbMZ5FUu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id kb14-20020a17090ae7ce00b001bee3c3502bsi276066pjb.3.2022.03.04.10.14.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Mar 2022 10:14:56 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id x200so18467399ybe.6
        for <kasan-dev@googlegroups.com>; Fri, 04 Mar 2022 10:14:56 -0800 (PST)
X-Received: by 2002:a25:af92:0:b0:628:b791:281b with SMTP id
 g18-20020a25af92000000b00628b791281bmr11191902ybh.87.1646417695968; Fri, 04
 Mar 2022 10:14:55 -0800 (PST)
MIME-Version: 1.0
References: <20220303031505.28495-1-dtcccc@linux.alibaba.com> <20220303031505.28495-3-dtcccc@linux.alibaba.com>
In-Reply-To: <20220303031505.28495-3-dtcccc@linux.alibaba.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Mar 2022 19:14:19 +0100
Message-ID: <CANpmjNNg2EN-Fnn_=Na8zE4CwTdoLOWw0N9ir5m4JLZf82_zwA@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] kfence: Alloc kfence_pool after system startup
To: Tianchen Ding <dtcccc@linux.alibaba.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=bbMZ5FUu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as
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

On Thu, 3 Mar 2022 at 04:15, Tianchen Ding <dtcccc@linux.alibaba.com> wrote:
>
> KFENCE aims at production environments, but it does not allow enabling
> after system startup because kfence_pool only alloc pages from memblock.
> Consider the following production scene:
> At first, for performance considerations, production machines do not
> enable KFENCE.
> However, after running for a while, the kernel is suspected to have
> memory errors. (e.g., a sibling machine crashed.)
> So other production machines need to enable KFENCE, but it's hard for
> them to reboot.

I think having this flexibility isn't bad, but your usecase just
doesn't make sense (to us at least, based on our experience).

So I would simply remove the above as it will give folks the wrong
impression. The below paragraph can be improved a little, but should
be enough.

> Allow enabling KFENCE by alloc pages after system startup, even if
> KFENCE is not enabled during booting.

The above doesn't parse very well -- my suggestion:
  "Allow enabling KFENCE after system startup by allocating its pool
via the page allocator. This provides the flexibility to enable KFENCE
even if it wasn't enabled at boot time."

> Signed-off-by: Tianchen Ding <dtcccc@linux.alibaba.com>
> ---
> This patch is similar to what the KFENCE(early version) do on ARM64.
> Instead of alloc_pages(), we'd prefer alloc_contig_pages() to get exact
> number of pages.
> I'm not sure about the impact of breaking __ro_after_init. I've tested
> with hackbench, and it seems no performance regression.
> Or any problem about security?

Performance would be the main consideration. However, I think
__read_mostly should be as good as __ro_after_init in terms of
performance.

> ---
>  mm/kfence/core.c | 96 ++++++++++++++++++++++++++++++++++++++----------
>  1 file changed, 76 insertions(+), 20 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 19eb123c0bba..ae69b2a113a4 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -93,7 +93,7 @@ static unsigned long kfence_skip_covered_thresh __read_mostly = 75;
>  module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644);
>
>  /* The pool of pages used for guard pages and objects. */
> -char *__kfence_pool __ro_after_init;
> +char *__kfence_pool __read_mostly;
>  EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
>
>  /*
> @@ -534,17 +534,18 @@ static void rcu_guarded_free(struct rcu_head *h)
>         kfence_guarded_free((void *)meta->addr, meta, false);
>  }
>
> -static bool __init kfence_init_pool(void)
> +/*
> + * The main part of init kfence pool.

"Initialization of the KFENCE pool after its allocation."

> + * Return 0 if succeed. Otherwise return the address where error occurs.

"Return 0 on success; otherwise returns the address up to which
partial initialization succeeded."

> + */
> +static unsigned long __kfence_init_pool(void)

Keep this function simply named 'kfence_init_pool()' - it's a static
function, and we can be more descriptive with the other function
names.

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
> @@ -562,7 +563,7 @@ static bool __init kfence_init_pool(void)
>
>                 /* Verify we do not have a compound head page. */
>                 if (WARN_ON(compound_head(&pages[i]) != &pages[i]))
> -                       goto err;
> +                       return addr;
>
>                 __SetPageSlab(&pages[i]);
>         }
> @@ -575,7 +576,7 @@ static bool __init kfence_init_pool(void)
>          */
>         for (i = 0; i < 2; i++) {
>                 if (unlikely(!kfence_protect(addr)))
> -                       goto err;
> +                       return addr;
>
>                 addr += PAGE_SIZE;
>         }
> @@ -592,7 +593,7 @@ static bool __init kfence_init_pool(void)
>
>                 /* Protect the right redzone. */
>                 if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
> -                       goto err;
> +                       return addr;
>
>                 addr += 2 * PAGE_SIZE;
>         }
> @@ -605,9 +606,21 @@ static bool __init kfence_init_pool(void)
>          */
>         kmemleak_free(__kfence_pool);
>
> -       return true;
> +       return 0;
> +}
> +
> +static bool __init kfence_init_pool(void)

Just call this kfence_init_pool_early().

> +{
> +       unsigned long addr;
> +
> +       if (!__kfence_pool)
> +               return false;
> +
> +       addr = __kfence_init_pool();
> +
> +       if (!addr)
> +               return true;
>
> -err:
>         /*
>          * Only release unprotected pages, and do not try to go back and change
>          * page attributes due to risk of failing to do so as well. If changing
> @@ -620,6 +633,22 @@ static bool __init kfence_init_pool(void)
>         return false;
>  }
>
> +static bool kfence_init_pool_late(void)
> +{
> +       unsigned long addr, free_pages;
> +
> +       addr = __kfence_init_pool();
> +
> +       if (!addr)
> +               return true;
> +
> +       /* Same as above. */
> +       free_pages = (KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool)) / PAGE_SIZE;
> +       free_contig_range(page_to_pfn(virt_to_page(addr)), free_pages);
> +       __kfence_pool = NULL;
> +       return false;
> +}
> +
>  /* === DebugFS Interface ==================================================== */
>
>  static int stats_show(struct seq_file *seq, void *v)
> @@ -768,31 +797,58 @@ void __init kfence_alloc_pool(void)
>                 pr_err("failed to allocate pool\n");
>  }
>
> +static inline void __kfence_init(void)

Don't make this 'inline', I see no reason for it. If the compiler
thinks it's really worth inlining, it'll do it anyway.

Also, just call it 'kfence_init_enable()' (sprinkling '__' everywhere
really doesn't improve readability if we can avoid it).

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
>         if (!kfence_init_pool()) {
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
> +       __kfence_init();
> +}
> +
> +static int kfence_init_late(void)
> +{
> +       struct page *pages;
> +       const unsigned long nr_pages = KFENCE_POOL_SIZE / PAGE_SIZE;

Order 'nr_pages' above 'pages' (reverse xmas-tree).


> +       pages = alloc_contig_pages(nr_pages, GFP_KERNEL, first_online_node, NULL);
> +
> +       if (!pages)
> +               return -ENOMEM;
> +
> +       __kfence_pool = page_to_virt(pages);
> +
> +       if (!kfence_init_pool_late()) {
> +               pr_err("%s failed\n", __func__);
> +               return -EBUSY;
> +       }
> +
> +       __kfence_init();
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
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220303031505.28495-3-dtcccc%40linux.alibaba.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNg2EN-Fnn_%3DNa8zE4CwTdoLOWw0N9ir5m4JLZf82_zwA%40mail.gmail.com.

Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNEQ3KSQMGQEKOR6VNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D48B757BFE
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jul 2023 14:40:22 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4fb76659cacsf4932232e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jul 2023 05:40:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689684021; cv=pass;
        d=google.com; s=arc-20160816;
        b=sxEc5+E/CSXZzzlso7OYra9/GwRrew3DLtc7MTmK0EYg49cQVp3hSUFQ337Kjae6nb
         KEGPcpgyiey7jzNkqkcgBBc6fZWxx+bHOuhC81eHIBWCUKa/xguLTyega1mIQNkh6Mvt
         ZJveF7d9sFPmZ3EjJScC0BfP7Euk3my5LpqxyTNB9NnqO+oBgasHjIZjhMn0WJLlVXIm
         ZGhQRM0vttq7T5+V3vIi4fPlMCHqqmZPp311RAI+n1bsfuIzxotV/3ncGY38yLDJ9kZO
         a94dnf6gH8JqZw6OKkWYpBqlZGn3vU9KDWYnXYZNNTvgmKlWTPdRz76FpYThQjurb6s5
         I7uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wZBoYIiNZ8r92gOy0uDRchmUpNdvNgPKiXCrmzecXL4=;
        fh=0xt18nsvWvc1tyZg2y0cJBpvWmzW8VhrrKfFcogvGIg=;
        b=rgCPXfZ8iwiCfWVc8XNaL2C9Z+GDX7fWeRH0SDj1nRgx8hSon3Z32mOvZ14b26VHSt
         6Ct0AwUjSNDVqcpt3N6v+mycAwBeRx1RIogTVN/Ii/nYafKDVZKr7RbqKVJFYVj/1nYO
         HReJPGhb4vwbgzjw0gshHx1yGGWvHETV+Vws1xvxniWgJvTP3TnwvxWVAh385zJigWOY
         31NjdR0bUs4LjhUs8vKsk/pMX+hvss130fno7QUBhikhqg0/dKGtpyzWt7YnAkFvmnbn
         aHYA3aRUShWcMFMFwfsg1rF+wgr0EHJrEP99qrsLKkSKiG8A1x6TZIqgBWYgDBp1z0jz
         OXqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=iPdReQBN;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689684021; x=1692276021;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wZBoYIiNZ8r92gOy0uDRchmUpNdvNgPKiXCrmzecXL4=;
        b=WiBlwYUrqiNxEkzVTF+oLPd3mppmG7Rd1cmupqH+nMx2P5JlwHFzuGaD4wfvXTBT0U
         ZuOUoea+Z2e8eM145FP3bcexGZX7ptQTVMBrElFjLkCmbHqrRbs7O80kHVXGTR+Ra6cH
         SvJh76TPTucKk5oYBpVu+LhJSARwWfnMPPfi4w0dIeAJ29jk83/blnk9suaEiiBXYXa5
         3jnnOLpNlODbcQrj2/0bPQ41bpv6WDoq6osqDLgna3aOdCrOsAmMECdMYiVp8U2Qy5wz
         FYDELQlHAostn7mz89c3fHdRPj880wHYT6+leRhRC/TzG6BlW1k/SHhBM3w+IZAR4oIx
         B4cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689684021; x=1692276021;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wZBoYIiNZ8r92gOy0uDRchmUpNdvNgPKiXCrmzecXL4=;
        b=Pj0Os4tetVdzwIgSkoZ41XOZDrRIpiK8ZLB7B0XxxieCqUJShJXQDS32hlHAWBoPyC
         k4w3hkU3XRuW+0axNHv3LPfsC/x3UdDNGOkjapTIDdcQvLTVYtbyG6xYNH1Umlb3rZkQ
         DsxInwnq1bWYAaPSNSlmIq9tJQFPWu4cT7wYLFl/hIhyfHvuXPL1U07SWoY/xJ2jGeNe
         6alfJwSy3plTWbQQqVTsIb4xGAy1JrD6Og33RMAcdydTqg7N08GqRMUWEP4MI3NjuJKf
         9JrEzXLeBZvxzsqSR7WzlxjR9KO2NTXBlQFd0vpnPp3IjJy9qux1AfgOWQ6My4OVO3Um
         1k8w==
X-Gm-Message-State: ABy/qLajkVzzzyxwFezyxe0Wa4C7D0KSVOiwxhAwXnV6FQn5S8gv31TW
	L3f2LsCLwybOnEWmazxxFPI=
X-Google-Smtp-Source: APBJJlHGC++33DaZDlqn+vCStWxyHPUoeU1uFElIktWiHgt1e7VWubOyHsAbrm85+WZR6y5cafa9CQ==
X-Received: by 2002:a19:7109:0:b0:4f4:dbcc:54da with SMTP id m9-20020a197109000000b004f4dbcc54damr9945406lfc.27.1689684020656;
        Tue, 18 Jul 2023 05:40:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:12ce:b0:51d:fa16:ac73 with SMTP id
 k14-20020a05640212ce00b0051dfa16ac73ls3395198edx.2.-pod-prod-07-eu; Tue, 18
 Jul 2023 05:40:18 -0700 (PDT)
X-Received: by 2002:a17:906:64d6:b0:97e:56d5:b885 with SMTP id p22-20020a17090664d600b0097e56d5b885mr13133173ejn.60.1689684018628;
        Tue, 18 Jul 2023 05:40:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689684018; cv=none;
        d=google.com; s=arc-20160816;
        b=c0HWS06rRC7vLC2biYWRnM3AwfAQ/vbuFHp0ynErzLzscCN0PmpB0KUqnVZxiVIcUd
         HwTmQADrMg3kEfAaZgCnZl63vXIvjg7RFDL2/Ti6dHB+BSvHrXsAmUj2JZoZfcovAD+2
         ZntrwnUYALlyyMpZqgT9u5LD37cakQkh4zNhv90FekYLOM6fjygzj7CPmE3MEavGeGab
         OOy1BiWxVpiOJD9RvEC4nAjA/94oob4P1mQpXGdx8Dw7R/f/o7UmMW5Ys8koXVxCKaUt
         hysCUuXmYm/OgoNLHJd+fNOqoWJYPHhJsSGN3ciHz1FtILIKH1Lhw55zT6SN4LoOv9RJ
         tv0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ikv3c5UKmNpyTHlS5fwGJGbwI2S8WZSWuI+ewsXdmvo=;
        fh=fxKpU4Ftja67DTEgdYtohJIwJZ1nSnaM/vURgBEXnfg=;
        b=S3fXSMFIiAtjt34jRD8yhF0hdT3sa1HfROGOq0rv33wbYSi883D1M4a4OJnBbxLID/
         agAmurAZ7C+P02KbzyFOAaNPLFCSDvJECsFyPXGJrwsYR0Gz5AYklQCYp8sa4eYN2Qf0
         ARif8d5TrSdIEmEGAPR/OIlXhtZw7tMq17aV7TzPPLzS3no9zpfhTSmdgKmlFHYUZvKw
         SuZThvJFM1YNPIALrYlbsYkYJMRz8s7PGx3XPAVYK/ooiLbGCIBS9PY6uxDHbQBnmy0i
         YDIu2ChcWNqNrWh1d6Cc0Z9FGrzkz7BF+mWQinIWX5n7rKf5voFTgwUpaJexJDZrd7Mw
         FbAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=iPdReQBN;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id vi18-20020a170907d41200b009885c0ef8d2si113241ejc.1.2023.07.18.05.40.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jul 2023 05:40:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-3fbc5d5746cso57160145e9.2
        for <kasan-dev@googlegroups.com>; Tue, 18 Jul 2023 05:40:18 -0700 (PDT)
X-Received: by 2002:a05:600c:204b:b0:3fa:9561:3016 with SMTP id
 p11-20020a05600c204b00b003fa95613016mr1714538wmg.30.1689684018077; Tue, 18
 Jul 2023 05:40:18 -0700 (PDT)
MIME-Version: 1.0
References: <20230718073019.52513-1-zhangpeng.00@bytedance.com>
In-Reply-To: <20230718073019.52513-1-zhangpeng.00@bytedance.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Jul 2023 14:39:41 +0200
Message-ID: <CANpmjNNUr17dKfBYumm54aqB9J-FaeWOW-az9cpkwMS6sd6+3A@mail.gmail.com>
Subject: Re: [PATCH v3] mm: kfence: allocate kfence_metadata at runtime
To: Peng Zhang <zhangpeng.00@bytedance.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	muchun.song@linux.dev, Kefeng Wang <wangkefeng.wang@huawei.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=iPdReQBN;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as
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

On Tue, 18 Jul 2023 at 09:30, Peng Zhang <zhangpeng.00@bytedance.com> wrote:
>
> kfence_metadata is currently a static array. For the purpose of allocating
> scalable __kfence_pool, we first change it to runtime allocation of
> metadata. Since the size of an object of kfence_metadata is 1160 bytes, we
> can save at least 72 pages (with default 256 objects) without enabling
> kfence.
>
> Signed-off-by: Peng Zhang <zhangpeng.00@bytedance.com>

This looks good (minor nit below).

Reviewed-by: Marco Elver <elver@google.com>

Thanks!

> ---
> Changes since v2:
>  - Fix missing renaming of kfence_alloc_pool.
>  - Add __read_mostly for kfence_metadata and kfence_metadata_init.
>  - Use smp_store_release() and smp_load_acquire() to access kfence_metadata.
>  - Some tweaks to comments and git log.
>
> v1: https://lore.kernel.org/lkml/20230710032714.26200-1-zhangpeng.00@bytedance.com/
> v2: https://lore.kernel.org/lkml/20230712081616.45177-1-zhangpeng.00@bytedance.com/
>
>  include/linux/kfence.h |  11 ++--
>  mm/kfence/core.c       | 124 ++++++++++++++++++++++++++++-------------
>  mm/kfence/kfence.h     |   5 +-
>  mm/mm_init.c           |   2 +-
>  4 files changed, 97 insertions(+), 45 deletions(-)
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 726857a4b680..401af4757514 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -59,15 +59,16 @@ static __always_inline bool is_kfence_address(const void *addr)
>  }
>
>  /**
> - * kfence_alloc_pool() - allocate the KFENCE pool via memblock
> + * kfence_alloc_pool_and_metadata() - allocate the KFENCE pool and KFENCE
> + * metadata via memblock
>   */
> -void __init kfence_alloc_pool(void);
> +void __init kfence_alloc_pool_and_metadata(void);
>
>  /**
>   * kfence_init() - perform KFENCE initialization at boot time
>   *
> - * Requires that kfence_alloc_pool() was called before. This sets up the
> - * allocation gate timer, and requires that workqueues are available.
> + * Requires that kfence_alloc_pool_and_metadata() was called before. This sets
> + * up the allocation gate timer, and requires that workqueues are available.
>   */
>  void __init kfence_init(void);
>
> @@ -223,7 +224,7 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
>  #else /* CONFIG_KFENCE */
>
>  static inline bool is_kfence_address(const void *addr) { return false; }
> -static inline void kfence_alloc_pool(void) { }
> +static inline void kfence_alloc_pool_and_metadata(void) { }
>  static inline void kfence_init(void) { }
>  static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
>  static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index dad3c0eb70a0..6b526435886c 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -116,7 +116,15 @@ EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
>   * backing pages (in __kfence_pool).
>   */
>  static_assert(CONFIG_KFENCE_NUM_OBJECTS > 0);
> -struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
> +struct kfence_metadata *kfence_metadata __read_mostly;
> +
> +/*
> + * If kfence_metadata is not NULL, it may be accessed by kfence_shutdown_cache().
> + * So introduce kfence_metadata_init to initialize metadata, and then make
> + * kfence_metadata visible after initialization is successful. This prevents
> + * potential UAF or access to uninitialized metadata.
> + */
> +static struct kfence_metadata *kfence_metadata_init __read_mostly;
>
>  /* Freelist with available objects. */
>  static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
> @@ -591,7 +599,7 @@ static unsigned long kfence_init_pool(void)
>
>                 __folio_set_slab(slab_folio(slab));
>  #ifdef CONFIG_MEMCG
> -               slab->memcg_data = (unsigned long)&kfence_metadata[i / 2 - 1].objcg |
> +               slab->memcg_data = (unsigned long)&kfence_metadata_init[i / 2 - 1].objcg |
>                                    MEMCG_DATA_OBJCGS;
>  #endif
>         }
> @@ -610,7 +618,7 @@ static unsigned long kfence_init_pool(void)
>         }
>
>         for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
> -               struct kfence_metadata *meta = &kfence_metadata[i];
> +               struct kfence_metadata *meta = &kfence_metadata_init[i];
>
>                 /* Initialize metadata. */
>                 INIT_LIST_HEAD(&meta->list);
> @@ -626,6 +634,12 @@ static unsigned long kfence_init_pool(void)
>                 addr += 2 * PAGE_SIZE;
>         }
>
> +       /*
> +        * Make kfence_metadata visible only when initialization is successful.
> +        * Otherwise, if the initialization fails and kfence_metadata is freed,
> +        * it may cause UAF in kfence_shutdown_cache().
> +        */
> +       smp_store_release(&kfence_metadata, kfence_metadata_init);
>         return 0;
>
>  reset_slab:
> @@ -672,26 +686,10 @@ static bool __init kfence_init_pool_early(void)
>          */
>         memblock_free_late(__pa(addr), KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool));
>         __kfence_pool = NULL;
> -       return false;
> -}
> -
> -static bool kfence_init_pool_late(void)
> -{
> -       unsigned long addr, free_size;
>
> -       addr = kfence_init_pool();
> -
> -       if (!addr)
> -               return true;
> +       memblock_free_late(__pa(kfence_metadata_init), KFENCE_METADATA_SIZE);
> +       kfence_metadata_init = NULL;
>
> -       /* Same as above. */
> -       free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
> -#ifdef CONFIG_CONTIG_ALLOC
> -       free_contig_range(page_to_pfn(virt_to_page((void *)addr)), free_size / PAGE_SIZE);
> -#else
> -       free_pages_exact((void *)addr, free_size);
> -#endif
> -       __kfence_pool = NULL;
>         return false;
>  }
>
> @@ -841,19 +839,30 @@ static void toggle_allocation_gate(struct work_struct *work)
>
>  /* === Public interface ===================================================== */
>
> -void __init kfence_alloc_pool(void)
> +void __init kfence_alloc_pool_and_metadata(void)
>  {
>         if (!kfence_sample_interval)
>                 return;
>
> -       /* if the pool has already been initialized by arch, skip the below. */
> -       if (__kfence_pool)
> -               return;
> -
> -       __kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> -
> +       /*
> +        * If the pool has already been initialized by arch, there is no need to
> +        * re-allocate the memory pool.
> +        */
>         if (!__kfence_pool)
> +               __kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> +
> +       if (!__kfence_pool) {
>                 pr_err("failed to allocate pool\n");
> +               return;
> +       }
> +
> +       /* The memory allocated by memblock has been zeroed out. */
> +       kfence_metadata_init = memblock_alloc(KFENCE_METADATA_SIZE, PAGE_SIZE);
> +       if (!kfence_metadata_init) {
> +               pr_err("failed to allocate metadata\n");
> +               memblock_free(__kfence_pool, KFENCE_POOL_SIZE);
> +               __kfence_pool = NULL;
> +       }
>  }
>
>  static void kfence_init_enable(void)
> @@ -895,33 +904,68 @@ void __init kfence_init(void)
>
>  static int kfence_init_late(void)
>  {
> -       const unsigned long nr_pages = KFENCE_POOL_SIZE / PAGE_SIZE;
> +       const unsigned long nr_pages_pool = KFENCE_POOL_SIZE / PAGE_SIZE;
> +       const unsigned long nr_pages_meta = KFENCE_METADATA_SIZE / PAGE_SIZE;
> +       unsigned long addr = (unsigned long)__kfence_pool;
> +       unsigned long free_size = KFENCE_POOL_SIZE;
> +       int err = -ENOMEM;
> +
>  #ifdef CONFIG_CONTIG_ALLOC
>         struct page *pages;
> -

Unnecessary blank line removal (it looks worse now).


> -       pages = alloc_contig_pages(nr_pages, GFP_KERNEL, first_online_node, NULL);
> +       pages = alloc_contig_pages(nr_pages_pool, GFP_KERNEL, first_online_node,
> +                                  NULL);
>         if (!pages)
>                 return -ENOMEM;
> +
>         __kfence_pool = page_to_virt(pages);
> +       pages = alloc_contig_pages(nr_pages_meta, GFP_KERNEL, first_online_node,
> +                                  NULL);
> +       if (pages)
> +               kfence_metadata_init = page_to_virt(pages);
>  #else
> -       if (nr_pages > MAX_ORDER_NR_PAGES) {
> +       if (nr_pages_pool > MAX_ORDER_NR_PAGES ||
> +           nr_pages_meta > MAX_ORDER_NR_PAGES) {
>                 pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocator\n");
>                 return -EINVAL;
>         }
> +
>         __kfence_pool = alloc_pages_exact(KFENCE_POOL_SIZE, GFP_KERNEL);
>         if (!__kfence_pool)
>                 return -ENOMEM;
> +
> +       kfence_metadata_init = alloc_pages_exact(KFENCE_METADATA_SIZE, GFP_KERNEL);
>  #endif
>
> -       if (!kfence_init_pool_late()) {
> -               pr_err("%s failed\n", __func__);
> -               return -EBUSY;
> +       if (!kfence_metadata_init)
> +               goto free_pool;
> +
> +       memzero_explicit(kfence_metadata_init, KFENCE_METADATA_SIZE);
> +       addr = kfence_init_pool();
> +       if (!addr) {
> +               kfence_init_enable();
> +               kfence_debugfs_init();
> +               return 0;
>         }
>
> -       kfence_init_enable();
> -       kfence_debugfs_init();
> +       pr_err("%s failed\n", __func__);
> +       free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
> +       err = -EBUSY;
>
> -       return 0;
> +#ifdef CONFIG_CONTIG_ALLOC
> +       free_contig_range(page_to_pfn(virt_to_page((void *)kfence_metadata_init)),
> +                         nr_pages_meta);
> +free_pool:
> +       free_contig_range(page_to_pfn(virt_to_page((void *)addr)),
> +                         free_size / PAGE_SIZE);
> +#else
> +       free_pages_exact((void *)kfence_metadata_init, KFENCE_METADATA_SIZE);
> +free_pool:
> +       free_pages_exact((void *)addr, free_size);
> +#endif
> +
> +       kfence_metadata_init = NULL;
> +       __kfence_pool = NULL;
> +       return err;
>  }
>
>  static int kfence_enable_late(void)
> @@ -941,6 +985,10 @@ void kfence_shutdown_cache(struct kmem_cache *s)
>         struct kfence_metadata *meta;
>         int i;
>
> +       /* Pairs with release in kfence_init_pool(). */
> +       if (!smp_load_acquire(&kfence_metadata))
> +               return;
> +
>         for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
>                 bool in_use;
>
> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> index 392fb273e7bd..f46fbb03062b 100644
> --- a/mm/kfence/kfence.h
> +++ b/mm/kfence/kfence.h
> @@ -102,7 +102,10 @@ struct kfence_metadata {
>  #endif
>  };
>
> -extern struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
> +#define KFENCE_METADATA_SIZE PAGE_ALIGN(sizeof(struct kfence_metadata) * \
> +                                       CONFIG_KFENCE_NUM_OBJECTS)
> +
> +extern struct kfence_metadata *kfence_metadata;
>
>  static inline struct kfence_metadata *addr_to_metadata(unsigned long addr)
>  {
> diff --git a/mm/mm_init.c b/mm/mm_init.c
> index 7f7f9c677854..3d0a63c75829 100644
> --- a/mm/mm_init.c
> +++ b/mm/mm_init.c
> @@ -2721,7 +2721,7 @@ void __init mm_core_init(void)
>          */
>         page_ext_init_flatmem();
>         mem_debugging_and_hardening_init();
> -       kfence_alloc_pool();
> +       kfence_alloc_pool_and_metadata();
>         report_meminit();
>         kmsan_init_shadow();
>         stack_depot_early_init();
> --
> 2.20.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNUr17dKfBYumm54aqB9J-FaeWOW-az9cpkwMS6sd6%2B3A%40mail.gmail.com.

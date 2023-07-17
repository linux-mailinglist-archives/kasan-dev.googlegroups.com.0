Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ5G2SSQMGQEIE7T6XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id B5847756015
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jul 2023 12:08:40 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2b934496cffsf9167131fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jul 2023 03:08:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689588520; cv=pass;
        d=google.com; s=arc-20160816;
        b=zmkv0eelnFHDmw03mgkFfTWQbQFtcEm+ogRP+jGeM1tWaPr7qfkCXFH+RuFGy4iYcB
         7OrqCxOyW1N3T/16hKfe1hy2sn/WfZD+zjGc7fd7ZSpuoUk9nsIEvH8njxlFCIOzdUD0
         jD9SDR5AZaqPxHirChSw5wPaa5ZkD9xoxWEx/KSVCkNsrqzjv7YGScBjrw9nh+zKUpAy
         I78irfNqZMbUb6BZlOr7jbBdjYavEBnZNC/RWwvx74O/dmybLf1qXUzCJl1riH4ip/RW
         k+lg55GfQxSLLMwxBjlyNU63BkZHx7pAyrXO+A+0MdJHjfjzp5InMzPoWzEmU752RU9p
         z78w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6zootlnvrI14EPLktgKq81DcM4mr7Im9Zzh0ZAvlzcY=;
        fh=Go+MQeyffb//bw2EX2PpOIK6QU461oGF5Mtc7nsdIDI=;
        b=vuBi2l65fZWdohHjvkwid2OcAxaFMaCvHuUAw0poQfihHgggtHGgKUhk6sDMh+1xTQ
         J0tstKyVD4+VmS9L5RIBpJVGQwB7SKPAz93TfzmTdx9qLnokq3RA78tRGhTg3OnQ1uz3
         3zIAq8p1kek2HuU1UY1zvPCa8isMA8BA0IDgjJ+jBwG9jvM4eQeH1sfWWYEU6eyXhXdN
         9AEAj23NGcBWc9CS4IzSgGfOBSCeOSWMZ2Nx0RRtYG6tTQFUdj+aDk1PQcDYwq/2h8Hx
         CjfaTVU0cnWa4wt3eywdeuFvgIu7t7GWSUCrCr9JrGkJ+aFB+j2+yeCLOl5z3rhpxkTT
         lqWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=3b6EnwrT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689588520; x=1692180520;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6zootlnvrI14EPLktgKq81DcM4mr7Im9Zzh0ZAvlzcY=;
        b=Ybqhc3gRgQzqugVIXRhfrsHyji+zOu9yPxxy22difTZnSpJ4LCvZJX4mvaEjqf2mSh
         LfIwkfsBOwJIaOTkz66w00cCYl9MkqKa84QbqkzqnRK0807i0kySnfnpZ+aDvp9TlSJM
         43nYHUkZUzWYnWrAcnSj/PMeYG9Ag8nMGOhJSBhoSb6v15ljw04cA5Kn//hA53EKbHEv
         w/cg2PMAQv64MWGxZQBoRO/+Jq4DJKeseBBj17JYXkeFy2vhCuDlxHve9NFJ6WfKHT+p
         MOBKAGCJStRNyaHrU4JHZsqLQSa6fReYDsytN66oS7UOCj3zXBN+ZJOLroI6MxCkdG6q
         0yyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689588520; x=1692180520;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6zootlnvrI14EPLktgKq81DcM4mr7Im9Zzh0ZAvlzcY=;
        b=Nbk6ttO8WdDMMzJ8jqDTeVeKkB9ljE1yWEf2mIW9iXX8MEt517nWw2k6MMam743M/b
         IcNuToeDEBMU2mUfyA4aH2n3DLFMkBHAo038TDClIJ97MXfpmnqJXZlxUy7KLWQNfzZL
         eV2MG7SXeUh2HvFv0IwmUGF2xYUknKIcFZzAey3xKucZkjyKN5uGTeUy7yH0Aw1EofB5
         2p4zACAi995g41usf7jwCqMcP56B63GkXfF1E5gjewt7tNaqDrMXQO0TKUZqVTyUJ7kU
         VbyP7nBDbXqySkagggOgUCh1UdeukRQ83sCooowKFmScgStQ8g6zJqwvfyken1tcbj6g
         xHuw==
X-Gm-Message-State: ABy/qLaEKwCTjrMn3LPMUguh55q4S5XmYOuIAvT2n8xjVS0Th38pOn2X
	JwrrMgChDhFxkiGN+WCFZIo=
X-Google-Smtp-Source: APBJJlGp43kzLWbMWifLMp/VMf3EylTrB99f6bEVlAldTZGi67VgI2neVC2B1xoKqQO3xeeDWgWOdw==
X-Received: by 2002:a2e:b550:0:b0:2b7:361:8c26 with SMTP id a16-20020a2eb550000000b002b703618c26mr2759883ljn.25.1689588519408;
        Mon, 17 Jul 2023 03:08:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1990:b0:2b9:3dcf:e398 with SMTP id
 bx16-20020a05651c199000b002b93dcfe398ls242702ljb.2.-pod-prod-00-eu; Mon, 17
 Jul 2023 03:08:37 -0700 (PDT)
X-Received: by 2002:a2e:9955:0:b0:2b4:74e2:afa8 with SMTP id r21-20020a2e9955000000b002b474e2afa8mr3397053ljj.9.1689588517357;
        Mon, 17 Jul 2023 03:08:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689588517; cv=none;
        d=google.com; s=arc-20160816;
        b=fAtygilw2EUBESoJWAn24JTDuOPqi+3NVp2BAJWSK5xv6bwFWlzkaHL6cbJZioLGlc
         U713YKyVMORSpLU73bSno0lYmslRd1rhqkz0CV/UBNRGCc3Wg8w9C5ai+mGelOI8kmtM
         St6qUb41ZcjeIYoyuPR6ySUjykLEQEBA5H1Uh7Y7xiVr+DxZssxCCHTleIWamH9f/uT1
         +4JF+UevHkszvxTCUUlhZdItL8tAKpRfwySaQWSKubwkvUouvW0evvt9bZs2x6eNWcOR
         YPC5GE5WB1m57D4Q3jmLlmgflVr+eYH6lblVBrzndrcvZFSXjq0zzGtqntzuXLMBY/EG
         lMEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kqBfpIPYXg9/0aovDlWqLigZJLcQOQ5ybNw4hlBZbB0=;
        fh=rCc/pEfIbCZwPFDN8O/N6VPx+uiN0K7wk6D8AwRyuU0=;
        b=Tmk8UGC0Pibdt7Vr26y2ZGY35VOhYdUrsOMtO/kskdxJnvxDWfi1R9BtZmFwptTbYc
         p3nzv7Z6ffFOVgVBzTXrGwy3HAdNwNgWE3xtdF68nbmtaMwSt8q/qLuEV6iKlexox38W
         z7BgVWK+sQBrzk16lb1Tey4r4DTvffHSYCJhNFX5XgXaZ+wBQx6Fwc0xQx0a49gmy32R
         Q+cs0IXmRUs1iRQi5kzzio0i7XChXXX4wneFWz0VTQJYMhY/zHyaW8IJ7z79HdGK8dSy
         RITXixQlF5Sq8JEQeULVUaO/clMwMAsLiTFu2cKiI6j3FDOfg3ltpluDx6A95/IpfyHx
         3PRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=3b6EnwrT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id x12-20020a2ea98c000000b002b657edbea8si1027581ljq.4.2023.07.17.03.08.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Jul 2023 03:08:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-3fbab0d0b88so32770525e9.0
        for <kasan-dev@googlegroups.com>; Mon, 17 Jul 2023 03:08:37 -0700 (PDT)
X-Received: by 2002:a05:600c:1d18:b0:3fa:94ea:583c with SMTP id
 l24-20020a05600c1d1800b003fa94ea583cmr8101722wms.8.1689588516493; Mon, 17 Jul
 2023 03:08:36 -0700 (PDT)
MIME-Version: 1.0
References: <20230712081616.45177-1-zhangpeng.00@bytedance.com>
In-Reply-To: <20230712081616.45177-1-zhangpeng.00@bytedance.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 Jul 2023 12:07:59 +0200
Message-ID: <CANpmjNOhNQuBZAgOKLv4+4UoFK1b_8PP0EzWzkuyyGE0bg+weg@mail.gmail.com>
Subject: Re: [PATCH v2] mm: kfence: allocate kfence_metadata at runtime
To: Peng Zhang <zhangpeng.00@bytedance.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	muchun.song@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=3b6EnwrT;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as
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

On Wed, 12 Jul 2023 at 10:16, 'Peng Zhang' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> kfence_metadata is currently a static array. For the purpose of
> allocating scalable __kfence_pool, we first change it to runtime
> allocation of metadata. Since the size of an object of kfence_metadata
> is 1160 bytes, we can save at least 72 pages (with default 256 objects)
> without enabling kfence.
>
> Below is the numbers obtained in qemu (with default 256 objects).
> before: Memory: 8134692K/8388080K available (3668K bss)
> after: Memory: 8136740K/8388080K available (1620K bss)
> More than expected, it saves 2MB memory. It can be seen that the size
> of the .bss section has changed, possibly because it affects the linker.
>
> Signed-off-by: Peng Zhang <zhangpeng.00@bytedance.com>
> ---
> Changes since v1:
>  - Fix a stupid problem of not being able to initialize kfence. The problem is
>    that I slightly modified the patch before sending it out, but it has not been
>    tested. I'm extremely sorry.
>  - Drop kfence_alloc_metadata() and kfence_free_metadata() because they are no
>    longer reused.
>  - Allocate metadata from memblock during early initialization. Fixed the issue
>    of allocating metadata size that cannot exceed the limit of the buddy system
>    during early initialization.
>  - Fix potential UAF in kfence_shutdown_cache().
>
> v1: https://lore.kernel.org/lkml/20230710032714.26200-1-zhangpeng.00@bytedance.com/
>
>  include/linux/kfence.h |   5 +-
>  mm/kfence/core.c       | 124 ++++++++++++++++++++++++++++-------------
>  mm/kfence/kfence.h     |   5 +-
>  mm/mm_init.c           |   2 +-
>  4 files changed, 94 insertions(+), 42 deletions(-)
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 726857a4b680..68e71562bfa7 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -59,9 +59,10 @@ static __always_inline bool is_kfence_address(const void *addr)
>  }
>
>  /**
> - * kfence_alloc_pool() - allocate the KFENCE pool via memblock
> + * kfence_alloc_pool_and_metadata() - allocate the KFENCE pool and KFENCE
> + * metadata via memblock
>   */
> -void __init kfence_alloc_pool(void);
> +void __init kfence_alloc_pool_and_metadata(void);

You've renamed this, but not the stub later in the file. So this
currently breaks with !CONFIG_KFENCE.

Also, there's a reference in comments to kfence_alloc_pool(), please
update as well.

>  /**
>   * kfence_init() - perform KFENCE initialization at boot time
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index dad3c0eb70a0..ed0424950cf1 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -116,7 +116,16 @@ EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
>   * backing pages (in __kfence_pool).
>   */
>  static_assert(CONFIG_KFENCE_NUM_OBJECTS > 0);
> -struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
> +struct kfence_metadata *kfence_metadata;

Add __read_mostly, like for __kfence_pool.

> +/*
> + * When kfence_metadata is not NULL, it may be that kfence is being initialized
> + * at this time, and it may be used by kfence_shutdown_cache() during
> + * initialization. If the initialization fails, kfence_metadata will be released,
> + * causing UAF. So it is necessary to add kfence_metadata_init for initialization,
> + * and kfence_metadata will be visible only when initialization is successful.
> + */
> +static struct kfence_metadata *kfence_metadata_init;

Also add __read_mostly.

>  /* Freelist with available objects. */
>  static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
> @@ -591,7 +600,7 @@ static unsigned long kfence_init_pool(void)
>
>                 __folio_set_slab(slab_folio(slab));
>  #ifdef CONFIG_MEMCG
> -               slab->memcg_data = (unsigned long)&kfence_metadata[i / 2 - 1].objcg |
> +               slab->memcg_data = (unsigned long)&kfence_metadata_init[i / 2 - 1].objcg |
>                                    MEMCG_DATA_OBJCGS;
>  #endif
>         }
> @@ -610,7 +619,7 @@ static unsigned long kfence_init_pool(void)
>         }
>
>         for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
> -               struct kfence_metadata *meta = &kfence_metadata[i];
> +               struct kfence_metadata *meta = &kfence_metadata_init[i];
>
>                 /* Initialize metadata. */
>                 INIT_LIST_HEAD(&meta->list);
> @@ -626,6 +635,12 @@ static unsigned long kfence_init_pool(void)
>                 addr += 2 * PAGE_SIZE;
>         }
>
> +       /*
> +        * Make kfence_metadata visible only when initialization is successful.
> +        * Otherwise, if the initialization fails and kfence_metadata is
> +        * freed, it may cause UAF in kfence_shutdown_cache().
> +        */
> +       kfence_metadata = kfence_metadata_init;

May cause _concurrent_ UAF, right? I assume so, at least with late init.

So in that case, this should be smp_store_release().

>         return 0;
>
>  reset_slab:
> @@ -672,26 +687,10 @@ static bool __init kfence_init_pool_early(void)
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
> @@ -841,19 +840,30 @@ static void toggle_allocation_gate(struct work_struct *work)
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
> @@ -895,33 +905,68 @@ void __init kfence_init(void)
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
> @@ -941,6 +986,9 @@ void kfence_shutdown_cache(struct kmem_cache *s)
>         struct kfence_metadata *meta;
>         int i;
>
> +       if (!kfence_metadata)
> +               return;

And this should be smp_load_acquire(&kfence_metadata), so that all the
metadata initialization is actually seen by concurrent
kfence_shutdown_cache / kfence_init_pool.

And add a comment something like:

  /* Pairs with release in kfence_init_pool(). */

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
> index a1963c3322af..86b26d013f4b 100644
> --- a/mm/mm_init.c
> +++ b/mm/mm_init.c
> @@ -2778,7 +2778,7 @@ void __init mm_core_init(void)
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
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230712081616.45177-1-zhangpeng.00%40bytedance.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOhNQuBZAgOKLv4%2B4UoFK1b_8PP0EzWzkuyyGE0bg%2Bweg%40mail.gmail.com.

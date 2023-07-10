Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3FWV6SQMGQELBTTDIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E9FB74D338
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jul 2023 12:20:30 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-3f5df65f9f4sf26476685e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Jul 2023 03:20:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688984429; cv=pass;
        d=google.com; s=arc-20160816;
        b=wgy5HxJNJofSiidXia7cAmU4DhiQOyOWFy26f0W+71uasJJvO+N/NUInWxRNVYfO8I
         0IB5z7B7GAihsY++FHhU0zxU7A2/dJ3+syEE0xjsSB4aML3WA7SSAQaY8frfipR3wy0+
         +moLGO9EfSX2dZ6Yj0kVIZux2z2Ykz39ecfDdPz3Oedh4oFu7jA+DM8K0TT6waWimcpJ
         L0amui9PSm74gQWYySAzGtxlHXLU8Eqlpe9b6nDtW7MSES1SuFE8w40VePScqro+ZGTm
         buwN/qQJq81iXdbBtIRbhSizYfjyglPfgxDun3Mh/VC4YrGBN9dWjFA1DodI+uuGy7aS
         +TLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=g/Ofc6CId/BYm/4TFab1JfTL+vTSmkAgwkz7dA5dzpM=;
        fh=Go+MQeyffb//bw2EX2PpOIK6QU461oGF5Mtc7nsdIDI=;
        b=QnIqKaUOwqJXzy24MsCL09s/sf7YV27U8tE5l+W4tjtRb2MtZRqFEf9N4xuMYAoc7M
         ERw7+JfD4/d+ZhbvKXFj+ru7Mj3yKPmTcFG1C7d7mr+CD8zrArcaNmHnOCOu+NYJ+Bxj
         k5QYXxT8g8xtc0W2+vvpkP2TqAHpZGxSXlKIqYjJCzWd8SDDQzr3YG+UysYyeum9Kyhy
         OzNTejxEH6GjHc1P3wJQ30eir/Z4S4HKU1x4nJdq2tJlpvSBQ0fDVO7J2Z/hkENIWsp+
         71B5iskhEueX+WENnkIwySKrDwKCI6OFz6q8RPfs8on/1KPo+90w7FknLWsWkUwopevu
         hbMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=hrK+K2RB;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688984429; x=1691576429;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g/Ofc6CId/BYm/4TFab1JfTL+vTSmkAgwkz7dA5dzpM=;
        b=HojiwsoTd/+cX0F8lCx6DwEM3E/ZaAUkN7Pt8Jzi8Oq/l0XA885LMRCcoij6L6NwsL
         w/Uz2gYxOQkF5m82GxykhJRbm+PQnev8EYjtOtVNL9mSbF2ZmyyiN75RrKU+tMvCRtJb
         CBdz7weAYxSv4vr8eomQRNu2OSgwEBhw7jRs7KircQ+Wa/Z7Nj0gm3Ct1BmM6FtHH2k/
         HAQELXIbbrmH2PIG2SaC5GxNj7b7qSd/uYJNd/W49vPzyOFdUe04IqxWIj7T+KKxwup0
         dbIu03amIjHcBCCIazG4vrO9535J2fYBugTZRwjjUTb+y0x0Bh1Y3FS/EhTfmIgyjOal
         4mew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688984429; x=1691576429;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=g/Ofc6CId/BYm/4TFab1JfTL+vTSmkAgwkz7dA5dzpM=;
        b=Rlf5GUN06HPjEXLyaMJdJ/dNvjljDCutJc8qSchtAqp7Bc4Hw1JcJbjWlGXKlB8kdn
         CnLvOwkoH0jXq14BrEEYGIOA0toxMcta6p8lBqGW7qjOnl3dsNpN3iKdivADawfYx750
         V23WjlEqF/MKEbmIwztFE797L+vZzGcg3QoVX1Pr1DxTCxeBBmk/y47bfv/zRNmywLRq
         Nb4qm090FCqRbX0cMWIRg+eTSW5v8KWh2CjzRbUd7s79uwxAZgvsg4YTgP9E2QK7Hhwz
         Upd2wwHBrmDBivZn1ZlajthFLG0tfCsgt8aCfCtc0SsGd8qa0FhiCuZpolrDDNeFxi+m
         C1gA==
X-Gm-Message-State: ABy/qLbq4jaDZwThpx5dZyXlxhDw+fkDOcHOqAXCYt69DKkick9hHLvG
	r0jMX4eH2+PLYqKWjSu0CsY=
X-Google-Smtp-Source: APBJJlG6ym9FxXsLHRcRLUolGt4cAJft1RhrTW3SlLyAD8zgo2dqvD91gScn9KP4Dzbc2JfQ9GRXKw==
X-Received: by 2002:a1c:770c:0:b0:3fc:e7d:ca57 with SMTP id t12-20020a1c770c000000b003fc0e7dca57mr3117679wmi.2.1688984428941;
        Mon, 10 Jul 2023 03:20:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e1b:b0:3fa:98f0:ce14 with SMTP id
 ay27-20020a05600c1e1b00b003fa98f0ce14ls1763334wmb.2.-pod-prod-04-eu; Mon, 10
 Jul 2023 03:20:27 -0700 (PDT)
X-Received: by 2002:a7b:cb93:0:b0:3fb:fca1:1965 with SMTP id m19-20020a7bcb93000000b003fbfca11965mr8438474wmi.18.1688984427376;
        Mon, 10 Jul 2023 03:20:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688984427; cv=none;
        d=google.com; s=arc-20160816;
        b=MSWta8JhNxgQUGhG364YVM0Wq5uYthHiIuvndz5aa6hoYLUEMWUwQBdgtdrqF1Ka4L
         9C7HL3+VVRd/rhIQDG29VTSAGuGt1Xjn0NCGhV6exztd3y+TG1EH5euP4mY9oZGbC0AY
         h2DJB7E97Ac02rvwMInCJdhLUelKSL2pgW6RfFl6sCPZ2uB2tIdIEnUvRNCTD0WNEdi2
         bCOs9QW7axvvukEmgYBC4GfcLwlIO+x+lDBcJ6CVGsH2iT9hxa3fysQo4VIkuuebF29F
         xOQbxRa4ghqA3w7KPmrlqHaEcnmPTnpnJg/UGSWAlt+BEEYEC+O1nKeN192YZ6GMi10z
         dK8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KO1SxVtMO5vB92CZUE0zhLXTJjAA8Kw6VkcMKrG36Wg=;
        fh=rCc/pEfIbCZwPFDN8O/N6VPx+uiN0K7wk6D8AwRyuU0=;
        b=Ma0di2k+BnGyYi+WJ34oWy3Pz5DxiPw66dwgNrLV5Wb2SY5FuDLl2IpOkElGBS9Wj7
         3G/slDEtUQ4iXCK8Yw4twqq85pHmA4iuaIpWVPuLdfGKVMTsGkTckkfe6p2ny2r4OJLJ
         S9Oh85ZcwXimA46MkmlZebXkdDCnml+YvLb6vICp2LRqXMxZZ921d8XVKlu8xFzrQH4I
         zOMUQQo5jQm7GNewlhJb6KufZYIb5mnzD+6j4oV7yrtGRRnEZzVZaZiE+paBp44NRis+
         Xn8YLSQi46OOMEqAxE1EZM+iX8Vo0UoERC1y8nXZuWmNic7llLCQjTlh7VOdOPyrNADT
         xKJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=hrK+K2RB;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id ay29-20020a05600c1e1d00b003fb415dd573si506642wmb.2.2023.07.10.03.20.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Jul 2023 03:20:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-3fbc77e76abso45120505e9.1
        for <kasan-dev@googlegroups.com>; Mon, 10 Jul 2023 03:20:27 -0700 (PDT)
X-Received: by 2002:a1c:7c15:0:b0:3fb:9ef2:157 with SMTP id
 x21-20020a1c7c15000000b003fb9ef20157mr10147681wmc.28.1688984426752; Mon, 10
 Jul 2023 03:20:26 -0700 (PDT)
MIME-Version: 1.0
References: <20230710032714.26200-1-zhangpeng.00@bytedance.com>
In-Reply-To: <20230710032714.26200-1-zhangpeng.00@bytedance.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Jul 2023 12:19:49 +0200
Message-ID: <CANpmjNOHz+dRbJsAyg29nksPMcd2P6109iPxTem_-b2qfUvXtw@mail.gmail.com>
Subject: Re: [PATCH] mm: kfence: allocate kfence_metadata at runtime
To: Peng Zhang <zhangpeng.00@bytedance.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	muchun.song@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=hrK+K2RB;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
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

On Mon, 10 Jul 2023 at 05:27, 'Peng Zhang' via kasan-dev
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
> More than expected, it saves 2MB memory.
>
> Signed-off-by: Peng Zhang <zhangpeng.00@bytedance.com>

Seems like a reasonable optimization, but see comments below.

Also with this patch applied on top of v6.5-rc1, KFENCE just doesn't
init at all anymore (early init). Please fix.

> ---
>  mm/kfence/core.c   | 102 ++++++++++++++++++++++++++++++++-------------
>  mm/kfence/kfence.h |   5 ++-
>  2 files changed, 78 insertions(+), 29 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index dad3c0eb70a0..b9fec1c46e3d 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -116,7 +116,7 @@ EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
>   * backing pages (in __kfence_pool).
>   */
>  static_assert(CONFIG_KFENCE_NUM_OBJECTS > 0);
> -struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
> +struct kfence_metadata *kfence_metadata;
>
>  /* Freelist with available objects. */
>  static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
> @@ -643,13 +643,56 @@ static unsigned long kfence_init_pool(void)
>         return addr;
>  }
>
> +static int kfence_alloc_metadata(void)
> +{
> +       unsigned long nr_pages = KFENCE_METADATA_SIZE / PAGE_SIZE;
> +
> +#ifdef CONFIG_CONTIG_ALLOC
> +       struct page *pages;
> +
> +       pages = alloc_contig_pages(nr_pages, GFP_KERNEL, first_online_node,
> +                                  NULL);
> +       if (pages)
> +               kfence_metadata = page_to_virt(pages);
> +#else
> +       if (nr_pages > MAX_ORDER_NR_PAGES) {
> +               pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocator\n");

Does this mean that KFENCE won't work at all if we can't allocate the
metadata? I.e. it won't work either in early nor late init modes?

I know we already have this limitation for _late init_ of the KFENCE pool.

So I have one major question: when doing _early init_, what is the
maximum size of the KFENCE pool (#objects) with this change?

> +               return -EINVAL;
> +       }
> +       kfence_metadata = alloc_pages_exact(KFENCE_METADATA_SIZE,
> +                                           GFP_KERNEL);
> +#endif
> +
> +       if (!kfence_metadata)
> +               return -ENOMEM;
> +
> +       memset(kfence_metadata, 0, KFENCE_METADATA_SIZE);

memzero_explicit, or pass __GFP_ZERO to alloc_pages?

> +       return 0;
> +}
> +
> +static void kfence_free_metadata(void)
> +{
> +       if (WARN_ON(!kfence_metadata))
> +               return;
> +#ifdef CONFIG_CONTIG_ALLOC
> +       free_contig_range(page_to_pfn(virt_to_page((void *)kfence_metadata)),
> +                         KFENCE_METADATA_SIZE / PAGE_SIZE);
> +#else
> +       free_pages_exact((void *)kfence_metadata, KFENCE_METADATA_SIZE);
> +#endif
> +       kfence_metadata = NULL;
> +}
> +
>  static bool __init kfence_init_pool_early(void)
>  {
> -       unsigned long addr;
> +       unsigned long addr = (unsigned long)__kfence_pool;
>
>         if (!__kfence_pool)
>                 return false;
>
> +       if (!kfence_alloc_metadata())
> +               goto free_pool;
> +
>         addr = kfence_init_pool();
>
>         if (!addr) {
> @@ -663,6 +706,7 @@ static bool __init kfence_init_pool_early(void)
>                 return true;
>         }
>
> +       kfence_free_metadata();
>         /*
>          * Only release unprotected pages, and do not try to go back and change
>          * page attributes due to risk of failing to do so as well. If changing
> @@ -670,31 +714,12 @@ static bool __init kfence_init_pool_early(void)
>          * fails for the first page, and therefore expect addr==__kfence_pool in
>          * most failure cases.
>          */
> +free_pool:
>         memblock_free_late(__pa(addr), KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool));
>         __kfence_pool = NULL;
>         return false;
>  }
>
> -static bool kfence_init_pool_late(void)
> -{
> -       unsigned long addr, free_size;
> -
> -       addr = kfence_init_pool();
> -
> -       if (!addr)
> -               return true;
> -
> -       /* Same as above. */
> -       free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
> -#ifdef CONFIG_CONTIG_ALLOC
> -       free_contig_range(page_to_pfn(virt_to_page((void *)addr)), free_size / PAGE_SIZE);
> -#else
> -       free_pages_exact((void *)addr, free_size);
> -#endif
> -       __kfence_pool = NULL;
> -       return false;
> -}
> -
>  /* === DebugFS Interface ==================================================== */
>
>  static int stats_show(struct seq_file *seq, void *v)
> @@ -896,6 +921,10 @@ void __init kfence_init(void)
>  static int kfence_init_late(void)
>  {
>         const unsigned long nr_pages = KFENCE_POOL_SIZE / PAGE_SIZE;
> +       unsigned long addr = (unsigned long)__kfence_pool;
> +       unsigned long free_size = KFENCE_POOL_SIZE;
> +       int ret;
> +
>  #ifdef CONFIG_CONTIG_ALLOC
>         struct page *pages;
>
> @@ -913,15 +942,29 @@ static int kfence_init_late(void)
>                 return -ENOMEM;
>  #endif
>
> -       if (!kfence_init_pool_late()) {
> -               pr_err("%s failed\n", __func__);
> -               return -EBUSY;
> +       ret = kfence_alloc_metadata();
> +       if (!ret)
> +               goto free_pool;
> +
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
> +       kfence_free_metadata();
> +       free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
> +       ret = -EBUSY;
>
> -       return 0;
> +free_pool:
> +#ifdef CONFIG_CONTIG_ALLOC
> +       free_contig_range(page_to_pfn(virt_to_page((void *)addr)), free_size / PAGE_SIZE);
> +#else
> +       free_pages_exact((void *)addr, free_size);
> +#endif

You moved this from kfence_init_pool_late - that did "__kfence_pool =
NULL" which is missing now.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOHz%2BdRbJsAyg29nksPMcd2P6109iPxTem_-b2qfUvXtw%40mail.gmail.com.

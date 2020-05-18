Return-Path: <kasan-dev+bncBCMIZB7QWENRBDGCRH3AKGQENLFJSZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 90DFC1D74FE
	for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 12:18:53 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id 65sf772367uae.3
        for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 03:18:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589797132; cv=pass;
        d=google.com; s=arc-20160816;
        b=dXmJI48f3QjoPhjMlg2kubLxN9BEN9Q2d2quLia+J00b4MQXx2qC4+T2lb2vsJNE3a
         tN0l4ApcYEacze/vL8Cfkj0F0W/gWKFTsn6WsskSW5s1PgtUM/XeUivj6Rr8N3qhURmq
         5YlHccoRAwJIcJSCbp0vrJ6iGyebXLEmSIzQXpPO/le4Gv8eSKTOov0n9YPvJuOjqmDq
         H/x5qiNF19SrgKuQCTGalJ89TB5XFEutJKKXqgdH17re53FD5tENi+9l+zOUEH49ZwIq
         BIikHQk0h0KSrtTJx5fSDghFz4h4etkR7WDf2wt2XzNve5lk7Piuz6vQOz5xtZL7EbWa
         3AGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=f4xA0uUBE/esvXcFynIkkXcdnFjiXNh/wZhuz/f6skY=;
        b=C/jKCjrbzdcAi7CTanrjSwrME97DOw2L7+6ioYq8qbRAg3I9UpSELfnLYSfYc5tBnU
         drFLp5rcusBwrUHh2AUTCjhpYhkSQnYFVLQeb0iJl0M3ZK0x2bzgBGQqxPfTMJDwfJHv
         tdGh8l4SeeJySkd1MLJyMiiStO/AfVBLyOg+1L9R0mH5l6V2/KA+7uEZwUYmGLfOO2ZC
         L3Q9HzGuFZKxHIBrk5hmJyfnAVWEOyXOVWiZPHlFWuch+Xmd//+UHGcjZirqEx3Fizj/
         4tZjQJQlbPF5vrootDlW8EJNPVSNsE9m59UPt6BkvPXfEb2LSbg94UuB42wVC41P72Z4
         mhgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Kopo/21L";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f4xA0uUBE/esvXcFynIkkXcdnFjiXNh/wZhuz/f6skY=;
        b=SWd1+5g/147GWZqKrv7CEoISYOXaQvOkAKczTkmertwrB5274Qx8ZwvhoFv/oxj2o2
         nkFT8aonJLJzXN3j4v+SnYHR+N1YXDJSl4CCShrkxSfbepiTACZ6WJdye4q9anD5EBMu
         yFP2jLsIstphqdo57ZUujYMVziqRB2sCp8MDskHpNfVDcYclNp4jPW4sTUd6O5LdnDRe
         3dSX7MhFmkBA87FYv4KgHUi9Hfm0SKC9DXxOXnHP63+qQab83TwlZCdb/cpxwBgsES93
         VUthGbizcNhSi50Lfe/m70M4zmKb7ADEYC4oUzCjbRYse6EgqU300t2v0+PLlLtYFZ2v
         cUYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f4xA0uUBE/esvXcFynIkkXcdnFjiXNh/wZhuz/f6skY=;
        b=qf15kJuGaC6mIWvWSSf/L20sZenYctDiuky3hQOpxdln9tZTayKcjFfyQH8l02R/y7
         TRdR6VYhs7RWzS54sF5s2xc+ei4fGcR7rlGgf6TB4qgQZq51n4kjbvhKq1UZl3Ty2f9E
         vxWTHc/4mB5STPMLeydTr0Iixn6bAU0lui1+IwX1eeda3qjNMB1LcuRzRpMowzqt9Mxf
         P3N3rOsLf/TEc3+V+GuhISQZBukKQu4VR69PIQYEISWRmgtHEe5D/JjPAmEy492+BHc7
         WseK3CghCrABToOcnw3Iu6gpBG8kXTpgTzFGCxH/oMMjfU2qssMVhzam+PZJYPWWMoOi
         wJpw==
X-Gm-Message-State: AOAM533I9OoDzaY/SfpeMwx21juRcO9k57QB6v0i4nDlvJybOCzBveM2
	rYktTa5D1LJaed/0ZbPo3Mo=
X-Google-Smtp-Source: ABdhPJzY7UdjYlr9Qed6z51VMD5P8eThXrfsmW2YgQBL2pnV3e/Dthj3xWtQ61yrithbaMGj/31w9w==
X-Received: by 2002:a67:d43:: with SMTP id 64mr10398094vsn.142.1589797132499;
        Mon, 18 May 2020 03:18:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7902:: with SMTP id u2ls1006251vsc.9.gmail; Mon, 18 May
 2020 03:18:52 -0700 (PDT)
X-Received: by 2002:a67:f356:: with SMTP id p22mr6767398vsm.130.1589797132191;
        Mon, 18 May 2020 03:18:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589797132; cv=none;
        d=google.com; s=arc-20160816;
        b=zHQq7Olw2DbL3GkWDHXRjmXFCb4FrLxVLmg7a3hzrN+ajPoU2kVeTar662s/C5Pkod
         u/Fy887IKH40ROaLe6O6hp+BZhyLP0JpKLRWz/7vV/t2P98bSLKArWpiowAhYxb8QPu7
         LYag6TgDIgQkhYS3mUb+iRXqAHUsyvT/izgJzeRJPzXjpnfoYPW1k5BzPqObmOLqxqTQ
         fwP+w/dQ4ZVDJ7dYwcJSZoIYdlFr1YO3nPAiNaTUslTZnM7qBdzgMQjg+hp06TZU0zv/
         iJIWQatNB35SxBSw61GeEOhttv1la2T8w2MgL9QeZVVM9cDNQKLbAOyMdnJKXBkgQa8J
         uU3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SeQSSJ6tmsyyQwBxZIU0ZhjYI9wUM1h2JniQ2eBNH4E=;
        b=ua0ZMktbo0ijTpyBTc8qvZekMiTQWxWiCzbCtHdGomrlmrswyhpRDnSGD/6kEIc/Um
         HYIl7uWzUvOzAEX9CbEbVUQz9EGgy6z6K0mJzriLCMeXow5NWzf6huWPhhmDTpOCtp3y
         mBEAHts7Ae4ikU5z/2miQaCfPsINxBTRFAVrwglMXde81k/IH7assGWSAEYirOfj2zzc
         uWOD4q+6iTjFr57YZc4Cx92oe9ChB1gh4vk6gx6ryF1qC93fygMpXBkK3epb4hxdgdZh
         D9+J1fwxMz2DRV5kr5k4kPYlZeIEPIRcx2WUNAxC6C1Z/zG+1O+UKvBT2UnyJXZyXQa1
         6o1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Kopo/21L";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id y77si499973vky.0.2020.05.18.03.18.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 May 2020 03:18:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id z80so9543155qka.0
        for <kasan-dev@googlegroups.com>; Mon, 18 May 2020 03:18:52 -0700 (PDT)
X-Received: by 2002:a05:620a:990:: with SMTP id x16mr14681630qkx.256.1589797131499;
 Mon, 18 May 2020 03:18:51 -0700 (PDT)
MIME-Version: 1.0
References: <20200518062730.4665-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200518062730.4665-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 May 2020 12:18:39 +0200
Message-ID: <CACT4Y+YVF2cLdg6qaK+3NcU3kLz2Pys6NWxLAYfity5n5cjirA@mail.gmail.com>
Subject: Re: [PATCH v3 2/4] kasan: record and print the free track
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Kopo/21L";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Mon, May 18, 2020 at 8:27 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> Move free track from slub alloc meta-data to slub free meta-data in
> order to make struct kasan_free_meta size is 16 bytes. It is a good
> size because it is the minimal redzone size and a good number of
> alignment.
>
> For free track in generic KASAN, we do the modification in struct
> kasan_alloc_meta and kasan_free_meta:
> - remove free track from kasan_alloc_meta.
> - add free track into kasan_free_meta.
>
> [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> ---
>  mm/kasan/common.c  | 33 ++++++++++-----------------------
>  mm/kasan/generic.c | 18 ++++++++++++++++++
>  mm/kasan/kasan.h   |  7 +++++++
>  mm/kasan/report.c  | 20 --------------------
>  mm/kasan/tags.c    | 37 +++++++++++++++++++++++++++++++++++++
>  5 files changed, 72 insertions(+), 43 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 8bc618289bb1..6500bc2bb70c 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -51,7 +51,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags)
>         return stack_depot_save(entries, nr_entries, flags);
>  }
>
> -static inline void set_track(struct kasan_track *track, gfp_t flags)
> +void kasan_set_track(struct kasan_track *track, gfp_t flags)
>  {
>         track->pid = current->pid;
>         track->stack = kasan_save_stack(flags);
> @@ -249,9 +249,7 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>         *size += sizeof(struct kasan_alloc_meta);
>
>         /* Add free meta. */
> -       if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
> -           (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
> -            cache->object_size < sizeof(struct kasan_free_meta))) {
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {

Why do we need to increase object size unconditionally?
We only store info in free track when the object is free, so I would
assume we still can generally overlap free track and the object
itself. We store free track at the same time we use the quarantine
link, and the quarantine link was overlapped with the object just
fine.
With this change we indeed increase object size, which we do not want
in general.


>                 cache->kasan_info.free_meta_offset = *size;
>                 *size += sizeof(struct kasan_free_meta);
>         }
> @@ -299,24 +297,6 @@ struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
>         return (void *)object + cache->kasan_info.free_meta_offset;
>  }
>
> -
> -static void kasan_set_free_info(struct kmem_cache *cache,
> -               void *object, u8 tag)
> -{
> -       struct kasan_alloc_meta *alloc_meta;
> -       u8 idx = 0;
> -
> -       alloc_meta = get_alloc_info(cache, object);
> -
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> -       idx = alloc_meta->free_track_idx;
> -       alloc_meta->free_pointer_tag[idx] = tag;
> -       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> -#endif
> -
> -       set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> -}
> -
>  void kasan_poison_slab(struct page *page)
>  {
>         unsigned long i;
> @@ -396,6 +376,13 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
>         alloc_info = get_alloc_info(cache, object);
>         __memset(alloc_info, 0, sizeof(*alloc_info));
>
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +               struct kasan_free_meta *free_info;
> +
> +               free_info = get_free_info(cache, object);
> +               __memset(free_info, 0, sizeof(*free_info));

If we overlap free track with object, this will not be needed as well, right?

> +       }
> +
>         if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
>                 object = set_tag(object,
>                                 assign_tag(cache, object, true, false));
> @@ -492,7 +479,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>                 KASAN_KMALLOC_REDZONE);
>
>         if (cache->flags & SLAB_KASAN)
> -               set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> +               kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
>
>         return set_tag(object, tag);
>  }
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 78d8e0a75a8a..988bc095b738 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -345,3 +345,21 @@ void kasan_record_aux_stack(void *addr)
>                 alloc_info->rcu_stack[1] = alloc_info->rcu_stack[0];
>         alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
>  }
> +
> +void kasan_set_free_info(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       struct kasan_free_meta *free_meta;
> +
> +       free_meta = get_free_info(cache, object);
> +       kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
> +}
> +
> +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       struct kasan_free_meta *free_meta;
> +
> +       free_meta = get_free_info(cache, object);
> +       return &free_meta->free_track;
> +}
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 870c5dd07756..87ee3626b8b0 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -127,6 +127,9 @@ struct kasan_free_meta {
>          * Otherwise it might be used for the allocator freelist.
>          */
>         struct qlist_node quarantine_link;
> +#ifdef CONFIG_KASAN_GENERIC
> +       struct kasan_track free_track;
> +#endif
>  };
>
>  struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
> @@ -168,6 +171,10 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
>  struct page *kasan_addr_to_page(const void *addr);
>
>  depot_stack_handle_t kasan_save_stack(gfp_t flags);
> +void kasan_set_track(struct kasan_track *track, gfp_t flags);
> +void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag);
> +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> +                               void *object, u8 tag);
>
>  #if defined(CONFIG_KASAN_GENERIC) && \
>         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 5ee66cf7e27c..7e9f9f6d5e85 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -159,26 +159,6 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
>                 (void *)(object_addr + cache->object_size));
>  }
>
> -static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> -               void *object, u8 tag)
> -{
> -       struct kasan_alloc_meta *alloc_meta;
> -       int i = 0;
> -
> -       alloc_meta = get_alloc_info(cache, object);
> -
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> -       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> -               if (alloc_meta->free_pointer_tag[i] == tag)
> -                       break;
> -       }
> -       if (i == KASAN_NR_FREE_STACKS)
> -               i = alloc_meta->free_track_idx;
> -#endif
> -
> -       return &alloc_meta->free_track[i];
> -}
> -
>  #ifdef CONFIG_KASAN_GENERIC
>  static void print_stack(depot_stack_handle_t stack)
>  {
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 25b7734e7013..201dee5d6ae0 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -162,3 +162,40 @@ void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
>         kasan_poison_shadow((void *)addr, size, tag);
>  }
>  EXPORT_SYMBOL(__hwasan_tag_memory);
> +
> +void kasan_set_free_info(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +       u8 idx = 0;
> +
> +       alloc_meta = get_alloc_info(cache, object);
> +
> +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +       idx = alloc_meta->free_track_idx;
> +       alloc_meta->free_pointer_tag[idx] = tag;
> +       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> +#endif
> +
> +       kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> +}
> +
> +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +       int i = 0;
> +
> +       alloc_meta = get_alloc_info(cache, object);
> +
> +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> +               if (alloc_meta->free_pointer_tag[i] == tag)
> +                       break;
> +       }
> +       if (i == KASAN_NR_FREE_STACKS)
> +               i = alloc_meta->free_track_idx;
> +#endif
> +
> +       return &alloc_meta->free_track[i];
> +}
> --
> 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYVF2cLdg6qaK%2B3NcU3kLz2Pys6NWxLAYfity5n5cjirA%40mail.gmail.com.

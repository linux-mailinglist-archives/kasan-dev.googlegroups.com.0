Return-Path: <kasan-dev+bncBCMIZB7QWENRB4NQR73AKGQEZKUAHAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id CDFBD1D96D9
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 15:00:34 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id b14sf7570546oii.10
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 06:00:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589893233; cv=pass;
        d=google.com; s=arc-20160816;
        b=HQhcmk9/PnswzLsfgWSE5nAqOpp6oXD5sOl3T9y+LxLGlC4pztY+dLlP5oJb2V5WUI
         up2dXVE9pX/FZmOQ5/JRgq7jKUalPTtrRSgMbjdiK4V4ncLNTKUBXy8g3OnwpH6vHqAv
         iDBwLrMjxOrthmJbxay8jfM7hg5I1OBMrTmZCJfKcNkfJT1QgNs4YfAPNWb5NpufHuJT
         Hbj+CCxZQyL1MfRyUU2xiXPb8ZfOfciRnlUpiEv4Xr6grG7UURxatkwl5H7f6N3lGvUE
         rvY7+Kr/inzw/fZawDgJPDzK2Mmj9Qb6Vb2UF3uLmwwPDQZxQTbB/V6HyhfUQM0Yi8Dx
         vOeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8zc2tn3GzbE6cFPAkg8sxzPpUm0DNZYXW6jg7QaqVSA=;
        b=iE7TWJLNy2dFnmW7FETqGDE8Fle8yG2pwXr3zxGolX9bahTuYsB7YVEseML09UJzX1
         bSzjNdSppBFJG4z1B8VJL8opLZ45+jXOHJyMV1467lEcrF+17UpNN8HHhQdl4alqk9Rb
         m2SCNAHfrjUxDewaj8loV3nv6t282jDeTleOq9mjEy6lo+ZjNd6ZXP0w8qUzwQPFtl+5
         ARYyaj6XxBE6NjA6FHpDFhJWqNMTu+6H76VMlJe6Vx6SR+1Hh6imfrQ9AnIK5fsSlrvj
         Id2+wGLBoA4SgRfaDQ9UcYzj0KFgvje7ny7Wty+MIvQIxI8x6idP/ScA6PxxK75aXZRM
         524w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eYzcJCuP;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=8zc2tn3GzbE6cFPAkg8sxzPpUm0DNZYXW6jg7QaqVSA=;
        b=s1yspZh+NSHiuyFqw4nV7IsxFHk+BX2SfSaiJnjqQJOfuhOE5ZFIIiXlDEkB/1AqIx
         IA7p8DnFnBffVIJdA0X/iSexQs0Gwb0xXbN89YpMHeM/XdgiRY2llvjd3ZgX2R0MF/yG
         c7Pa3KYA00kaZbdnZaVdkBT6T2qnkwxOamMxzb0gO/cskMtzROuvXJz/U8PqIRTXgagO
         WNBgVPRZpwg7eyBP773GLbgOpoKMEMN0Y3p4BauipbnQMXBMkV8w8rqAET5sqakv40SD
         1W4prs7paQrrXARCvJSjlcjGKIN3LWEArIfa3opaupvpnkRMETx1Ey/69erKZiqeWyzY
         AIyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8zc2tn3GzbE6cFPAkg8sxzPpUm0DNZYXW6jg7QaqVSA=;
        b=F1xKEOBpRIL/wUsV+tGQGpIw3mDX1d9XYz1ofcFG2BfOFKU2alfJvI8CBBFYxnYUZQ
         Sk2dC3wGmpbPJumhR620d9NaLFhHrDzjxnsRaCoeGc6eDd+PcRUCfZqVLbs6MlGuQdFE
         UQ7aix2Vs0EX8Cw1RzEnIppE1Ibbyb4OIrjkIhe5O5JcMONg7rDliKGu+6M5kalUG116
         1b6VG+W0AlpMhWRWICWVCPiF2bBaruCLBYMKPuxRf1jX/wXlpgEQJszCI8ioqcV7rIBj
         vVIzIHfNfMZkH2Lz8gNLkJTqQ2E79HLsexoSL7gywQ3zx1Tqm8pYmicwTY9v9ZwxwhGU
         hgjQ==
X-Gm-Message-State: AOAM530gvVUeBqrOeZCAZWEbj/NyB9pBuTi46ZkArrbVmtDHnwada9kZ
	QikEXpRSpNzN92I7+5pYvr0=
X-Google-Smtp-Source: ABdhPJyNKbto6rOM+kC9RQkEHagEtHLhr2cy4AoAfduJ3Anlp8ju8JtgR0KzyjvQ9q/lIjnHqdvURw==
X-Received: by 2002:aca:ab4b:: with SMTP id u72mr3074992oie.112.1589893233167;
        Tue, 19 May 2020 06:00:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:aace:: with SMTP id t197ls2548847oie.4.gmail; Tue, 19
 May 2020 06:00:32 -0700 (PDT)
X-Received: by 2002:aca:d496:: with SMTP id l144mr3138285oig.72.1589893232388;
        Tue, 19 May 2020 06:00:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589893232; cv=none;
        d=google.com; s=arc-20160816;
        b=zXWMLRWu1aFCyXs4i74XjBMP0MtlqQf46SKdxpyU4PXyIjeMn87O4rQ9Csbtapb/p5
         BIM7NVMQJE9nwjdpGUQHSyqo1Kt7xPrN5yQSATRYTdJSUKPGn7dTRoZyH0pkUi2LY8Dv
         rkq+WLa37/Q/aun64F/cal3lZU4c7UGpIH6bTR72iuPBEF+Fks+74O1QbCpXhTywNlQs
         mqfhsn84ySrlg4UVjIsvnlGYkYn6Ut9mbsp/Owo/AgslZorPf5TAs2M5l1LKNEcCSoth
         shhVwiaXIYDAgNwRdNi3Fv0C+swaI4K9BhXQeKYVOU054VtA5AodYpJERvPBHnFwX9n9
         AwKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=o0yMq0MI3r0qFODZUM7uYp3B+CDouvIs/eVr6e/i9vY=;
        b=TeHSh3W4H3+KsFeM5X9LKQVONuAgACIPNQlfiOdbecYKeHJ1yP8Xraw+Y6rDcQS5VA
         iult/TK8oudQlL8nfR/uD/hXO8D7FHWgEi5ZVJrfIYVN7NJdAhJ0pE6EeuL22+nC83QY
         9wzrffWkW/aFL/n9aH45bsc9fsd6Uvic51XY4QLgy4z+9DPgnl/XqvFB2eo+8MIERwTj
         ZEuxkJuhApljzsu6wXmatLbf2U1y1RvsTuglxgcc1375oThAI35JcH79z4HiTJbZ15Lp
         byO3gRq526gx8lLF1OHXLuZElkMd8ygrh5uvcTzfWGq1UZBGERFAXy1ylI0OgsfDXu6B
         YRmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eYzcJCuP;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id n140si860511oig.0.2020.05.19.06.00.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 06:00:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id f189so14816005qkd.5
        for <kasan-dev@googlegroups.com>; Tue, 19 May 2020 06:00:32 -0700 (PDT)
X-Received: by 2002:a37:9d55:: with SMTP id g82mr18468689qke.407.1589893231394;
 Tue, 19 May 2020 06:00:31 -0700 (PDT)
MIME-Version: 1.0
References: <20200519022517.24182-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200519022517.24182-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 May 2020 15:00:18 +0200
Message-ID: <CACT4Y+aJDO+2kSgNpcvHksfn+bZaFWPoGj3-55-dyjLHcHbFUg@mail.gmail.com>
Subject: Re: [PATCH v4 2/4] kasan: record and print the free track
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eYzcJCuP;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Tue, May 19, 2020 at 4:25 AM Walter Wu <walter-zh.wu@mediatek.com> wrote=
:
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
> [1]https://bugzilla.kernel.org/show_bug.cgi?id=3D198437
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> ---
>  mm/kasan/common.c  | 22 ++--------------------
>  mm/kasan/generic.c | 18 ++++++++++++++++++
>  mm/kasan/kasan.h   |  7 +++++++
>  mm/kasan/report.c  | 20 --------------------
>  mm/kasan/tags.c    | 37 +++++++++++++++++++++++++++++++++++++
>  5 files changed, 64 insertions(+), 40 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 8bc618289bb1..47b53912f322 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -51,7 +51,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags)
>         return stack_depot_save(entries, nr_entries, flags);
>  }
>
> -static inline void set_track(struct kasan_track *track, gfp_t flags)
> +void kasan_set_track(struct kasan_track *track, gfp_t flags)
>  {
>         track->pid =3D current->pid;
>         track->stack =3D kasan_save_stack(flags);
> @@ -299,24 +299,6 @@ struct kasan_free_meta *get_free_info(struct kmem_ca=
che *cache,
>         return (void *)object + cache->kasan_info.free_meta_offset;
>  }
>
> -
> -static void kasan_set_free_info(struct kmem_cache *cache,
> -               void *object, u8 tag)
> -{
> -       struct kasan_alloc_meta *alloc_meta;
> -       u8 idx =3D 0;
> -
> -       alloc_meta =3D get_alloc_info(cache, object);
> -
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> -       idx =3D alloc_meta->free_track_idx;
> -       alloc_meta->free_pointer_tag[idx] =3D tag;
> -       alloc_meta->free_track_idx =3D (idx + 1) % KASAN_NR_FREE_STACKS;
> -#endif
> -
> -       set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> -}
> -
>  void kasan_poison_slab(struct page *page)
>  {
>         unsigned long i;
> @@ -492,7 +474,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache=
, const void *object,
>                 KASAN_KMALLOC_REDZONE);
>
>         if (cache->flags & SLAB_KASAN)
> -               set_track(&get_alloc_info(cache, object)->alloc_track, fl=
ags);
> +               kasan_set_track(&get_alloc_info(cache, object)->alloc_tra=
ck, flags);
>
>         return set_tag(object, tag);
>  }
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 3372bdcaf92a..763d8a13e0ac 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -344,3 +344,21 @@ void kasan_record_aux_stack(void *addr)
>         alloc_info->aux_stack[1] =3D alloc_info->aux_stack[0];
>         alloc_info->aux_stack[0] =3D kasan_save_stack(GFP_NOWAIT);
>  }
> +
> +void kasan_set_free_info(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       struct kasan_free_meta *free_meta;
> +
> +       free_meta =3D get_free_info(cache, object);
> +       kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
> +}
> +
> +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       struct kasan_free_meta *free_meta;
> +
> +       free_meta =3D get_free_info(cache, object);
> +       return &free_meta->free_track;
> +}
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index a7391bc83070..ad897ec36545 100644
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
> @@ -168,6 +171,10 @@ void kasan_report_invalid_free(void *object, unsigne=
d long ip);
>  struct page *kasan_addr_to_page(const void *addr);
>
>  depot_stack_handle_t kasan_save_stack(gfp_t flags);
> +void kasan_set_track(struct kasan_track *track, gfp_t flags);
> +void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag)=
;
> +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> +                               void *object, u8 tag);
>
>  #if defined(CONFIG_KASAN_GENERIC) && \
>         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 6f8f2bf8f53b..96d2657fe70f 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -159,26 +159,6 @@ static void describe_object_addr(struct kmem_cache *=
cache, void *object,
>                 (void *)(object_addr + cache->object_size));
>  }
>
> -static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache=
,
> -               void *object, u8 tag)
> -{
> -       struct kasan_alloc_meta *alloc_meta;
> -       int i =3D 0;
> -
> -       alloc_meta =3D get_alloc_info(cache, object);
> -
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> -       for (i =3D 0; i < KASAN_NR_FREE_STACKS; i++) {
> -               if (alloc_meta->free_pointer_tag[i] =3D=3D tag)
> -                       break;
> -       }
> -       if (i =3D=3D KASAN_NR_FREE_STACKS)
> -               i =3D alloc_meta->free_track_idx;
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
> @@ -162,3 +162,40 @@ void __hwasan_tag_memory(unsigned long addr, u8 tag,=
 unsigned long size)
>         kasan_poison_shadow((void *)addr, size, tag);
>  }
>  EXPORT_SYMBOL(__hwasan_tag_memory);
> +
> +void kasan_set_free_info(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +       u8 idx =3D 0;
> +
> +       alloc_meta =3D get_alloc_info(cache, object);
> +
> +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +       idx =3D alloc_meta->free_track_idx;
> +       alloc_meta->free_pointer_tag[idx] =3D tag;
> +       alloc_meta->free_track_idx =3D (idx + 1) % KASAN_NR_FREE_STACKS;
> +#endif
> +
> +       kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> +}
> +
> +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +       int i =3D 0;
> +
> +       alloc_meta =3D get_alloc_info(cache, object);
> +
> +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +       for (i =3D 0; i < KASAN_NR_FREE_STACKS; i++) {
> +               if (alloc_meta->free_pointer_tag[i] =3D=3D tag)
> +                       break;
> +       }
> +       if (i =3D=3D KASAN_NR_FREE_STACKS)
> +               i =3D alloc_meta->free_track_idx;
> +#endif
> +
> +       return &alloc_meta->free_track[i];
> +}

Hi Walter,

FTR I've uploaded this for review purposes here:
https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2=
458

Diff from the previous version is available as:
https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2=
458/1..2

I've tested this locally and with syzkaller. This is =F0=9F=94=A5=F0=9F=94=
=A5=F0=9F=94=A5:

[   80.583021][    C3] Freed by task 0:
[   80.583480][    C3]  kasan_save_stack+0x1b/0x40 mm/kasan/common.c:49
[   80.584056][    C3]  kasan_set_track+0x1c/0x30 mm/kasan/common.c:57
[   80.584617][    C3]  kasan_set_free_info+0x1b/0x30 mm/kasan/generic.c:35=
4
[   80.585221][    C3]  __kasan_slab_free+0xd8/0x120 mm/kasan/common.c:438
[   80.585814][    C3]  __cache_free mm/slab.c:3426 [inline]
[   80.585814][    C3]  kfree+0x10b/0x2b0 mm/slab.c:3757
[   80.586291][    C3]  kasan_rcu_reclaim+0x16/0x43 [test_kasan]
[   80.587009][    C3]  rcu_do_batch kernel/rcu/tree.c:2207 [inline]
[   80.587009][    C3]  rcu_core+0x59f/0x1370 kernel/rcu/tree.c:2434
[   80.587537][    C3]  __do_softirq+0x26c/0x9fa kernel/softirq.c:292
[   80.588085][    C3]
[   80.588367][    C3] Last one call_rcu() call stack:
[   80.589052][    C3]  kasan_save_stack+0x1b/0x40 mm/kasan/common.c:49
[   80.589622][    C3]  kasan_record_aux_stack+0x82/0xb0 mm/kasan/generic.c=
:345
[   80.590254][    C3]  __call_rcu kernel/rcu/tree.c:2672 [inline]
[   80.590254][    C3]  call_rcu+0x14f/0x7f0 kernel/rcu/tree.c:2746
[   80.590782][    C3]  kasan_rcu_uaf+0xe4/0xeb [test_kasan]
[   80.591697][    C3]  kmalloc_tests_init+0xbc/0x1097 [test_kasan]
[   80.592900][    C3]  do_one_initcall+0x10a/0x7d0 init/main.c:1196
[   80.593494][    C3]  do_init_module+0x1e6/0x6d0 kernel/module.c:3539
[   80.594066][    C3]  load_module+0x7464/0x9450 kernel/module.c:3890
[   80.594626][    C3]  __do_sys_init_module+0x1e3/0x220 kernel/module.c:39=
53
[   80.595265][    C3]  do_syscall_64+0xf6/0x7d0 arch/x86/entry/common.c:29=
5
[   80.595822][    C3]  entry_SYSCALL_64_after_hwframe+0x49/0xb3


Overall this looks very good to me.
But there is one aspect that bothers me. In the previous patch you had
code that returned NULL from kasan_get_free_track() if the object is
live (which means free meta is not available, it's occupied by object
data). Now you dropped that code, but I think we still need it.
Otherwise we cast user object data to free meta and print the free
stack/pid from whatever garbage is there. This may lead to very
confusing output and potentially to crashes in stackdepot.

What do you think about this patch on top of your patches?
https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2=
478
This way we very precisely mark the period of time when the object has
free track live and set.
If it looks good to you, feel free to incorporate it into your series.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BaJDO%2B2kSgNpcvHksfn%2BbZaFWPoGj3-55-dyjLHcHbFUg%40mail.=
gmail.com.

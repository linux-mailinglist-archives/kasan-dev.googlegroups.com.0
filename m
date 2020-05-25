Return-Path: <kasan-dev+bncBCMIZB7QWENRBXFMV33AKGQE5KGSFYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 2ADD81E0B17
	for <lists+kasan-dev@lfdr.de>; Mon, 25 May 2020 11:56:46 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id o192sf14001632pfg.19
        for <lists+kasan-dev@lfdr.de>; Mon, 25 May 2020 02:56:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590400604; cv=pass;
        d=google.com; s=arc-20160816;
        b=SdjcokkiA7M9Y5ev9Emzb23c909XWVEjao8ig0KB0bzGFAQd47nO3jNayQO+AmCPrH
         Zy2gClWBjngD3bMn35K7Vj92VTbG66W4cqaUJ/elgajcSA5L3yex37Y2vA/8w41nuaq1
         0ocTUvKA5LtYU+VwCQY0XPI3+ZjglGWaeW9rulIUZoJoW/VBCmBKDTODVeWOgQEkJIhg
         ktClAIezoLlHP4nBHctiBLQbTaEuSJQ9EHXWUfvlXfJCB7SbMi3+0URFQ3meGnuI9tvj
         r4PWwzFxWFBkMCXtEFNyI7392RFZ1veuDJcwQJE/f9t3s5y7YlxqZVYJI9Gb83UZkffM
         7Zqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MCMif6n33aBRQNVR4ZmNvktgCR7hYbMR0x/2iU57uW4=;
        b=iktgs5RyFJpGWTGg5nv7eGe18KSoZj1KfZGFuMVFsXlr99eZ+fE1EUE3Bnhcn14TRH
         2utPs3atqPgRr4QAnsZBNszlrj3ABH3KCaRByxlHqivB/OrXuuA34blOsywfCo+NwQCk
         hpXcZbZlZEJ7H7OQWtZPBJtvDCnu0XwmkU2DRqTLmS1ngsola+JDdPtflKq7Qva4koCQ
         +i4tuk4gMAfK/nW0hisPrfP3GgQa5rnrn5eGDRli/1qhf8mR81biSSmPoHdQW+Ju+Gmh
         6ts3onLfQggYhvCB3u1Py7wa9tzwHRDMdlUaOt9c/48MxgV/dZPEiffIsDyEmS43b/Ei
         mt6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pw328Wov;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MCMif6n33aBRQNVR4ZmNvktgCR7hYbMR0x/2iU57uW4=;
        b=Qwv3W61JecD3B/k4aViom8NULSRoIjqlML3ko0h5AzBeUpliip+7JMEQ+/+aPU3Cb3
         WYbOX146Z7BC7L//SEp2JldjyA/k/fw3IlO4IYP+90t6c8q2rpbByM8RccpH8tpmWurv
         0FjQY2sKCEwGXeMo8oqpRzPkJm/7RG+aNXtXPftqy5mca1HD9zj/XWXihcSVmmEmEDn5
         f2Put2PH5sjGCyNyDJ8udntw6FN3tnORcOiog2x6QAftwpL3psz5AkvqO8nDN0a0FvAm
         MJCVa++D6yoJ4dC5NUoZyOJcbtTbcR1GlbDxKknVbgRJgAFzHG9xytSBC5ApnFfFpOyD
         wK3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MCMif6n33aBRQNVR4ZmNvktgCR7hYbMR0x/2iU57uW4=;
        b=AEN6ahnZWOSmFImBRuGHwFnGlgcNSkhfZvnYQA3d1BbMQC7GQwxSZLqAix+qGNIKqV
         kUWBfamNwIz3Ez9RvztHuOXxRWqxANNqAemdUwaKFEVdf6ln9gK7pK9s4xOw4pAIszCg
         YGPIOtezvtYD14OIZWZK1vCxUs6p3IOFl/yURFJGJTg6/HG1kzwFsGvp/XB57n510IDd
         8iCxqGG/xzA9OYnicqNVl7NSsLSQH4lekgJCUce/1ee6q3gZz6H4Y9LP8HpznRrqWUSd
         JzMvnnM101iJNW4BRMt06dfIiSyGjl4vlAQY8CDGIrOVxg2nwIHIEz+pKY08kUjeTFJ2
         mm4w==
X-Gm-Message-State: AOAM532bf4zcWRJ5NwJVPY9NVKdj/e7VDhAiO0F+3m0uolGvjA8IdfnV
	UYDLFxsm9lOZSHf9LonPUAU=
X-Google-Smtp-Source: ABdhPJzNHAemTnpfR1Wh7nRMaQ9cI/vOOQFX2CKgMvL3WMgMc9LAMCROFyjzMl0+biweFKmHHl9AgQ==
X-Received: by 2002:a17:902:7b89:: with SMTP id w9mr24971293pll.252.1590400604685;
        Mon, 25 May 2020 02:56:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8ccf:: with SMTP id m198ls2847965pfd.10.gmail; Mon, 25
 May 2020 02:56:44 -0700 (PDT)
X-Received: by 2002:aa7:8c19:: with SMTP id c25mr13552224pfd.72.1590400604310;
        Mon, 25 May 2020 02:56:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590400604; cv=none;
        d=google.com; s=arc-20160816;
        b=K7LnuFqICUooCg+QUO/2Qt6cT3EfNu9e0kSyDvmZSqq1N/oDd+L76bpRg/RnVzNm0Z
         1qnNtK/ghPAI29FT35KsnIRfP+RbR0AKMg1EhscOKgM+BXimyldEktI0GWi/Wo7QtTPr
         Do1HCJFkCJCgQko5QeZY/uuHH/cdNBDCUoia4X8h0iGwv32QVeVNSzpT/dzgYj4nq6uK
         oszeZO6R9pdyrr+/tw2FrBPWKm0VkA8Ls4hz0RrbplEv3XIbBNWryvfy8zPMFEACflfj
         L2N7sEUWn7PAwSG/x52KqfN3yX0gCWzOpxHVS/iTeHwgLuEBXFQf5QXkYsBGCFHZJMEO
         O1YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xgy4pPwZvtj+TPA9hBH3u2ab7Rd+oEJ+C7zugCqkjSE=;
        b=kgtFFZGRr6AOIHebcxyVS7oEtxTaH9DV5yLOogn3jHoUFDOgAqggMMvjqQstFFv2Yq
         CDl7qeeV8G0yQi9jVtXaDYCBPHnPyAMuvshufJfqlFl4Yg1aSLl8J3F87isJ5Pj3ZlZg
         o6lMdUY/YcqbnzQd8tt9p6u6Ox7gk4db8tnGUd+9KDDHdbL0Z7sIwW6i5tvERoG+yk9E
         dw5LuQkkvIKraNEF3mgkAeSqpGfVlfLFsbxIrWwGtykQmHFzBigNeXAee/LzwguBSU+4
         eHogIM5251PwU6ruWkm6tM17DMh5kkkCLEtAdiomaR5YdzAs97TreN1gbuW3pR8SX2Qi
         Z0UQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pw328Wov;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id l1si1067215pjw.2.2020.05.25.02.56.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 May 2020 02:56:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id p12so13388905qtn.13
        for <kasan-dev@googlegroups.com>; Mon, 25 May 2020 02:56:44 -0700 (PDT)
X-Received: by 2002:ac8:260b:: with SMTP id u11mr27310502qtu.380.1590400603220;
 Mon, 25 May 2020 02:56:43 -0700 (PDT)
MIME-Version: 1.0
References: <20200522020127.23335-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200522020127.23335-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 25 May 2020 11:56:32 +0200
Message-ID: <CACT4Y+aFiKZs4EW9ovnQYCu0ytgy0Po3k0rCWAXObmV3Yvd68A@mail.gmail.com>
Subject: Re: [PATCH v6 2/4] kasan: record and print the free track
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pw328Wov;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
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

On Fri, May 22, 2020 at 4:01 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> Move free track from kasan_alloc_meta to kasan_free_meta in order
> to make struct kasan_alloc_meta and kasan_free_meta size are both
> 16 bytes. It is a good size because it is the minimal redzone size
> and a good number of alignment.
>
> For free track, we make some modifications as shown below:
> 1) Remove the free_track from struct kasan_alloc_meta.
> 2) Add the free_track into struct kasan_free_meta.
> 3) Add a macro KASAN_KMALLOC_FREETRACK in order to check whether
>    it can print free stack in KASAN report.
>
> [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437

Reviewed-and-tested-by: Dmitry Vyukov <dvyukov@google.com>

> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> ---
>  mm/kasan/common.c         | 22 ++--------------------
>  mm/kasan/generic.c        | 22 ++++++++++++++++++++++
>  mm/kasan/generic_report.c |  1 +
>  mm/kasan/kasan.h          | 13 +++++++++++--
>  mm/kasan/quarantine.c     |  1 +
>  mm/kasan/report.c         | 26 ++++----------------------
>  mm/kasan/tags.c           | 37 +++++++++++++++++++++++++++++++++++++
>  7 files changed, 78 insertions(+), 44 deletions(-)
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
>         track->pid = current->pid;
>         track->stack = kasan_save_stack(flags);
> @@ -299,24 +299,6 @@ struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
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
> @@ -492,7 +474,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>                 KASAN_KMALLOC_REDZONE);
>
>         if (cache->flags & SLAB_KASAN)
> -               set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> +               kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
>
>         return set_tag(object, tag);
>  }
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 8acf48882ba2..4b3cbad7431b 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -346,3 +346,25 @@ void kasan_record_aux_stack(void *addr)
>         alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
>         alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
>  }
> +
> +void kasan_set_free_info(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       struct kasan_free_meta *free_meta;
> +
> +       free_meta = get_free_info(cache, object);
> +       kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
> +
> +       /*
> +        *  the object was freed and has free track set
> +        */
> +       *(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREETRACK;
> +}
> +
> +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_KMALLOC_FREETRACK)
> +               return NULL;
> +       return &get_free_info(cache, object)->free_track;
> +}
> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> index e200acb2d292..a38c7a9e192a 100644
> --- a/mm/kasan/generic_report.c
> +++ b/mm/kasan/generic_report.c
> @@ -80,6 +80,7 @@ static const char *get_shadow_bug_type(struct kasan_access_info *info)
>                 break;
>         case KASAN_FREE_PAGE:
>         case KASAN_KMALLOC_FREE:
> +       case KASAN_KMALLOC_FREETRACK:
>                 bug_type = "use-after-free";
>                 break;
>         case KASAN_ALLOCA_LEFT:
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index a7391bc83070..ef655a1c6e15 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -17,15 +17,17 @@
>  #define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
>  #define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
>  #define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
> +#define KASAN_KMALLOC_FREETRACK 0xFA  /* object was freed and has free track set */
>  #else
>  #define KASAN_FREE_PAGE         KASAN_TAG_INVALID
>  #define KASAN_PAGE_REDZONE      KASAN_TAG_INVALID
>  #define KASAN_KMALLOC_REDZONE   KASAN_TAG_INVALID
>  #define KASAN_KMALLOC_FREE      KASAN_TAG_INVALID
> +#define KASAN_KMALLOC_FREETRACK KASAN_TAG_INVALID
>  #endif
>
> -#define KASAN_GLOBAL_REDZONE    0xFA  /* redzone for global variable */
> -#define KASAN_VMALLOC_INVALID   0xF9  /* unallocated space in vmapped page */
> +#define KASAN_GLOBAL_REDZONE    0xF9  /* redzone for global variable */
> +#define KASAN_VMALLOC_INVALID   0xF8  /* unallocated space in vmapped page */
>
>  /*
>   * Stack redzone shadow values
> @@ -127,6 +129,9 @@ struct kasan_free_meta {
>          * Otherwise it might be used for the allocator freelist.
>          */
>         struct qlist_node quarantine_link;
> +#ifdef CONFIG_KASAN_GENERIC
> +       struct kasan_track free_track;
> +#endif
>  };
>
>  struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
> @@ -168,6 +173,10 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
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
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 978bc4a3eb51..4c5375810449 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -145,6 +145,7 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
>         if (IS_ENABLED(CONFIG_SLAB))
>                 local_irq_save(flags);
>
> +       *(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREE;
>         ___cache_free(cache, object, _THIS_IP_);
>
>         if (IS_ENABLED(CONFIG_SLAB))
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 2421a4bd9227..fed3c8fdfd25 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -164,26 +164,6 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
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
>  static void describe_object(struct kmem_cache *cache, void *object,
>                                 const void *addr, u8 tag)
>  {
> @@ -195,8 +175,10 @@ static void describe_object(struct kmem_cache *cache, void *object,
>                 print_track(&alloc_info->alloc_track, "Allocated");
>                 pr_err("\n");
>                 free_track = kasan_get_free_track(cache, object, tag);
> -               print_track(free_track, "Freed");
> -               pr_err("\n");
> +               if (free_track) {
> +                       print_track(free_track, "Freed");
> +                       pr_err("\n");
> +               }
>
>  #ifdef CONFIG_KASAN_GENERIC
>                 if (alloc_info->aux_stack[0]) {
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
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200522020127.23335-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaFiKZs4EW9ovnQYCu0ytgy0Po3k0rCWAXObmV3Yvd68A%40mail.gmail.com.

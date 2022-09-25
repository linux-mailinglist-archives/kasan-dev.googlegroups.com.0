Return-Path: <kasan-dev+bncBDW2JDUY5AORB5MEYKMQMGQEOH7GNWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 68C055E945F
	for <lists+kasan-dev@lfdr.de>; Sun, 25 Sep 2022 18:31:51 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id i25-20020a635859000000b0042bbb74be8bsf2703287pgm.5
        for <lists+kasan-dev@lfdr.de>; Sun, 25 Sep 2022 09:31:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664123509; cv=pass;
        d=google.com; s=arc-20160816;
        b=tF4h/NUTYg6J7FmZigVG4PE+FtMcOrMzn1HnwpezOi5gRj/0AVIscMwEipYnPg6eOq
         sfAGChb+QoOTPsRoHbKfDBaqnKJgAT6e4x4xEpuEJ9kM04OAHznSi3aeghomXyV5SP1y
         XeOtJoB4L6DvuXJan+MvXkhu2LO4BC2DxVl4qC+8cBOOlhBg6cTc0s9pz2b030bUZ+34
         aa+Z/lgj0Nll3VisUrmL5AUpvuX+TMY5c2shL+pShw+8F+6cPlOhDWeL9i2p6FJ0chNT
         hGtZZPKIgO8AJ+DXERkFrV8iOiE15eH7hV1RAiBTNRWrkINtngA5TjZEOwe2MolSRl2Y
         1Uiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=tZsj6pQuvMhqYRjg/Ip35kCH5FDDUh6NTEMHZwx6qEY=;
        b=k0U0WrdnO2QdJXzc1eJlnCxDhnqdPo7RwACWOWOW9G2RxQBuy9ruA++zVt0Tyu3a6g
         o2qKkiL5iicuyztMqsE6W1989BVoh+Ehv8CM9s66zvgreUr5t4sdw1i8Vf6Ret3MmsKU
         8uHGnQyXdIqco64vKs0EKiV7m7ZDlHMWdMHXnx8o+oNyReF14XYWNelUHtd47LWQlchs
         t74/9B/juyO0QMJ7/C1IDKgcgUVV1kI1h2zGwZpf/rC6wPMAY02bAeoquxZCc796y5BU
         ejgHxo86Z7xOqitXhnHly6UWeBLGTp2CoA4lJi+UNqR/EndwiRX7hzQJaQDMy5BgKfQT
         XH4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ARNgIAQg;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=tZsj6pQuvMhqYRjg/Ip35kCH5FDDUh6NTEMHZwx6qEY=;
        b=JM174QrE/l/WSokR66BC4Atmo1Ak9mUOHXu3IVxoqK9JV3FEPhY5QJuINt+xFBMZyz
         xDJAh6hMDhDKldfpBwVS333vMkTR3ZWlLpi5EkwbIIyShQ5QrjRvgdlttB1lpbZrOJ3Y
         MQ0F5nAtkt0OYXv3C0d9x+BSrl+rGd1crFlqlxnRtbittQQa4TDRLEy2c+SW58G97SPp
         iG9+U44irRwWoUbYn9bgNzsApaf2v69lwZYBSwj0vqb5srqxAN4Pfq1lLqOdFjrgIufi
         ud5hdpnfy/OcW4xCofBi1Qp4Qf1QmDUOM39KmGpXxKZkuyiRSdMD4ZQSVbaSu83OQ6OZ
         cn2g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=tZsj6pQuvMhqYRjg/Ip35kCH5FDDUh6NTEMHZwx6qEY=;
        b=AY0xMTMhHBWB82+A7ehiYKTWeoNg8TIWL7geHmn/O/arixGBe3M6s4MLMfypPrOdDL
         EpMaVu+h4QNxCGfBeIjVJNXnl8UoAX9VDy5zLi0ma6Fb2Xj+Pg7Mb1mq/5HMzWz/YQO9
         9p0xO2xWZW5OjLUUOdvb7s8cjABNQh8ntxcDkQzvsFqhrdQJ8EpkFQgtgRPUKBLRmXHw
         jA/m1E60SFf5qw1LJ8z+xMc+lfLrjJir/NS/5RpyGzzgGPawUTGvhh/Y0XszxnpGQFJC
         8OMr7+yqVODAiP5c4JQSXgikiCCipeNukNdjZwUeeiDHWZXncPVo3SmNVcZr0Xe2WIzO
         I1qQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=tZsj6pQuvMhqYRjg/Ip35kCH5FDDUh6NTEMHZwx6qEY=;
        b=XFL4lFbITaRrF45Kj+asooq+giSgysNgLEuNlNaNQRdGHVmy/fJzIRECfol/LSkHXg
         ab10tOWsE+CSOD0askM1toTxU66PxU70E/WGje9VrwzSidU0aJSvmZHBAEnncBGEwIeQ
         LMuDVbkGKuEJAUVvxOU7dOA/QcK8WeDagbgRJEw1obQD1zYsTsOBunEIgYGJ8kkM0zo9
         akSn2EDLkp8AynzvekVTs0mNFKq0gwmZEd9b4UdxQREz1c4caYJdUdY8VLm04wQN2Ist
         5G8hIXsYSZ7oecd71KnzjKljA6yIHvYfKGMBwnqbfaZkXfUqPJiFZUDZGM5Gu0Su01qG
         fn4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf05rYM9M0ZkpdPgUGkPIvTrxIPxMI08ipJ44FZaTI/GG7MR8EaT
	nnCRlxULFwdfTjIr7z3x45k=
X-Google-Smtp-Source: AMsMyM4DE9uvD3KwrJ5VkJdVU3Pf3NiaxQgSeUMKhoxjdD5IzOUImfyXN44fE6VJaVn4bgib19X+NA==
X-Received: by 2002:a65:44c5:0:b0:439:4697:ead0 with SMTP id g5-20020a6544c5000000b004394697ead0mr16139978pgs.45.1664123509719;
        Sun, 25 Sep 2022 09:31:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:788d:b0:178:5938:29de with SMTP id
 q13-20020a170902788d00b00178593829dels14630464pll.2.-pod-prod-gmail; Sun, 25
 Sep 2022 09:31:48 -0700 (PDT)
X-Received: by 2002:a17:90b:1d0f:b0:202:be3e:a14a with SMTP id on15-20020a17090b1d0f00b00202be3ea14amr31976556pjb.102.1664123508749;
        Sun, 25 Sep 2022 09:31:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664123508; cv=none;
        d=google.com; s=arc-20160816;
        b=lzFi/fM03asufHdNlQIGaLRyBEAw4k8ufoNtdybKwed/9Ss9iGOw0AoO7c5zkkVgVJ
         I7g5FWlU9B2Mapq2iXmPQ44SSwh1ae1276SzUdlh2xmyq44j7CzsZlobDeOL8g7UKUDl
         SCtjJVXwuOQQa7YblAGl/uQJUhXM4ZDfosjwxZUnuIJmHe4KeRV6iEKyqojM0SX2ym60
         BYD2rwg9HkkoFFd9rilZaT+Dy5UVZCaBu/RLXFl0bbzxQqQuUKhtz/1Hwi9x05BfutJF
         w/lGjg27/JJWjbe+YoROtkF+hCBN3LXWL3YXHiKKuyi/PKZNsTlvWSpTphp4lr33l9VW
         gT9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C77rGCAYqGdTYQ5Hat6z7HfUcuu3QTxI69RZhcgUIhM=;
        b=nGMG3OkhsCO+KuzPB9sUoSQ1WMdmQ/eUlF5yMOjQS9IsdWv8R6tMjLmI8CPeOiaRpk
         LiBXctFmx2o8elC5ISLqUNWhuYlyGChuEI9GrItCYDzPoyCzmZdqTQ4ywPXzLy53qb8U
         yED7y+IO2W7HHVJEPGHpsfR+eKUtyDvBdqYlUcfTrkGrvZze0ZUwVlP9gPKjo4wh2eZJ
         tgvw6KLHgGKP7vfcVFFtKLpxQPjVTwUVaA2LSzY2m0f0qOW/G0KRdfvZIA2amEkisPxn
         Xn+qhXB1LrJdgq9kwAMbOPOa0tltqiXQ3hx0+f0tiavbQ34HNyyTlyrNjwu24lyOeu4E
         oiNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ARNgIAQg;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id u187-20020a6379c4000000b0042ba5b4bd9asi659336pgc.2.2022.09.25.09.31.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 25 Sep 2022 09:31:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id w4so3094830qvp.2
        for <kasan-dev@googlegroups.com>; Sun, 25 Sep 2022 09:31:48 -0700 (PDT)
X-Received: by 2002:ad4:5be2:0:b0:4ad:791c:8724 with SMTP id
 k2-20020ad45be2000000b004ad791c8724mr14396644qvc.56.1664123507765; Sun, 25
 Sep 2022 09:31:47 -0700 (PDT)
MIME-Version: 1.0
References: <20220913065423.520159-1-feng.tang@intel.com> <20220913065423.520159-4-feng.tang@intel.com>
 <CA+fCnZdFi471MxQG9RduQcBZWR10GCqxyNkuaDXzX6y4zCaYAQ@mail.gmail.com>
 <Yyr9ZZnVPgr4GHYQ@feng-clx> <CA+fCnZdUF3YiNpy10=xOJmPVbftaJr76wB5E58v0W_946Uketw@mail.gmail.com>
 <YzA68cSh5Uuh5pjZ@feng-clx>
In-Reply-To: <YzA68cSh5Uuh5pjZ@feng-clx>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 25 Sep 2022 18:31:37 +0200
Message-ID: <CA+fCnZd4SD4rSD5yWogwvYm0h7YZ73CXFNCSd8PVOSeNXdWR1Q@mail.gmail.com>
Subject: Re: [PATCH v6 3/4] mm: kasan: Add free_meta size info in struct kasan_cache
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, "Hansen, Dave" <dave.hansen@intel.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, "Sang, Oliver" <oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ARNgIAQg;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f36
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sun, Sep 25, 2022 at 1:27 PM Feng Tang <feng.tang@intel.com> wrote:
>
> > [1] https://lore.kernel.org/linux-mm/c7b316d30d90e5947eb8280f4dc78856a49298cf.1662411799.git.andreyknvl@google.com/
>
> I noticed this has been merged to -mm tree's 'mm-everything' branch,
> so following is the patch againt that. Thanks!
>
> One thing I'm not very sure is, to check 'in-object' kasan's meta
> size, I didn't check 'alloc_meta_offset', as from the code reading
> the alloc_meta is never put inside slab object data area.

Yes, this is correct.

> Thanks,
> Feng
>
> ---8<---
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index d811b3d7d2a1..96c9d56e5510 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -302,7 +302,7 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
>
>  #ifdef CONFIG_KASAN_GENERIC
>
> -size_t kasan_metadata_size(struct kmem_cache *cache);
> +size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object);
>  slab_flags_t kasan_never_merge(void);
>  void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>                         slab_flags_t *flags);
> @@ -315,7 +315,8 @@ void kasan_record_aux_stack_noalloc(void *ptr);
>  #else /* CONFIG_KASAN_GENERIC */
>
>  /* Tag-based KASAN modes do not use per-object metadata. */
> -static inline size_t kasan_metadata_size(struct kmem_cache *cache)
> +static inline size_t kasan_metadata_size(struct kmem_cache *cache,
> +                                               bool in_object)
>  {
>         return 0;
>  }
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index d8b5590f9484..5a806f9b9466 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -450,15 +450,22 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
>                 __memset(alloc_meta, 0, sizeof(*alloc_meta));
>  }
>
> -size_t kasan_metadata_size(struct kmem_cache *cache)
> +size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
>  {
> +       struct kasan_cache *info = &cache->kasan_info ;
> +
>         if (!kasan_requires_meta())
>                 return 0;
> -       return (cache->kasan_info.alloc_meta_offset ?
> -               sizeof(struct kasan_alloc_meta) : 0) +
> -               ((cache->kasan_info.free_meta_offset &&
> -                 cache->kasan_info.free_meta_offset != KASAN_NO_FREE_META) ?
> -                sizeof(struct kasan_free_meta) : 0);
> +
> +       if (in_object)
> +               return (info->free_meta_offset ?
> +                       0 : sizeof(struct kasan_free_meta));
> +       else
> +               return (info->alloc_meta_offset ?
> +                       sizeof(struct kasan_alloc_meta) : 0) +
> +                       ((info->free_meta_offset &&
> +                       info->free_meta_offset != KASAN_NO_FREE_META) ?
> +                       sizeof(struct kasan_free_meta) : 0);
>  }
>
>  static void __kasan_record_aux_stack(void *addr, bool can_alloc)
> diff --git a/mm/slub.c b/mm/slub.c
> index ce8310e131b3..a75c21a0da8b 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -887,7 +887,7 @@ static void print_trailer(struct kmem_cache *s, struct slab *slab, u8 *p)
>         if (s->flags & SLAB_STORE_USER)
>                 off += 2 * sizeof(struct track);
>
> -       off += kasan_metadata_size(s);
> +       off += kasan_metadata_size(s, false);
>
>         if (off != size_from_object(s))
>                 /* Beginning of the filler is the free pointer */
> @@ -1042,7 +1042,7 @@ static int check_pad_bytes(struct kmem_cache *s, struct slab *slab, u8 *p)
>                 /* We also have user information there */
>                 off += 2 * sizeof(struct track);
>
> -       off += kasan_metadata_size(s);
> +       off += kasan_metadata_size(s, false);
>
>         if (size_from_object(s) == off)
>                 return 1;

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd4SD4rSD5yWogwvYm0h7YZ73CXFNCSd8PVOSeNXdWR1Q%40mail.gmail.com.

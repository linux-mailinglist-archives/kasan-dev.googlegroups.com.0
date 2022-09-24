Return-Path: <kasan-dev+bncBDW2JDUY5AORBXENXWMQMGQEBZ4P2KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B4D325E8F20
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 20:05:17 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id j135-20020a1f6e8d000000b003a357909b2esf1213444vkc.1
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 11:05:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664042716; cv=pass;
        d=google.com; s=arc-20160816;
        b=EUAm+51EZbwkss+E/5Ci82UL4xjW8rzv6iHtujRqL/+pTXbIgF0paVoq3cAuoy5Ghw
         heCbCiCsFAsKcPkqvHXxMlFvqaTfH+cLZioJtInXrbEqDzfc6KZPvgSnhaHhzPV7Yw4s
         zGySqnPd3esGdv6hPlwGkNQvTetjRspRjXeIZk+/kYydCT9BEvFH50zncop1r26c0O5j
         R4EQ7oUmqE7YNRFm7L01W2bAoa7ymdrEBy0fOpICg0trFTFmeJcTC25rSpcjFRaiJJ68
         l9A35BfBdzlSAIUnUkzhrV9y/L76jkkx7KmhEqPJgBy8LPPCngCyJ1jzx6ly8YMzo4p9
         5aQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=rXtYeJRwgrRwayEjMP6T81Zp7azHcLlqtmvg2Px8oGI=;
        b=mQTuvjwMWklOWFdElNTTF5s2NSIXO/QGht+w5Mfk38ip4PvVFLHfsAebiCWzviiA73
         /oj0AXGuhYvx4uVw1j1S5IIbraFuvO67wcspSxlI7bPX0OAVVih5FlZds7wuZJnUEpmJ
         tgYv5KchiqmTDe/+0FyhLNdqMrGZBqUAOWUVS1ySN3Ub2GXVzT+r+6VwVCvode/ZPS3w
         JZr2VhfI/oQ8A9LjshAdknfSu4A8w25xSALGW08xtpZj0Y4/Ilb0evYk6Fbk1MuHdL2A
         UAsLZnOa0VUuaII+RtHO3IE3zILpxIlAYF3govDmqz2tRIFnQZj2k4tYcKWZA3lD7gNn
         kjpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=TBDentZR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=rXtYeJRwgrRwayEjMP6T81Zp7azHcLlqtmvg2Px8oGI=;
        b=QcxKJF2pZuAaKomG5+zpttTnRpODvhhFC/ShVkjnHU3zwrFU/5j7uhER7yiazEBAlG
         RyMRFZ+TP7Bncs84UC2RRdAuplUFuX0AnyBxmg7PkDRsAa2QF8wVcsHFf01+/LTYqmur
         CzCJrIRh+OUAhCiGpFPHy5hcsgc2dBPkxWNjZCJcCoPBuOoB1jFb2hdSgG9fcakIGY7O
         VJBxMk3zB3Z5WYwUmtXSR0lj3RSH3xWMW/2EO3M2zStB2pbD/QNERfjNzepo/YGlylaZ
         6TAgn3QRFAALZvhx5HkmIlwr1Y/fGYkeuH+YSSQsHR0XeoFXWaslpxHIC0iCsbnSErlX
         ItLw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=rXtYeJRwgrRwayEjMP6T81Zp7azHcLlqtmvg2Px8oGI=;
        b=RMPLcT7pLYBkeIuZHa1Wm2ALCxKrmsAjgY9pSAEHQUQU82MArBIQM0qyj+mJUi1Vb3
         xkeXXDwG8A7Zh4kcJAD+lg67blp8oFcWBgK8tTHCKGrZfZGC2uxeVEWBfzRPHrM4UYRH
         5R7ZtVWAFXPw5b+07JM2BuEEPhoaFn7KSDCUlAlf92jDQ89kzPopDEDOqU5lk+BJGw3n
         HbtEms+DuB18jmzmg/Gw0y6FbLNR9I9gE+7uNV52TP1hnryuLj3sJAQZ0tJCjOcbgZuN
         L6i4U6cQyvSbP5AJnXjHCiuSxtILzxqqhjzf4RS5k3+NtrqceM4pum3PuERx6qhAoQRy
         3gCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=rXtYeJRwgrRwayEjMP6T81Zp7azHcLlqtmvg2Px8oGI=;
        b=NlYm5mMjAI0yKy1KjTG9onZuC2QdoEMz14gjY+PWEdM6VVURiSTwxXfDTZVLAwxi/h
         f35RqK6A/C85kNpeCq5TP+ip3uMs/dbIZ8DO6z4mM4USEygjwtfHfNc8xx51VXHujSaw
         WeUvdFt9dnBBvy7xzkKLEmIOf7zX8YFcE0ROGOBquhGbNuu1f0bdXYMkIoI9CEjcQz/h
         oPPxbPKcpZCvuWVdPUfLmooo6QlQ/xXO7N9ACBQjhnjpz06RmebZuj01F/ze9pJCHJv8
         2S+XPAITQKyXYnnDXSR4aDwi4fjU7rPi6td/diq1JNeLsOYhphtR7bxcxCnzOMMgc4Oh
         QdQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2W2SQHWptmX2GfOSMbV/eBVU4iSbWP8xZaKZTVLwVRg/iq+I6X
	9hBJHxZJp8mG4znZr9g7QV8=
X-Google-Smtp-Source: AMsMyM6aWA9Sr4YkOmUrEbGqtXXXSIT9/Niqbm1k2GxT5fKWEmKQNfTYyDnuIcFhKACM66gbogNuqw==
X-Received: by 2002:a05:6102:319c:b0:398:c9a8:ef0f with SMTP id c28-20020a056102319c00b00398c9a8ef0fmr5198550vsh.43.1664042716415;
        Sat, 24 Sep 2022 11:05:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3843:0:b0:3bc:cfde:8672 with SMTP id q3-20020a9f3843000000b003bccfde8672ls1373904uad.7.-pod-prod-gmail;
 Sat, 24 Sep 2022 11:05:15 -0700 (PDT)
X-Received: by 2002:ab0:70c6:0:b0:39e:ed14:806b with SMTP id r6-20020ab070c6000000b0039eed14806bmr5677240ual.82.1664042715861;
        Sat, 24 Sep 2022 11:05:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664042715; cv=none;
        d=google.com; s=arc-20160816;
        b=Q1kNsQ7krTU//dcG8iZFoHWttdje49CLHtE6tnIYvAENHXupHkiMsFKGXHEKaboIbR
         wMCsuFf+Oayxcszsc0hC/xZaeXfQC1E8NAunLBtKcF7Jz+wHKw5yPt9tqGhsxcnIIOZs
         VQMSQZlCEPaChtSBiDF/K2ta3qTn+471ScyP/xa/Y11qHa11WEOoaEhWu8VhMZNr8G7o
         B2XAqVzrZqM9Hr8BpU+58CQb6T4lHvkN2ZUIsH8GI4fVJxzPY4PKmtXs3DWdwB9fCK6H
         iHuGMGM50OF78rfItS3jFp8RI/H/6T5tZnZxcTtlNmbNVt1a/wfydwB9RimzgfulV3Qr
         VYdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cWXihzkts7fGQmkZ/lCAYDuSh40IJwfY6ZWwrmbTVGU=;
        b=AjufuOgZLvIY17jLHZ5t572+u5HCeZZF/be+g9V1uhCJPCe57yQXzYXP1b6KoXpfx6
         x5XA3wEPAl3qr2RWNxDyspo8uFysGMPlJZEDaBea0wjjwoJ5kipf08LIgJLEmrvLH5Iy
         boOzg4n03CPqS/H0BFwWsqrt9adq/jtf8MwbcjMI2zQkk6j6TLzedYOGfS/2OnzjXXRb
         rNw6LTUf+PRXxEaM755FuHyOGOHDAZeaWwzcyuRuEj3UBbqw9Ir9FK2DYT3unfnd877Q
         v5656gRIeR2LZ1cx5UKg+PLHgC2iIiW3jUTpZlsvWVARjXJmx+sfk60eULTGuXaC4pDE
         RaDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=TBDentZR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x82f.google.com (mail-qt1-x82f.google.com. [2607:f8b0:4864:20::82f])
        by gmr-mx.google.com with ESMTPS id 126-20020a1f1684000000b003760f8bf2a0si578630vkw.2.2022.09.24.11.05.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 24 Sep 2022 11:05:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82f as permitted sender) client-ip=2607:f8b0:4864:20::82f;
Received: by mail-qt1-x82f.google.com with SMTP id h21so1905484qta.3
        for <kasan-dev@googlegroups.com>; Sat, 24 Sep 2022 11:05:15 -0700 (PDT)
X-Received: by 2002:a05:622a:180d:b0:35b:d283:7e65 with SMTP id
 t13-20020a05622a180d00b0035bd2837e65mr12033167qtc.106.1664042715583; Sat, 24
 Sep 2022 11:05:15 -0700 (PDT)
MIME-Version: 1.0
References: <20220913065423.520159-1-feng.tang@intel.com> <20220913065423.520159-4-feng.tang@intel.com>
 <CA+fCnZdFi471MxQG9RduQcBZWR10GCqxyNkuaDXzX6y4zCaYAQ@mail.gmail.com> <Yyr9ZZnVPgr4GHYQ@feng-clx>
In-Reply-To: <Yyr9ZZnVPgr4GHYQ@feng-clx>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 24 Sep 2022 20:05:04 +0200
Message-ID: <CA+fCnZdUF3YiNpy10=xOJmPVbftaJr76wB5E58v0W_946Uketw@mail.gmail.com>
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
 header.i=@gmail.com header.s=20210112 header.b=TBDentZR;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82f
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

On Wed, Sep 21, 2022 at 2:03 PM Feng Tang <feng.tang@intel.com> wrote:
>
> Agree, it's better not touch the internal fields in slub code.
>
> How about the following patch, it merge the 2 functions with one flag
> indicating in meta data or object. (I'm fine with 2 separate functions)

The overall approach sounds good. See some comments below.

> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b092277bf48d..0ad05a34e708 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -150,11 +150,12 @@ static __always_inline void kasan_cache_create_kmalloc(struct kmem_cache *cache)
>                 __kasan_cache_create_kmalloc(cache);
>  }
>
> -size_t __kasan_metadata_size(struct kmem_cache *cache);
> -static __always_inline size_t kasan_metadata_size(struct kmem_cache *cache)
> +size_t __kasan_meta_size(struct kmem_cache *cache, bool in_slab_object);
> +static __always_inline size_t kasan_meta_size(struct kmem_cache *cache,
> +                                                       bool in_slab_object)

I would keep the name as kasan_metadata_size as it's more clear to
external users but rename in_slab_object to in_object to make the
declaration shorter.

>  {
>         if (kasan_enabled())
> -               return __kasan_metadata_size(cache);
> +               return  __kasan_meta_size(cache, in_slab_object);
>         return 0;
>  }
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 69f583855c8b..2a8710461ebb 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -218,14 +218,21 @@ void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
>         cache->kasan_info.is_kmalloc = true;
>  }
>
> -size_t __kasan_metadata_size(struct kmem_cache *cache)
> +size_t __kasan_meta_size(struct kmem_cache *cache, bool in_slab_object)
>  {
>         if (!kasan_stack_collection_enabled())
>                 return 0;
> -       return (cache->kasan_info.alloc_meta_offset ?
> -               sizeof(struct kasan_alloc_meta) : 0) +
> -               (cache->kasan_info.free_meta_offset ?
> -               sizeof(struct kasan_free_meta) : 0);
> +
> +       if (in_slab_object)
> +               return (cache->kasan_info.alloc_meta_offset == 0 ?
> +                       sizeof(struct kasan_alloc_meta) : 0) +
> +                       (cache->kasan_info.free_meta_offset ?
> +                       sizeof(struct kasan_free_meta) : 0);
> +       else
> +               return (cache->kasan_info.alloc_meta_offset == 0 ?
> +                       sizeof(struct kasan_alloc_meta) : 0) +
> +                       (cache->kasan_info.free_meta_offset ?
> +                       sizeof(struct kasan_free_meta) : 0);

Something weird here: both if and else cases are the same.

The change also needs to be rebased onto [1].

Thanks!

[1] https://lore.kernel.org/linux-mm/c7b316d30d90e5947eb8280f4dc78856a49298cf.1662411799.git.andreyknvl@google.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdUF3YiNpy10%3DxOJmPVbftaJr76wB5E58v0W_946Uketw%40mail.gmail.com.

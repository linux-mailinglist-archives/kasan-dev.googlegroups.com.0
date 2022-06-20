Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNXRYGKQMGQEMSSLGEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 62DA5551ACD
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 15:40:08 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id z19-20020ab04913000000b0036868226b2fsf5870547uac.16
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 06:40:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655732407; cv=pass;
        d=google.com; s=arc-20160816;
        b=LO3nwHEjIVqB12CxEJdzmrJDpeAsL1tqXi4zPqaxqTB1VtfKonbJ64Oeo46ldoMwhu
         vhP1dyQ9+Ix5eKotAM2lrjjHy2Kz+7qnu1gb7nYEcX8iet8YKYklqaal0Qlw+N6CXhR0
         Lv2IaSoQFtQMnA0vPQz6HyEDv/AaJ1+TT6oxoX1mpG4CObnKGP8eE8l8uNRHf7MRca70
         2bVcvDACk0pBu5NteitM5Zoxs4feN/GF1tFC6ZAO8oYPtwrIMqJrsTHIOGdd0kJ3jZTZ
         ioRZbwPpDk1XDG7MHCYyl/K5vQZHwbP0/8LUgaI79dtl58yAZZkz6RLMyiHocNSC6O5e
         VgGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=li5WZtLhYlGQoDXFZKLUOLGICZtjfryAl9acBH/k8iE=;
        b=X5t8Q3X4+fW+RHS5cjo9o9T2vdzQoVEzEEeioCH5T0Tzai4V/atPtix01xTrqfZKCD
         5YHgmdVJtobIeJiVbdryZbZZhmY4TRxBzAiQ3GYSiIPEZj+JhmHEKlUyk29aSKS03xB9
         C+BiPm4pyI963XvrAfgTXnvk2WCKjSkXMfiSw6gXPa0KWvwgESWtrvK0tPHhKutMCfPR
         n9+1udPuKQbx1wT2ncZewGZG0pzNQ0i5juOp0B0CWfx4yCeI5v77XCeO/7Tieuzp+OFe
         vnAhwEfPwHwCzyOjuSBlLcv4M8DkUY5Bb+G+QALJm06scRUFgu2u7vtTnpGg90tfumXC
         vWGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K21MOgAw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=li5WZtLhYlGQoDXFZKLUOLGICZtjfryAl9acBH/k8iE=;
        b=jYDr36eYa2XJDSV0gyfFMSlTHH4VP4lQblLPQLfgS8PCT9unGSOu08fTn8DnokgvGa
         F+Kal062RHCsEvMSoKf7r+GA97/Ds3WJ3Yxz31sZVJjqxqRDOTs9jz4Hv9Abhp0ki3Ww
         VS+tzZn8LPsjJG+MHRl04dAxKGvT0cfkgj9NVLn3F9TG6nuZM1Um/4Ml53ZRDZOuLq2/
         sLmq0NCS3iTMUVbIWynswEGI0PLScAg9JYEXa6md5vNyLeOTo1qYpjTHOo0LwacXOprj
         VazJYtLAutHpuzXLW8JSamaH+wYO0CsqtkJe3MLPiBoifUN/VVkTwXKLyyTqcBWSnnLS
         g7lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=li5WZtLhYlGQoDXFZKLUOLGICZtjfryAl9acBH/k8iE=;
        b=t86AUhTBoXgQYKSvYjP6gFjg4TfqydjpMQlxSiz9ffOx9+2bAbHKZCeL/ooFodzRCb
         tPjKtHxSu6vNQp2wbis6mN5KDDr57LWn28LR9JmRv+OSqZ4nOAKObe29LblQN+OFh1vO
         DVxcLPQFD39XArwwMB84XHV4riB7Z4YNsr+2mv8nl6N0cFTv80c7VwemqDWQ0wbuXRVO
         pL9JlLeWj8JaAjDG2Ir9wP56gBb1H0YKrrzItFo1o7Z/XsBm1ALzhBMAePyi/M9iwiEb
         WsR+KnHDHdy+bx0A7KDOmWg4wmnHKzqTQk5OgVAJrpJIdDipWFvBGVCb3LxJkChVT+UG
         bjlg==
X-Gm-Message-State: AJIora+FlyR2YWN7yRUzmnNznQtnYHhhXHozF4Wgkit34RkrFP6KlqA7
	iTTv+vgcfWEck1sCS8S3xDI=
X-Google-Smtp-Source: AGRyM1sNxHkrTcqVVscEyg90lB46ois7fT34CdqgNXvslYmtchiPmcHxsAtluQNYmhrM8SQYhYnI0w==
X-Received: by 2002:a1f:e684:0:b0:368:6230:bf62 with SMTP id d126-20020a1fe684000000b003686230bf62mr8944944vkh.25.1655732407069;
        Mon, 20 Jun 2022 06:40:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c981:0:b0:353:1bec:1d4c with SMTP id y1-20020a67c981000000b003531bec1d4cls1328194vsk.7.gmail;
 Mon, 20 Jun 2022 06:40:06 -0700 (PDT)
X-Received: by 2002:a05:6102:3e0c:b0:354:39bb:eea5 with SMTP id j12-20020a0561023e0c00b0035439bbeea5mr1028340vsv.46.1655732406364;
        Mon, 20 Jun 2022 06:40:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655732406; cv=none;
        d=google.com; s=arc-20160816;
        b=IF8rbxefa+ww5HX6n4jtJDyaOt/4m7dYJzyFvNjOP0YKvTZg+TqYiPqm0GxzKAQysR
         Ky86IQdLv5q5oYGOQ+BCxJnGQx2T+AZS3HvkToznARFR2PhJ/nW2avYr1KbAjWZedAOY
         KKl1KQ5AuFNIz9+M/vLN/4kNGGghy8IfJHXPzF9Yos6WvtJUBeugP7nwAjg7WrDrp+F8
         LfJ5O/4WUQ59zVcGV68OUrRlpVBe/ixMzxiIvSv5I/stc/0nP7e8UWPHZGj4XwwD9Ou2
         yngIoKAPhYYwwEDAMFO5eBJ0e4yKt+5Qe34+J/mGzdy5Jlsm/g3UeV6slBdwlbW8Eznr
         Fhbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PSBOYdsGO6+KrB480UmpDMZjJ15J65v7kSYVCX5JDz0=;
        b=QT11+tRguU5IyXscQCTYoP8rjNhS9rT/+go5eZ8E0VhQwOau66kICo8LLK8yMf1E6M
         JsoqvtQC9Pd8vyIBQIxzPIqYI3y1BFUgfMNpgXY2DpMRMP5jXWK3Vv25+tQiyjhoPiDO
         OMsXN/54NwQAWmV8R+fB0VonOmfNFYH9keIcs2l7GxM6YZfjL2sYUQU5jStt8madXcEa
         Y0+0Sa6ei+5BMGBOxotsg4Vz+87s7TvehdheKdOFdy136+bHMc9J24WF/GqGP6MCx/+q
         b7kY1oJduTXkq9cRNnHo04h0UCv2UN5Qb6NEdRfMHUjkLWhW6Jr9Fmrm5fEYLpRMB4Od
         V/IA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K21MOgAw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id az19-20020a056102285300b00354200da743si371450vsb.0.2022.06.20.06.40.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jun 2022 06:40:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-3137316bb69so100481697b3.10
        for <kasan-dev@googlegroups.com>; Mon, 20 Jun 2022 06:40:06 -0700 (PDT)
X-Received: by 2002:a81:574c:0:b0:317:7c3a:45be with SMTP id
 l73-20020a81574c000000b003177c3a45bemr21447189ywb.316.1655732405833; Mon, 20
 Jun 2022 06:40:05 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1655150842.git.andreyknvl@google.com> <50cdd8e8d696a8958b7b59c940561c6ed8042436.1655150842.git.andreyknvl@google.com>
In-Reply-To: <50cdd8e8d696a8958b7b59c940561c6ed8042436.1655150842.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jun 2022 15:39:30 +0200
Message-ID: <CANpmjNP-TJs5pcnMXE7L2m9CPAdmiBjkeRCm3RtyPdQQFM3H0Q@mail.gmail.com>
Subject: Re: [PATCH 02/32] kasan: rename kasan_set_*_info to kasan_save_*_info
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=K21MOgAw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as
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

On Mon, 13 Jun 2022 at 22:15, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Rename set_alloc_info() and kasan_set_free_info() to save_alloc_info()
> and kasan_save_free_info(). The new names make more sense.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  mm/kasan/common.c  | 8 ++++----
>  mm/kasan/generic.c | 2 +-
>  mm/kasan/kasan.h   | 2 +-
>  mm/kasan/tags.c    | 2 +-
>  4 files changed, 7 insertions(+), 7 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 968d2365d8c1..753775b894b6 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -364,7 +364,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>                 return false;
>
>         if (kasan_stack_collection_enabled())
> -               kasan_set_free_info(cache, object, tag);
> +               kasan_save_free_info(cache, object, tag);
>
>         return kasan_quarantine_put(cache, object);
>  }
> @@ -423,7 +423,7 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
>         }
>  }
>
> -static void set_alloc_info(struct kmem_cache *cache, void *object,
> +static void save_alloc_info(struct kmem_cache *cache, void *object,
>                                 gfp_t flags, bool is_kmalloc)
>  {
>         struct kasan_alloc_meta *alloc_meta;
> @@ -467,7 +467,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
>
>         /* Save alloc info (if possible) for non-kmalloc() allocations. */
>         if (kasan_stack_collection_enabled())
> -               set_alloc_info(cache, (void *)object, flags, false);
> +               save_alloc_info(cache, (void *)object, flags, false);
>
>         return tagged_object;
>  }
> @@ -513,7 +513,7 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
>          * This also rewrites the alloc info when called from kasan_krealloc().
>          */
>         if (kasan_stack_collection_enabled())
> -               set_alloc_info(cache, (void *)object, flags, true);
> +               save_alloc_info(cache, (void *)object, flags, true);
>
>         /* Keep the tag that was set by kasan_slab_alloc(). */
>         return (void *)object;
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 437fcc7e77cf..03a3770cfeae 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -358,7 +358,7 @@ void kasan_record_aux_stack_noalloc(void *addr)
>         return __kasan_record_aux_stack(addr, false);
>  }
>
> -void kasan_set_free_info(struct kmem_cache *cache,
> +void kasan_save_free_info(struct kmem_cache *cache,
>                                 void *object, u8 tag)
>  {
>         struct kasan_free_meta *free_meta;
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 610d60d6e5b8..6df8d7b01073 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -284,7 +284,7 @@ struct slab *kasan_addr_to_slab(const void *addr);
>
>  depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
>  void kasan_set_track(struct kasan_track *track, gfp_t flags);
> -void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag);
> +void kasan_save_free_info(struct kmem_cache *cache, void *object, u8 tag);
>  struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>                                 void *object, u8 tag);
>
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 8f48b9502a17..b453a353bc86 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -17,7 +17,7 @@
>
>  #include "kasan.h"
>
> -void kasan_set_free_info(struct kmem_cache *cache,
> +void kasan_save_free_info(struct kmem_cache *cache,
>                                 void *object, u8 tag)
>  {
>         struct kasan_alloc_meta *alloc_meta;
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/50cdd8e8d696a8958b7b59c940561c6ed8042436.1655150842.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP-TJs5pcnMXE7L2m9CPAdmiBjkeRCm3RtyPdQQFM3H0Q%40mail.gmail.com.

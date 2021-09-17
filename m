Return-Path: <kasan-dev+bncBCMIZB7QWENRBA5CSKFAMGQEVT53WUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id D774D40F888
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 14:58:44 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id f16-20020a92cb50000000b002376905517dsf21283887ilq.18
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 05:58:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631883523; cv=pass;
        d=google.com; s=arc-20160816;
        b=C3FEqls7NHF5ab5iJYPi+QLdKCL0gd0K48TwCOGMLBR7vtyx2T9eakiMTZX5nU6wmV
         aovlup54qmMnPH4JOHBrwJ+IaFqFla5bRXDbVitQlNpM6iLLVP69I3Y/XIozqDVjX0y4
         sSE6HehTa7OrtTUiX0rQJLONx2Z44Ssu41TkpgLUFtFNIp1XMT8tH5dg3KFQGZDBKTkh
         TWQrM/UJ9ABHFiz3V1hhmw+B57PIDpUV6uCP9TeYTKznfVgBgsL/LhalmwEv3L8sz2XV
         obysvifdFplBvHCoA3Lih5YVs6mCgrRyaajxqsIE8tEyOyzJG7WSgGOH4m6dMxPQ7Q9d
         eJnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cLQ147anhtTmAK4uMwOk5v8wY1uXgdqPwMsCj4+5iJs=;
        b=PAzVIyjRUT3oJer5LwttIUj/mawi0fFr69/0Ece2Ihw8501bWZ+Nv/7nuoaPLy5CxS
         /PnT2mYmm49JCQtNO40bijZyrjEjaC2EVmUmzQdLOQqt05/9y2B9g8V3lXBmhtcj8220
         xanX99QSaq0Uxo6v608Ho924cuo1jhcoEK5Sd+X5MoGwBs8VtksSshuKtqfUY35SeMJS
         jpSu3H6W+Qxp2xWsP8sBeB19/6rO15iV5kOeyJFM6PdVV1Nryr/OmMIh051FzPjymP3v
         WGp34zgvVgLPolub7399vezX/f9YwnJ2eXejJt5gBCDUzjCHp87jtIf+JNO87tK/ZIG/
         krAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ohm9YZmH;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cLQ147anhtTmAK4uMwOk5v8wY1uXgdqPwMsCj4+5iJs=;
        b=UiqsckICybPFk1h9JN/21BcDnmUIB+wZmkq3giKGpbuwUN16inlwRjnnb7DwgaT/ts
         7d9a+5wdMRp15xHPeZMVxM+6UONEWN+CY0KCJhxOO0vwV0RPOegWEw2lCDeC16oCcwXY
         ev4dOCTOfcYo/yCwUtBzmhu2xdti34H31ljEk107ODge+hPt40LpnRq4vIXFw36BGQsk
         uR4zSkoUoHBOCs7UsJGR7lPSMJhrOsjG0Q72HJeacg0PWfuLVUW7bUb6MzTHHHhleZfa
         0QzDDm+41pLlpF1mw1RARxa3FKZwzZ02fmsL7ego16gwi9EgAmCFXjq6oc+a9Y+vVyWe
         9ccg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cLQ147anhtTmAK4uMwOk5v8wY1uXgdqPwMsCj4+5iJs=;
        b=J/fLutvnBkLt0vydtC+1IDuPF+yAVduj3bjq1yCoj4/nsKzWVWmm9jRxNyjuKzHiYA
         D2dG07UBlR/aXWKVnEaiwyVHjjC9qrzu54EVks2tpI4+ilZyOmx61AXmMdFgRhDe42c5
         /ganFf4Jb1zLLo1LyoqUmn/f2PHS8zFRfUxCEaGQx6vgu5yGnFrqPxkyCiqVowbrmpVb
         0YRsZs0SE/QHtJJ+vS4Y9eUYRC+POa7dApdggxvQdfD2w2WXRXu373QsAF9Iiv9UDVSa
         EKhH1vSpivrTUE+k7pxq+i78Sde5dTFFdUHm6eU2hZUkooRCTyfFBFkDaOq0DYz7gDkK
         ystQ==
X-Gm-Message-State: AOAM531suBfp/OZxG4oKrJC7Ed7lzu9eJG1vlUkzuUqVoSAzTSLLFelO
	CHy7PIj/+jrPueFDvhgQs6A=
X-Google-Smtp-Source: ABdhPJxJ+NEjBgWtDQkQ1Xa1MHsrOsjWqTAk9v4IXR7806sMa/07NZxaNGfeZS10fbcuI9Dwv0Vd5w==
X-Received: by 2002:a05:6638:a2d:: with SMTP id 13mr8577173jao.12.1631883523479;
        Fri, 17 Sep 2021 05:58:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:f906:: with SMTP id j6ls94712iog.9.gmail; Fri, 17 Sep
 2021 05:58:43 -0700 (PDT)
X-Received: by 2002:a6b:3e84:: with SMTP id l126mr8697296ioa.151.1631883523092;
        Fri, 17 Sep 2021 05:58:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631883523; cv=none;
        d=google.com; s=arc-20160816;
        b=o3J8j+dGdsUqoeJRD6Og18WneVp35P0DKhTTi7+lwCTt7xNZzJ6cRqJGjNsfNNY8Gv
         T4H92lYfLKdSObGBk9hzKOTwRkzxCca//Bdpa5ER/d+7Icx/SbIOskWv8JC7dTr43eKe
         yk/HDz2aSiPii9HwiSLNja3Tz6woOGIEWzyh5oQTAfkl2C95igm6U5rIa0UZ4ScKaR5B
         pm96CSS2goBago07KAXAVtVAIF0koMpMumCKE3abmgL92J33YuVignG16qb3Nihtj8qS
         lBTQmNkdmkPFQ5dksKZFFY4G1lA4fS/LbgfvZJ7o5GPk/srwXJWmuNCsFd4lBjE5XTvm
         //Pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+0q9dMDiPL7l1Xvh/pCQyuBurf5KBV4txXHcebk3J7o=;
        b=EcgpHoswmQYzsry8BMLblm97O2JLgCMskZXYOyccuOo5YaOkjJmQTfoylEKphkuj+i
         jdU/A5SfLsX8bAu2qoMKoffp4q6tH8kdTZm5uf0XnAr6cYbP0QmCBpyDEKxIZ2e4FqkY
         X6jFrtmx2/tYKw3AFIILV2W4wnqk7X5BcZYQrwBKbWw4k1cETLXLkx6JNFhLRTx39DWD
         th/JjOGosspIGxQwYHYAT6o6+kOxrPGS0rfRvnvEcpdiL6pFqLgrVmMjLWfQFFzSTEml
         Hugka9b3Eim00ShiGKFbjDTTn9ObKqZD3GeZpcv2flMU0J5CQ33dh93u9OiqnIVs/xYB
         HiUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ohm9YZmH;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22f.google.com (mail-oi1-x22f.google.com. [2607:f8b0:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id o21si440578iov.2.2021.09.17.05.58.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Sep 2021 05:58:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22f as permitted sender) client-ip=2607:f8b0:4864:20::22f;
Received: by mail-oi1-x22f.google.com with SMTP id bi4so13800347oib.9
        for <kasan-dev@googlegroups.com>; Fri, 17 Sep 2021 05:58:43 -0700 (PDT)
X-Received: by 2002:aca:1109:: with SMTP id 9mr3759856oir.109.1631883522559;
 Fri, 17 Sep 2021 05:58:42 -0700 (PDT)
MIME-Version: 1.0
References: <20210917110756.1121272-1-elver@google.com>
In-Reply-To: <20210917110756.1121272-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Sep 2021 14:58:30 +0200
Message-ID: <CACT4Y+Zzxo19YH-tFOPHGJ25zP=pdjSSjzjQNZTG62bCjZgz3w@mail.gmail.com>
Subject: Re: [PATCH 1/3] kfence: count unexpectedly skipped allocations
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ohm9YZmH;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22f
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

On Fri, 17 Sept 2021 at 13:08, 'Marco Elver' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Maintain a counter to count allocations that are skipped due to being
> incompatible (oversized, incompatible gfp flags) or no capacity.
>
> This is to compute the fraction of allocations that could not be
> serviced by KFENCE, which we expect to be rare.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  mm/kfence/core.c | 20 ++++++++++++++++----
>  1 file changed, 16 insertions(+), 4 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 7a97db8bc8e7..2755800f3e2a 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -112,6 +112,8 @@ enum kfence_counter_id {
>         KFENCE_COUNTER_FREES,
>         KFENCE_COUNTER_ZOMBIES,
>         KFENCE_COUNTER_BUGS,
> +       KFENCE_COUNTER_SKIP_INCOMPAT,
> +       KFENCE_COUNTER_SKIP_CAPACITY,
>         KFENCE_COUNTER_COUNT,
>  };
>  static atomic_long_t counters[KFENCE_COUNTER_COUNT];
> @@ -121,6 +123,8 @@ static const char *const counter_names[] = {
>         [KFENCE_COUNTER_FREES]          = "total frees",
>         [KFENCE_COUNTER_ZOMBIES]        = "zombie allocations",
>         [KFENCE_COUNTER_BUGS]           = "total bugs",
> +       [KFENCE_COUNTER_SKIP_INCOMPAT]  = "skipped allocations (incompatible)",
> +       [KFENCE_COUNTER_SKIP_CAPACITY]  = "skipped allocations (capacity)",
>  };
>  static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);
>
> @@ -272,7 +276,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>         }
>         raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
>         if (!meta)
> -               return NULL;
> +               goto no_capacity;
>
>         if (unlikely(!raw_spin_trylock_irqsave(&meta->lock, flags))) {
>                 /*
> @@ -289,7 +293,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>                 list_add_tail(&meta->list, &kfence_freelist);
>                 raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
>
> -               return NULL;
> +               goto no_capacity;

Do we expect this case to be so rare that we don't care?
Strictly speaking it's not no_capacity. So if I see large no_capacity
numbers, the first question I will have is: is it really no_capacity,
or some other case that we mixed together?



>         }
>
>         meta->addr = metadata_to_pageaddr(meta);
> @@ -349,6 +353,10 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>         atomic_long_inc(&counters[KFENCE_COUNTER_ALLOCS]);
>
>         return addr;
> +
> +no_capacity:
> +       atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_CAPACITY]);
> +       return NULL;
>  }
>
>  static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool zombie)
> @@ -740,8 +748,10 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>          * Perform size check before switching kfence_allocation_gate, so that
>          * we don't disable KFENCE without making an allocation.
>          */
> -       if (size > PAGE_SIZE)
> +       if (size > PAGE_SIZE) {
> +               atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_INCOMPAT]);
>                 return NULL;
> +       }
>
>         /*
>          * Skip allocations from non-default zones, including DMA. We cannot
> @@ -749,8 +759,10 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>          * properties (e.g. reside in DMAable memory).
>          */
>         if ((flags & GFP_ZONEMASK) ||
> -           (s->flags & (SLAB_CACHE_DMA | SLAB_CACHE_DMA32)))
> +           (s->flags & (SLAB_CACHE_DMA | SLAB_CACHE_DMA32))) {
> +               atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_INCOMPAT]);
>                 return NULL;
> +       }
>
>         /*
>          * allocation_gate only needs to become non-zero, so it doesn't make
> --
> 2.33.0.464.g1972c5931b-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210917110756.1121272-1-elver%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZzxo19YH-tFOPHGJ25zP%3DpdjSSjzjQNZTG62bCjZgz3w%40mail.gmail.com.

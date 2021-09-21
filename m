Return-Path: <kasan-dev+bncBCMIZB7QWENRB2HRU2FAMGQEYDBPGVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 54A784131F2
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 12:50:18 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id w5-20020a654105000000b002692534afcesf17515738pgp.8
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 03:50:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632221417; cv=pass;
        d=google.com; s=arc-20160816;
        b=mdzDphLWHq4AXpAAcr7iRh5Vr9vFEfQUcveR61fwlA3F30DoJY6DaAMmLq17ZIP3al
         18+O4ol9/BhQMCcMoF/F79XCkxlf3jjBjV6krKUMaG8T3vCK832Uq7cfvio9mjJ0dcFE
         WEHWnPu5Uw2NRkmWOKAFcIp57kdNmSLp2peLZYaPQDnqia2U4BCDrXdbFXZURL6Rh/YN
         2Yprc0Uy6yp+RMT3DOfm+l3HaGJuhZIBcgsiT43hfcAAHxJh03xOwEa3EMn9Kpcrzpjp
         V8pDiXcWOBAT10GJWHW2GgNZ5RmXIXH453D00A+xaHXzlMPQItQ0Um0xH9JTvW3s3o3C
         FwRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gJJ8XzLe61sYBlNwBrMQFWTL8Es2J1EtWjg7EMnzgWg=;
        b=hnFabeclQddzfG8ej/Ak0iAYHfxdpWzYiSTmHnSjesXiCdGJHZ4/JtBix9xol3hVlR
         qkAgd1QgCNjBF+5dT/HGy2FfuTz2vVSc5yNYifwmKhv+gVGA7Yyt9exC1DqlI/OYvhtg
         9yScXFHrR6oxrnp2ynjVMAJb0r/K//NNdI2sLF8EfJ7AAefeRVb8UtOhn5npbwD0kZ2D
         0y5td7fOW0HNbJvvrsiIZMslevIntgTJZq+yiwc9+l3mSwiCGy9C5jkddwts9R1f3Pb2
         3Y1wPwDhD4opcwP9W3jK+0OyUq9NUoqOedRs6/Ecas6WF1FEnlau05pr1HU4lF87cnSB
         4qkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pGybIBE1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c29 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gJJ8XzLe61sYBlNwBrMQFWTL8Es2J1EtWjg7EMnzgWg=;
        b=Njbtgb1sTWsiO6Qdrx/DxYfoHlg+vkIiHPFlui07ljnoa0w9MZ2aZp87SSaKpoa1J6
         N5BxBDd4SmGZYv3SRV8XghL4UAAhXZv6dR/L6Bs+Y6GCgxKJq2kUAzRi9uNz7tiggR0K
         84TpTOnzToiNy4RHpNY4ff3r2T3zby1znaNKw6LfMjnoX/QzLtL5Vh0EsnrwS6psfN+X
         z9/6QoAj32BlDYR4X9EuxYs75E8jbv1qgnKmwgwOs40L2fwVo770VZrXaCLkPRK3dFvo
         euidbStACNka2qZNKChj4EOCECQXOOFq3KECPXN3m3bXa1F8tK3ywXbPMIRuKu9yT+7D
         7WjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gJJ8XzLe61sYBlNwBrMQFWTL8Es2J1EtWjg7EMnzgWg=;
        b=AWg/ljLhmM2D46M2DJT5LOS31GzNZjx82jd4qLegWIb/uOfbMLvQa0Fb/RJGvDiR2H
         VUzQB3itr9NI+PFrL0JHaV7sKSBdMES1W6jXs14St84Vbr/E/LaLBR1IMMRqRY8RujaR
         pK6+WJCxu1EhlkefKwozoYrkwFgqvYNzDdUn9ED2v8P/OTDvrepgYHTwOEF6Xtsdbg3e
         Qyr6YpcReTBAdQ7fY/gOwnBq1ZqcThcTupEn5jHxnf7g3O6zhwc/9ZH8TbD+wPbZDL+o
         r3wyAUp1nyNSf8gEJ0j+8lCyI2Vh+ZIZBnKAKRKEEUjlXAYtjkOwH2TLQyyDtCm1Ug+K
         UIkA==
X-Gm-Message-State: AOAM531v+AHhZ9Tmbt3GPLWrXA8dPcg0kPsOu3JK1a+oIXVctYQJWHk0
	Vf7u4ul1/nXbb1KDANBYz2A=
X-Google-Smtp-Source: ABdhPJxmTwXv3Xan3JE380Cuf/5hD6T6aZ5Ts+b1wAQ8gvA8naqaRjss42nSwFU0zRLeb5bhRZgz0w==
X-Received: by 2002:a63:894a:: with SMTP id v71mr18905461pgd.13.1632221417003;
        Tue, 21 Sep 2021 03:50:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:2cd8:: with SMTP id s207ls7638226pfs.11.gmail; Tue, 21
 Sep 2021 03:50:16 -0700 (PDT)
X-Received: by 2002:a63:2cce:: with SMTP id s197mr2053774pgs.45.1632221416292;
        Tue, 21 Sep 2021 03:50:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632221416; cv=none;
        d=google.com; s=arc-20160816;
        b=sciCVJkzHBwJvpqMEgmjzqDfHlPQ1157eTR77RWH34DkHINcl+xcmj+WutdNQLz2eq
         7PvyaMbaowobV0AAltDZwfnnzTuKVJO/x0BxfIX/ZbTFQK0gYTKltWinHUyHiG+/4XhT
         zM4mDQ6GR5nrMcvszMXeGQSYKbbfKXCjL97TPOM0GK6ed+hwKlJIoty4nekTKyWMVEBV
         aDlOlbPdxphj10z9Tfi0hhdfD/X6YZ6KU+jw9WK1im5aTMRiKhvZJshG1/4Qv/NDR3QD
         hvoTaM53rYFQfU9Dw2HMaEtYuNM0Kj8clEaKrRYDtQHbi6Tm7C0duF4rkcFnMYTcfm7p
         Nskw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=K0Bhbgp6QvbcNQHQeE1e8BDMff+79sDxtFoMpFLBCbA=;
        b=XzkpRRdfSVKCx39iAflpJ4XY4W5KK1WfXuP3y3w7ga3amXUx8RvibSqEd9iphaZFYC
         L1irbthqv5DXLOwSYqWBNuRlVJbODvPYU78dNmDIf/v/jc0/V4L/U/HQpHRQQDGKVNsF
         +buhgZxj/ojb5QCAM1GAaG7pZsK8xFOmlsqnnyWn1mufDVO7GRrVOIZtRPfBqwKqTnAH
         /eEKw60HjNxOypV8bRRP/dMQq8CorVbEQCFTQIIK2FI8nQ5eBD9nwTltPGkZ+XDb5etG
         DCFJmNcmlh8Cbje85udwFjPxU6opnbU8LySC4J8o17YwtRZX5tMjW1P4jNIiSjmSIgIR
         3mpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pGybIBE1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c29 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc29.google.com (mail-oo1-xc29.google.com. [2607:f8b0:4864:20::c29])
        by gmr-mx.google.com with ESMTPS id n63si276884pfd.3.2021.09.21.03.50.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Sep 2021 03:50:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c29 as permitted sender) client-ip=2607:f8b0:4864:20::c29;
Received: by mail-oo1-xc29.google.com with SMTP id u15-20020a4a970f000000b0029aed4b0e4eso4936280ooi.9
        for <kasan-dev@googlegroups.com>; Tue, 21 Sep 2021 03:50:16 -0700 (PDT)
X-Received: by 2002:a4a:52c4:: with SMTP id d187mr9155943oob.53.1632221415456;
 Tue, 21 Sep 2021 03:50:15 -0700 (PDT)
MIME-Version: 1.0
References: <20210921101014.1938382-1-elver@google.com> <20210921101014.1938382-3-elver@google.com>
In-Reply-To: <20210921101014.1938382-3-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Sep 2021 12:50:04 +0200
Message-ID: <CACT4Y+Yt6KjcvOehj6VV=0-W+mGuzh1vOd3dH9DbnPW9h04tQA@mail.gmail.com>
Subject: Re: [PATCH v2 3/5] kfence: move saving stack trace of allocations
 into __kfence_alloc()
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Jann Horn <jannh@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pGybIBE1;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c29
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

On Tue, 21 Sept 2021 at 12:10, 'Marco Elver' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Move the saving of the stack trace of allocations into __kfence_alloc(),
> so that the stack entries array can be used outside of
> kfence_guarded_alloc() and we avoid potentially unwinding the stack
> multiple times.
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v2:
> * New patch.
> ---
>  mm/kfence/core.c | 35 ++++++++++++++++++++++++-----------
>  1 file changed, 24 insertions(+), 11 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 249d75b7e5ee..db01814f8ff0 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -187,19 +187,26 @@ static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *m
>   * Update the object's metadata state, including updating the alloc/free stacks
>   * depending on the state transition.
>   */
> -static noinline void metadata_update_state(struct kfence_metadata *meta,
> -                                          enum kfence_object_state next)
> +static noinline void
> +metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state next,
> +                     unsigned long *stack_entries, size_t num_stack_entries)
>  {
>         struct kfence_track *track =
>                 next == KFENCE_OBJECT_FREED ? &meta->free_track : &meta->alloc_track;
>
>         lockdep_assert_held(&meta->lock);
>
> -       /*
> -        * Skip over 1 (this) functions; noinline ensures we do not accidentally
> -        * skip over the caller by never inlining.
> -        */
> -       track->num_stack_entries = stack_trace_save(track->stack_entries, KFENCE_STACK_DEPTH, 1);
> +       if (stack_entries) {
> +               memcpy(track->stack_entries, stack_entries,
> +                      num_stack_entries * sizeof(stack_entries[0]));
> +       } else {
> +               /*
> +                * Skip over 1 (this) functions; noinline ensures we do not
> +                * accidentally skip over the caller by never inlining.
> +                */
> +               num_stack_entries = stack_trace_save(track->stack_entries, KFENCE_STACK_DEPTH, 1);
> +       }
> +       track->num_stack_entries = num_stack_entries;
>         track->pid = task_pid_nr(current);
>         track->cpu = raw_smp_processor_id();
>         track->ts_nsec = local_clock(); /* Same source as printk timestamps. */
> @@ -261,7 +268,8 @@ static __always_inline void for_each_canary(const struct kfence_metadata *meta,
>         }
>  }
>
> -static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp)
> +static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp,
> +                                 unsigned long *stack_entries, size_t num_stack_entries)
>  {
>         struct kfence_metadata *meta = NULL;
>         unsigned long flags;
> @@ -320,7 +328,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>         addr = (void *)meta->addr;
>
>         /* Update remaining metadata. */
> -       metadata_update_state(meta, KFENCE_OBJECT_ALLOCATED);
> +       metadata_update_state(meta, KFENCE_OBJECT_ALLOCATED, stack_entries, num_stack_entries);
>         /* Pairs with READ_ONCE() in kfence_shutdown_cache(). */
>         WRITE_ONCE(meta->cache, cache);
>         meta->size = size;
> @@ -400,7 +408,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
>                 memzero_explicit(addr, meta->size);
>
>         /* Mark the object as freed. */
> -       metadata_update_state(meta, KFENCE_OBJECT_FREED);
> +       metadata_update_state(meta, KFENCE_OBJECT_FREED, NULL, 0);
>
>         raw_spin_unlock_irqrestore(&meta->lock, flags);
>
> @@ -742,6 +750,9 @@ void kfence_shutdown_cache(struct kmem_cache *s)
>
>  void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>  {
> +       unsigned long stack_entries[KFENCE_STACK_DEPTH];
> +       size_t num_stack_entries;
> +
>         /*
>          * Perform size check before switching kfence_allocation_gate, so that
>          * we don't disable KFENCE without making an allocation.
> @@ -786,7 +797,9 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>         if (!READ_ONCE(kfence_enabled))
>                 return NULL;
>
> -       return kfence_guarded_alloc(s, size, flags);
> +       num_stack_entries = stack_trace_save(stack_entries, KFENCE_STACK_DEPTH, 0);
> +
> +       return kfence_guarded_alloc(s, size, flags, stack_entries, num_stack_entries);
>  }
>
>  size_t kfence_ksize(const void *addr)
> --
> 2.33.0.464.g1972c5931b-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210921101014.1938382-3-elver%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYt6KjcvOehj6VV%3D0-W%2BmGuzh1vOd3dH9DbnPW9h04tQA%40mail.gmail.com.

Return-Path: <kasan-dev+bncBCMIZB7QWENRBYNK4D6AKGQEVPHUMGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id AAE0729AC4F
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 13:41:06 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id w4sf538978vkm.8
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 05:41:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603802465; cv=pass;
        d=google.com; s=arc-20160816;
        b=X3TnCjLKaEwx0GY3d5Za1mjy4SMoUdrAm0+dRtr1bPjIzVsSP28uXQ4syb6FkiKuBA
         Z8RSF4QSAtVwmB2A/JZeK/GccDWuxZ1bncKra/Bb6FLpkjLypXbSXzA8YpUBpWTtEaWD
         U1lxWgIxK9RXKG/0vrTtyyNCpzFKZaAv7JZFf59C/+Kjp+RX7CVFAvaQYS3m/wzocYko
         MpuSM+B32/HrjfIl2dRqVuJsR7s/4JiL2K7S/ecyb8xdDdWQYOt+FTMoQFm/ll5vA/KE
         ittOwGyLZuYIcQgFOw6MsyJf4XqFzhTD/kcMhnIexkUZKJV2Yj7jrGjKbJFmekenp1sp
         PgwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=r18cF495h70B6kTjHhZUPpr6DMp66wwUZYeo5d5oEQ4=;
        b=DFZs38wP3nSg8bBptCOM1Fln01GfEhR6rX/JAoYtzwywaWDQb7suP2z4+zcg5B0QZc
         mTiamc7ybl1M5eInzwshvQkrp1HmtqM+gECTu8xl4yTwz46g4Z9+qEFBBDfB5JV5pNou
         A/2FrGKqoqbje72jglNmt7umbHVgPnonn7BQG/dF0X6koWi4dnCG8DBuHNSCecyJ0ILU
         zqUXPHbd0JSLijDbUut+fCOfyI8xsLNdG2WHx63AmCXpFnZ0KoR7V1LvnGXL1V86bD1g
         k5JqtDs/fWQ2M/09ynyZ3vx9P9O+7aJeo6hoEbyz8SVNXZvcYLByYs3QRTcGeeYeG8uh
         2DRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PKPUtEjz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r18cF495h70B6kTjHhZUPpr6DMp66wwUZYeo5d5oEQ4=;
        b=pkwGzoGBa/4W3Wckz3828YqjKJT74e09af224PRNleK1gZG2rXWIPQZXnCoSp0IDl/
         EeWnp3Usi8xl3XTQoxiJgP8yOnIzIg4AKTrbDDZih0b+UTtDxzwekHnaWIbRoogpqQhE
         Pfsc8jfvk2ecsh2ZrbT1mGcPTjRpCWlhNJPQ9NEkWFiWnfvkwJs74ZN3yYS+1IlpYRQh
         r5sDSrgseUrcRza69R6WHsNkNHjVHLWcIKil59R0VyTBTOakFKcErlYusZJRgnnoBB+k
         2XbrWlF0/4h8bZMDnG0fCPbr4jvAk+hSlmt5VETdcX0q9EqpihjU7BiD9Z01ZXtdI9oH
         Vdew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r18cF495h70B6kTjHhZUPpr6DMp66wwUZYeo5d5oEQ4=;
        b=nGWxowBiuX343FJrTDBazkPOM89jlp6n61YqPIEHGuK+LEj7pa3xQ5dcasoTs9LIa/
         RuNt5l/FC/riNSoPX/8YEKm6dCFcp8n941q2Nwrei75yHdaekfG7upXr/uJ6ThsfuJ7a
         VxyNkt6PBrc6pTe9ngk3MSz4J2UxaxwAzpSwG4f6PTRL2mBB3ntNXHjcPpbyJf4LYlYT
         /EYE4xLcnAflA3zqfA8dOA9DC+lsgQRSkbE9z5H0RstoIca6oNhlO8bwj9yCahErhqI9
         G3yKLhFOIIHuGumPPNM1iR5X7XDaeBFW++7L8xp1PMsILPYBKwctCAxVpMHVfvRU/oS7
         xUbg==
X-Gm-Message-State: AOAM533ikjFSAZ3WKXACdeHpj0TUXiz/4+DfRa01pSUTfyVhxz4V+f2A
	MrRwaGaYiqaxsTbW/g/bTFw=
X-Google-Smtp-Source: ABdhPJy6s/IizV0i1OR2JNstKQhOfNLmrX8KrWhjMfs3ZwKiAqXQ+d/qhlL97PtZalT6QZHGw/gI/g==
X-Received: by 2002:a1f:5fce:: with SMTP id t197mr1087095vkb.7.1603802465671;
        Tue, 27 Oct 2020 05:41:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:15c7:: with SMTP id 190ls145266vsv.1.gmail; Tue, 27 Oct
 2020 05:41:05 -0700 (PDT)
X-Received: by 2002:a67:7f8a:: with SMTP id a132mr1137022vsd.23.1603802465091;
        Tue, 27 Oct 2020 05:41:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603802465; cv=none;
        d=google.com; s=arc-20160816;
        b=XlJX5Vy9AA1RUa3T1T3lqRi2Qdv/i2zEwGtn1NxbJJtJ1Aq+PpUL2BiWloW+K+GMhw
         NDdf0Ox4vCLyEDcQDt8vOQ0tW4HtsfGIDC82bHSe64MrjlS+OWrdjZfNLSQLzRPb5/qF
         PJtKEu7l+Cd717otmC0KFqslBfYcDDZjdLJ1z6+IV7vmNBpKo7fO5JcWWVVyFsswNCTc
         NYSsBama69n+UgFmXBfPGYeqeb1qrF5D2A08438HSLv1fx1U06opbJ8/YRYsepQ2CPQp
         uAccl2j1UuNmmdBi7WoInz8pTuT6aKDWNwTb+u2Xf5DeJUnM422Zk+l0V0m0QQb5tDvV
         TMYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=41n2Ilf3HkOC7w8XKi7whm47sc4vWGvgMbmf7JM80uI=;
        b=fRj1T/Y9Pj38FWvIQyseu0DBol1yXc4kOwHEg+ZAqtSljLzcxx0R9G6v22bU3I6pRA
         v07Q1zMGOqhDq+7LqSSyTpE4HaeaSD2o0bIjs2Wh8Fl65IgC8pqNCMahIw5W1NBmRBAq
         3jeZvepXAZkndaC8dpBvMZ4eBGc2zhCdpWp0Fizzd+VDVZ6wT/c9XRDixsIcNBlCvumj
         1kA3lDk3jq/PNiUA8I5bFedFT72QYJJAK2QZBRBrRcMLn9gbheI6TJT9ZoHT9hF3flVG
         oNtzAZDtzM69xRUOrS/MRgvL3MV5PtLCo2yFmrd1Xbd44So2xlOJdecF1D92urIL2Qj8
         L1FQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PKPUtEjz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id w123si69469vke.3.2020.10.27.05.41.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 05:41:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id q199so918185qke.10
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 05:41:05 -0700 (PDT)
X-Received: by 2002:a37:9747:: with SMTP id z68mr1809588qkd.424.1603802464374;
 Tue, 27 Oct 2020 05:41:04 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <b205406ea24f189da7fa94f0fc78de8d856858d9.1603372719.git.andreyknvl@google.com>
In-Reply-To: <b205406ea24f189da7fa94f0fc78de8d856858d9.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Oct 2020 13:40:53 +0100
Message-ID: <CACT4Y+YriYDCw0_8p8gxWPLuSrv2OCZp=HRSM315wTTkyCkJPA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 02/21] kasan: rename get_alloc/free_info
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PKPUtEjz;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Rename get_alloc_info() and get_free_info() to kasan_get_alloc_meta()
> and kasan_get_free_meta() to better reflect what those do and avoid
> confusion with kasan_set_free_info().
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ib6e4ba61c8b12112b403d3479a9799ac8fff8de1

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  mm/kasan/common.c         | 16 ++++++++--------
>  mm/kasan/generic.c        | 12 ++++++------
>  mm/kasan/hw_tags.c        |  4 ++--
>  mm/kasan/kasan.h          |  8 ++++----
>  mm/kasan/quarantine.c     |  4 ++--
>  mm/kasan/report.c         | 12 ++++++------
>  mm/kasan/report_sw_tags.c |  2 +-
>  mm/kasan/sw_tags.c        |  4 ++--
>  8 files changed, 31 insertions(+), 31 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 5712c66c11c1..8fd04415d8f4 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -175,14 +175,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
>                 sizeof(struct kasan_free_meta) : 0);
>  }
>
> -struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
> -                                       const void *object)
> +struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
> +                                             const void *object)
>  {
>         return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_offset;
>  }
>
> -struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
> -                                     const void *object)
> +struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
> +                                           const void *object)
>  {
>         BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
>         return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
> @@ -259,13 +259,13 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
>  void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
>                                                 const void *object)
>  {
> -       struct kasan_alloc_meta *alloc_info;
> +       struct kasan_alloc_meta *alloc_meta;
>
>         if (!(cache->flags & SLAB_KASAN))
>                 return (void *)object;
>
> -       alloc_info = get_alloc_info(cache, object);
> -       __memset(alloc_info, 0, sizeof(*alloc_info));
> +       alloc_meta = kasan_get_alloc_meta(cache, object);
> +       __memset(alloc_meta, 0, sizeof(*alloc_meta));
>
>         if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>                 object = set_tag(object, assign_tag(cache, object, true, false));
> @@ -345,7 +345,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>                 KASAN_KMALLOC_REDZONE);
>
>         if (cache->flags & SLAB_KASAN)
> -               kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> +               kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
>
>         return set_tag(object, tag);
>  }
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index e1af3b6c53b8..de6b3f03a023 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -331,7 +331,7 @@ void kasan_record_aux_stack(void *addr)
>  {
>         struct page *page = kasan_addr_to_page(addr);
>         struct kmem_cache *cache;
> -       struct kasan_alloc_meta *alloc_info;
> +       struct kasan_alloc_meta *alloc_meta;
>         void *object;
>
>         if (!(page && PageSlab(page)))
> @@ -339,13 +339,13 @@ void kasan_record_aux_stack(void *addr)
>
>         cache = page->slab_cache;
>         object = nearest_obj(cache, page, addr);
> -       alloc_info = get_alloc_info(cache, object);
> +       alloc_meta = kasan_get_alloc_meta(cache, object);
>
>         /*
>          * record the last two call_rcu() call stacks.
>          */
> -       alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
> -       alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
> +       alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
> +       alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
>  }
>
>  void kasan_set_free_info(struct kmem_cache *cache,
> @@ -353,7 +353,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
>  {
>         struct kasan_free_meta *free_meta;
>
> -       free_meta = get_free_info(cache, object);
> +       free_meta = kasan_get_free_meta(cache, object);
>         kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
>
>         /*
> @@ -367,5 +367,5 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>  {
>         if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_KMALLOC_FREETRACK)
>                 return NULL;
> -       return &get_free_info(cache, object)->free_track;
> +       return &kasan_get_free_meta(cache, object)->free_track;
>  }
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 7f0568df2a93..2a38885014e3 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -56,7 +56,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
>  {
>         struct kasan_alloc_meta *alloc_meta;
>
> -       alloc_meta = get_alloc_info(cache, object);
> +       alloc_meta = kasan_get_alloc_meta(cache, object);
>         kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
>  }
>
> @@ -65,6 +65,6 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>  {
>         struct kasan_alloc_meta *alloc_meta;
>
> -       alloc_meta = get_alloc_info(cache, object);
> +       alloc_meta = kasan_get_alloc_meta(cache, object);
>         return &alloc_meta->free_track[0];
>  }
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 5c0116c70579..456b264e5124 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -148,10 +148,10 @@ struct kasan_free_meta {
>  #endif
>  };
>
> -struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
> -                                       const void *object);
> -struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
> -                                       const void *object);
> +struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
> +                                               const void *object);
> +struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
> +                                               const void *object);
>
>  void kasan_poison_memory(const void *address, size_t size, u8 value);
>
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index a0792f0d6d0f..0da3d37e1589 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -166,7 +166,7 @@ void quarantine_put(struct kmem_cache *cache, void *object)
>         unsigned long flags;
>         struct qlist_head *q;
>         struct qlist_head temp = QLIST_INIT;
> -       struct kasan_free_meta *info = get_free_info(cache, object);
> +       struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
>
>         /*
>          * Note: irq must be disabled until after we move the batch to the
> @@ -179,7 +179,7 @@ void quarantine_put(struct kmem_cache *cache, void *object)
>         local_irq_save(flags);
>
>         q = this_cpu_ptr(&cpu_quarantine);
> -       qlist_put(q, &info->quarantine_link, cache->size);
> +       qlist_put(q, &meta->quarantine_link, cache->size);
>         if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
>                 qlist_move_all(q, &temp);
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index f8817d5685a7..dee5350b459c 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -162,12 +162,12 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
>  static void describe_object(struct kmem_cache *cache, void *object,
>                                 const void *addr, u8 tag)
>  {
> -       struct kasan_alloc_meta *alloc_info = get_alloc_info(cache, object);
> +       struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
>
>         if (cache->flags & SLAB_KASAN) {
>                 struct kasan_track *free_track;
>
> -               print_track(&alloc_info->alloc_track, "Allocated");
> +               print_track(&alloc_meta->alloc_track, "Allocated");
>                 pr_err("\n");
>                 free_track = kasan_get_free_track(cache, object, tag);
>                 if (free_track) {
> @@ -176,14 +176,14 @@ static void describe_object(struct kmem_cache *cache, void *object,
>                 }
>
>  #ifdef CONFIG_KASAN_GENERIC
> -               if (alloc_info->aux_stack[0]) {
> +               if (alloc_meta->aux_stack[0]) {
>                         pr_err("Last call_rcu():\n");
> -                       print_stack(alloc_info->aux_stack[0]);
> +                       print_stack(alloc_meta->aux_stack[0]);
>                         pr_err("\n");
>                 }
> -               if (alloc_info->aux_stack[1]) {
> +               if (alloc_meta->aux_stack[1]) {
>                         pr_err("Second to last call_rcu():\n");
> -                       print_stack(alloc_info->aux_stack[1]);
> +                       print_stack(alloc_meta->aux_stack[1]);
>                         pr_err("\n");
>                 }
>  #endif
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index aebc44a29e83..317100fd95b9 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -46,7 +46,7 @@ const char *get_bug_type(struct kasan_access_info *info)
>         if (page && PageSlab(page)) {
>                 cache = page->slab_cache;
>                 object = nearest_obj(cache, page, (void *)addr);
> -               alloc_meta = get_alloc_info(cache, object);
> +               alloc_meta = kasan_get_alloc_meta(cache, object);
>
>                 for (i = 0; i < KASAN_NR_FREE_STACKS; i++)
>                         if (alloc_meta->free_pointer_tag[i] == tag)
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index ccc35a311179..c10863a45775 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -172,7 +172,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
>         struct kasan_alloc_meta *alloc_meta;
>         u8 idx = 0;
>
> -       alloc_meta = get_alloc_info(cache, object);
> +       alloc_meta = kasan_get_alloc_meta(cache, object);
>
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>         idx = alloc_meta->free_track_idx;
> @@ -189,7 +189,7 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>         struct kasan_alloc_meta *alloc_meta;
>         int i = 0;
>
> -       alloc_meta = get_alloc_info(cache, object);
> +       alloc_meta = kasan_get_alloc_meta(cache, object);
>
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>         for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYriYDCw0_8p8gxWPLuSrv2OCZp%3DHRSM315wTTkyCkJPA%40mail.gmail.com.

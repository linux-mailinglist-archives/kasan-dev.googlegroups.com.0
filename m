Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO7RYGKQMGQESGBPMDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id A44A6551ACE
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 15:40:12 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id v18-20020acaac12000000b0032ec95c7299sf6226324oie.17
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 06:40:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655732411; cv=pass;
        d=google.com; s=arc-20160816;
        b=QBuLfszUdr2Ra0EFmwNdsq7QmalSvwc/nEyWirv8uAYnO2XGMG5jOXPBOaaD4DfwQq
         qbP/z9nmcU1xeeYHFoZ0UcTOtiCg1Lm4JLUbV0jWfEz/jyIgi/SIvc5RxT/AgOq96wrw
         yighQ1mQLp6ii6jjE11VGB1RzJb/rt6SSBNqI1LmMWDePuGh5jsmmQsDBOCyLcw0gRWv
         BKoyDHOFea1mAJn6vGHSee+Ra0q9wL8bXlEe3gcvhp67SsXlVSpqEy/N7Wp82vIoyb9U
         rFiQ+uqY9dORLkYP5/5pe2KAxVbfP+sOOEBuZVhKqxYwyX6NFXBuCSe0GwYquZtPBsqo
         VvNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PLlMK2/gURiIeFzrdeldtA6ulk7zhg2j0j5TtdQ5N4c=;
        b=kvvsOxbw0nPE5NjOSlVJ1+KqpqtzD0tyirNwAYtsZP6z2vBpcO/tjTvLl1HzuMHE/u
         846Ey5IOe/OMisr/OGXrpqlfPrhEOFjBdWKwoqC006df6LqYzK+16eo0PDbXkgEvGJ+E
         u3Dh/KUtjZK1UwspZO0MRUxWcLJepwnYGPZVpmvkyxBTExBvBBI8twgqNWfZM3rTnI1Y
         0ph3D4Ite2tL5i419sWw/xwoxzEIAxmStx2ouXQQOSQ1V8d4DXjqPpROYWqxLfRGp3tD
         JRoo/h/4HsDaqRPSq/x9QqKMt4JReO5fZNdu9VqcrKTtOgewHCnp8ER+jWNAuwojLtFv
         c4Fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FTr4DRmC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PLlMK2/gURiIeFzrdeldtA6ulk7zhg2j0j5TtdQ5N4c=;
        b=Qj15nsdhnZQbKN/HUWRx9oQB9Vm23pXgbW69c86TOExJV8Y/h6v6Lcls4rlq3m6yeK
         KLZH5zl25ak0Q5N7e0469/A5TwV60+TjpmHo1tD4SrPdUTp7cQOLm89gMXh0eqi+Cq2j
         KjHzF2ylxZO48RW1btBFg4Jb33lu65WHXblMOyYYz/vsmqttutDNKYyHyMiJxLQJ1iQp
         oRPfU7TGlWYbokcqbAGFBpEo4tMsmJxnxBlXNYYsBWWQ2tL2HexM178Km2Ju5nfAX4xC
         9Rg7iTjVJvGCNG8+DFNZxOjOZYiks+o/r1RjQHUlkrmt8moF1aiKGM9rFXhcX2u3c1M/
         weEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PLlMK2/gURiIeFzrdeldtA6ulk7zhg2j0j5TtdQ5N4c=;
        b=ZuBwrYB3BFu20TpKdEbuqbIlFxnryAlKPNwHghWI/7s94iQ8LPZ2p2JTu4RRZeS/Fm
         2bJXBlQmYo20Lh2jE0yuiLkuqnGMdg+BOVsibFrc1ZIPXincdwSgBBdstfbsghziWCr+
         o4++EyCD549y7ppjo6atnO59oQcFLSmXT2zLWtZc9FmbdWNsO5rXGKDxPBW8ihhFXCKv
         71oKW+YgktceHEj3nj44+WZN5ocDW9yw49aV81qOaRGlQkodXzfJ3LjV1AW1BhRfHCol
         /tC+IaumzVzGXU5YLMkYvcvPbt79acy/XTEGVAU36/otVBxEpXtHsI2XGpERLzzVtlDJ
         3OQw==
X-Gm-Message-State: AJIora8HqqBVmxEyrkuZVBuVVM8TUOLYqF/ATlr1YXg4tXKiqjZTh0Hz
	e5vFGC2oRlSuReowxvLCXAo=
X-Google-Smtp-Source: AGRyM1saUEokdzCAqR0y/bBJxuCCsi7SC+SMCW0qLSZCrtG0xpXjSunltPUoB+ra3pqyRQfW9/HsVw==
X-Received: by 2002:a05:6870:9122:b0:101:baca:30b9 with SMTP id o34-20020a056870912200b00101baca30b9mr7665526oae.71.1655732411355;
        Mon, 20 Jun 2022 06:40:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a9a4:b0:f2:dc5c:8024 with SMTP id
 ep36-20020a056870a9a400b000f2dc5c8024ls4125036oab.0.gmail; Mon, 20 Jun 2022
 06:40:11 -0700 (PDT)
X-Received: by 2002:a05:6870:b494:b0:101:cb67:66cf with SMTP id y20-20020a056870b49400b00101cb6766cfmr5265318oap.68.1655732410931;
        Mon, 20 Jun 2022 06:40:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655732410; cv=none;
        d=google.com; s=arc-20160816;
        b=dv2lwWUpSn1jeJrNexRkEmMQIQ/WbEp1D02ZOX36R0mi2ORczoVZkQ9AdPds3CQ/aa
         VMnAsKB3ANxc59aIAAQjmJnwBSK+YT12cmJlue5kcBGGTM+FrRoC0iJJ2zPRe3YxXa70
         1J3mLqkOt+w62cnZJsL401VQzwd5c+46HHwhB3AtiVtY0K8mNPlVof6ysuqtCZmuG4hn
         cqq2TqA+WpmE5T2VWalKOkqSt36ZWseJCDWSSOnGTxxxr8L5FnxO9T7d3azreZOQuT04
         G3Q0MifD5+NHC1qFbhf09EG3bYojQ9UF8DcolrzwZABUPLlHFp60o+yOLn9mz0aKh01w
         EuFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZIuI4RCTb90zIPiwyne5eQXzXeGLUJKIbNqh+rIdowY=;
        b=uEGBTckq074dvbFEECkFFb0PsGXmVlINiHKhHbyjiPTdjAU2WhhAZqb9Uz44SyFOU/
         RaXx0/hfsK+5OvwHl+0p0/XuKx79+cfpLsV2XHyc9v3OyH8Z0H4g/CQZxUwHiZeAfWTX
         R0+eslE7ANdcif37KTSjnWBMBJzi/aZk4b3RF15/BL1w05nanhTvZB7ZtEWJQRRJ7INq
         KZfxyjV4+MgOJjl3mXipoFc4TXOZT5qzEJnqMpMdpZNIVIxCN5cN/dxvccfhxf/ZkNVH
         FD6CkiKKycagmFJnP3hf0J5QQSg2U9ZzTWMRk9zRPM1jETMGp60gMohf102OwWfC/THO
         JLKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FTr4DRmC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id bd23-20020a056808221700b0032f15fa78efsi675071oib.4.2022.06.20.06.40.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jun 2022 06:40:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-3176d94c236so100787727b3.3
        for <kasan-dev@googlegroups.com>; Mon, 20 Jun 2022 06:40:10 -0700 (PDT)
X-Received: by 2002:a0d:f4c6:0:b0:30c:8e46:abe5 with SMTP id
 d189-20020a0df4c6000000b0030c8e46abe5mr27511237ywf.333.1655732410435; Mon, 20
 Jun 2022 06:40:10 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1655150842.git.andreyknvl@google.com> <ad7b6cfa3fbe10d2d9c4d15a9d30c2db9a41362c.1655150842.git.andreyknvl@google.com>
In-Reply-To: <ad7b6cfa3fbe10d2d9c4d15a9d30c2db9a41362c.1655150842.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jun 2022 15:39:34 +0200
Message-ID: <CANpmjNOJoR2ReowDbw5DG3i95392uiukXmVmkSKL3ORLeW_6Zg@mail.gmail.com>
Subject: Re: [PATCH 03/32] kasan: move is_kmalloc check out of save_alloc_info
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FTr4DRmC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as
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
> Move kasan_info.is_kmalloc check out of save_alloc_info().
>
> This is a preparatory change that simplifies the following patches
> in this series.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  mm/kasan/common.c | 15 +++++----------
>  1 file changed, 5 insertions(+), 10 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 753775b894b6..a6107e8375e0 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -423,15 +423,10 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
>         }
>  }
>
> -static void save_alloc_info(struct kmem_cache *cache, void *object,
> -                               gfp_t flags, bool is_kmalloc)
> +static void save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>  {
>         struct kasan_alloc_meta *alloc_meta;
>
> -       /* Don't save alloc info for kmalloc caches in kasan_slab_alloc(). */
> -       if (cache->kasan_info.is_kmalloc && !is_kmalloc)
> -               return;
> -
>         alloc_meta = kasan_get_alloc_meta(cache, object);
>         if (alloc_meta)
>                 kasan_set_track(&alloc_meta->alloc_track, flags);
> @@ -466,8 +461,8 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
>         kasan_unpoison(tagged_object, cache->object_size, init);
>
>         /* Save alloc info (if possible) for non-kmalloc() allocations. */
> -       if (kasan_stack_collection_enabled())
> -               save_alloc_info(cache, (void *)object, flags, false);
> +       if (kasan_stack_collection_enabled() && !cache->kasan_info.is_kmalloc)
> +               save_alloc_info(cache, (void *)object, flags);
>
>         return tagged_object;
>  }
> @@ -512,8 +507,8 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
>          * Save alloc info (if possible) for kmalloc() allocations.
>          * This also rewrites the alloc info when called from kasan_krealloc().
>          */
> -       if (kasan_stack_collection_enabled())
> -               save_alloc_info(cache, (void *)object, flags, true);
> +       if (kasan_stack_collection_enabled() && cache->kasan_info.is_kmalloc)
> +               save_alloc_info(cache, (void *)object, flags);
>
>         /* Keep the tag that was set by kasan_slab_alloc(). */
>         return (void *)object;
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ad7b6cfa3fbe10d2d9c4d15a9d30c2db9a41362c.1655150842.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOJoR2ReowDbw5DG3i95392uiukXmVmkSKL3ORLeW_6Zg%40mail.gmail.com.

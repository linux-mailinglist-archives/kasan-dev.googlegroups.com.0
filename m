Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSPRYGKQMGQEQC6S4SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id F2D39551AD2
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 15:40:26 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id l3-20020a056e021aa300b002d9094fb397sf2468658ilv.11
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 06:40:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655732425; cv=pass;
        d=google.com; s=arc-20160816;
        b=VxbkvvASN/Ug97jjC960KquC9ULloLH4rTnFTMwDfzvd/MoNuqC4KcG+1Agc4Z6yWR
         Hu1UthvroDIW5KJ93rRO2/MNVNT8Vc85QBbmLVg4qyldFC3RSY/NflKBqqN1XysBr6Ii
         KZzIR6P5nyZD3VBfyuaM0Kej5V8MwvjXSgjTM4Aq29F7ryVQw14Ds4vogqLCHVHNbZcZ
         9C/N6bK7Zmoe8K9qZYj+BIyW/dWCxjxvnMKRs9notQvqnsX8/U/gmGXWyzN1bmt/vrhg
         P41PXYGpOnTPHZWVpmP3WWVDv1gBV3rskM0xxLsR1FASZL2L9JTTYF3DH4qXXuP7MXXd
         tGqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VxBa8WS7r6nx8Tg4mWAaOmOPe7c91LBudUmAPlfiM/k=;
        b=tbCvCLu7bv+XyLErS2ebuX6V57DdjyfrKgPH5Dm6w1lg0Feez/J4JlgcjgBuL35jhS
         1BIn4UsBkiNc3jSsdQwlm7YAfWfK/xEr6W/MlIpM7Tp4LU7AoCyPfyWxyrZtRT/GfwuA
         Tt+tdJEYtEpSf0vGh+bSE2YnmXPSsYp5xDm1eDhtAKR26cWuWk1Ge//PMERq9rKKHtEa
         iOE3RdjnxpeZ73Mg2oIE5o097zRNskxrUr+GhP1AC3pzwjHNyPOvbrcLNR6rrzcWXP+a
         nD8rOMZO4gdOzAD/GBNrovQpeKqwRRCvTSk1NUwVGwom42KGLuMxKTxPH+fus/mT4yzZ
         Mxgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n5grsZvn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VxBa8WS7r6nx8Tg4mWAaOmOPe7c91LBudUmAPlfiM/k=;
        b=YOEGCcFJ2P2WaTHZCyxqV+aGbK4kGzE+xopRRfaHVB6Vd1USAJRXEbc+ysbD2mcOW4
         I0QoGlfM0Liobbl73zjbftUagr3Tv25Vd/8rci/QiImvyotnBBfm8Z8b1qDW41pWUpdX
         sSRIfeEPodJdxR6Hiz1/82w2etvbL0EWsvG7lN66LGM1rXLaUZ6oMfsqW4bsEFuewTEk
         8twFe8drKv/Ujtvl/xNjKY5o3YYimbRVTYSYOa3dSnvs77VWPOl7RRax7WAP0prwyFC7
         bL1Zrow3rzfuXKjMcyeMpumU9ysRtaYbqCLEL5gLGyTh7KBbh0O2o9HG+Vc7uv4srWDm
         +6Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VxBa8WS7r6nx8Tg4mWAaOmOPe7c91LBudUmAPlfiM/k=;
        b=4xu5eMHXCWrh4NMok2DdB5k/3AGKi2vjIrIxYARZ6nnDlRrK1Fu4ezcj3WwtktoRfC
         aNnK6UmTBREzXS3M05sEAHXa+Di3Rdwd97KxA8k+jXye4Lm/eyPW4q1ChQMx8Wx3NIL/
         DK2tYOlNGr2b7NFkwZQfdT6wAI8f+a6rPnciHkkpGaPyiNeikJ/+H86BwLwf1puBGwrM
         7TpBRuAb7LMomaJ2H2EQGEQJ4KpqBvUqDGdEqy1RngYDiRJ9wJ2rQMvSgvDPCpZkjAlF
         huhOQdmjCxcauJumD3+CKRCjeEDnuBs8bQRyFoX/H8JduWdWFH6rkGA9o/FnYHGzA6HS
         z/XA==
X-Gm-Message-State: AJIora+m/O7u4/EDqz9hVrp3yHlTHY1pHqdrUsNxBb4b6bgF5fSlaC2j
	2N1xSWTP7XCuqhAVx5XlDXw=
X-Google-Smtp-Source: AGRyM1tXi2rVFgqNvuVCW1rzJ8TPEFHcMdp4nCy3G1l6llXCSkniVRwPqnyeoM3fPO5H43qK+IgnJQ==
X-Received: by 2002:a05:6638:1508:b0:331:f6e2:f82b with SMTP id b8-20020a056638150800b00331f6e2f82bmr13286346jat.279.1655732425613;
        Mon, 20 Jun 2022 06:40:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:4808:b0:331:a24a:b90a with SMTP id
 cp8-20020a056638480800b00331a24ab90als1892082jab.3.gmail; Mon, 20 Jun 2022
 06:40:25 -0700 (PDT)
X-Received: by 2002:a05:6638:14c3:b0:331:8153:e5b with SMTP id l3-20020a05663814c300b0033181530e5bmr13037798jak.114.1655732425171;
        Mon, 20 Jun 2022 06:40:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655732425; cv=none;
        d=google.com; s=arc-20160816;
        b=rvKSTfDQTjg/mzXvHTmmyxzhnZ9xs1GW2MWCaJWXNl9Hi4j9JnkhDr3mQ+1Mr//tvC
         rd6y+J6iJJ2lMPziQA6BcXWUkzI0U8uuIb+Y2Qs2zt1xAZCXDKUW3uEIgNCjoKmKsuVU
         tgDeC6rKJbai3giwpBMpyySg+DlGH1Y3DfeBkorRdJp7gF7HMGNTK43mTvYXU0SnwYpu
         3Ip754uj+AEqrILF4sU7OOuiRf3KzHvODXHg2gxydDgU3wSKlfG+5UIn1POhvYRis6TB
         7ATgZu4FDaeF1Jeiu1S+oDbGQLqq1EGaCqjoQXRsTtlXOjS5Vc3VCfkOsf9UR8C4gT2C
         uvuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qC8/39KyiVmkl5BIZHurMzBUhpZZ/2u2VsK+Aq1J8ck=;
        b=CYAgD58Lyb5R9RH4F3RrQPAve84mvw+aflofT0a24zvpBo0DxQxuKZJN7In2gh3gsh
         GlvQK5QhoEV0y0gClszqqztCAUNUGOunXcZZLjNYlulTntuxdAH9L5Ez2t9K0hxgCT5P
         /unYs6KRFf9GCj0E27i3Npvm9LvhfA/NxQh+41QEE7GvUFUu1TDLOep5/WSi3YDiYnpb
         vwvbtjYLm9omaQsilUrqPQL007uzv8CZkvVmLL5JdCCLBbAQRnftYHb1m8DHHfaznX39
         WlGoQxeualy2A0WxCYlmtYbQlgW+luyuMd8vSiod0FP3qv75J5ULkMGfQPgrAYlO9lHO
         R7SQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n5grsZvn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id q10-20020a056e02078a00b002d3b0cebdc3si618924ils.2.2022.06.20.06.40.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jun 2022 06:40:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id e4so6371396ybq.7
        for <kasan-dev@googlegroups.com>; Mon, 20 Jun 2022 06:40:25 -0700 (PDT)
X-Received: by 2002:a25:1583:0:b0:668:e74a:995f with SMTP id
 125-20020a251583000000b00668e74a995fmr11104743ybv.1.1655732424678; Mon, 20
 Jun 2022 06:40:24 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1655150842.git.andreyknvl@google.com> <8d1cf94238a325e441f684cbdbb2a1da0db78add.1655150842.git.andreyknvl@google.com>
In-Reply-To: <8d1cf94238a325e441f684cbdbb2a1da0db78add.1655150842.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jun 2022 15:39:48 +0200
Message-ID: <CANpmjNO_DqF+=HMQ+j9uL7qeO4a7FGy1Vuzs=pHhpQVC_is9Pw@mail.gmail.com>
Subject: Re: [PATCH 08/32] kasan: introduce kasan_init_object_meta
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=n5grsZvn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as
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

On Mon, 13 Jun 2022 at 22:16, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Add a kasan_init_object_meta() helper that initializes metadata for a slab
> object and use it in the common code.
>
> For now, the implementations of this helper are the same for the Generic
> and tag-based modes, but they will diverge later in the series.
>
> This change hides references to alloc_meta from the common code. This is
> desired as only the Generic mode will be using per-object metadata after
> this series.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  mm/kasan/common.c  | 10 +++-------
>  mm/kasan/generic.c |  9 +++++++++
>  mm/kasan/kasan.h   |  2 ++
>  mm/kasan/tags.c    |  9 +++++++++
>  4 files changed, 23 insertions(+), 7 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2848c7a2402a..f0ee1c1b4b3c 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -312,13 +312,9 @@ static inline u8 assign_tag(struct kmem_cache *cache,
>  void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
>                                                 const void *object)
>  {
> -       struct kasan_alloc_meta *alloc_meta;
> -
> -       if (kasan_stack_collection_enabled()) {
> -               alloc_meta = kasan_get_alloc_meta(cache, object);
> -               if (alloc_meta)
> -                       __memset(alloc_meta, 0, sizeof(*alloc_meta));
> -       }
> +       /* Initialize per-object metadata if it is present. */
> +       if (kasan_stack_collection_enabled())
> +               kasan_init_object_meta(cache, object);
>
>         /* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
>         object = set_tag(object, assign_tag(cache, object, true));
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index f212b9ae57b5..5462ddbc21e6 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -328,6 +328,15 @@ DEFINE_ASAN_SET_SHADOW(f3);
>  DEFINE_ASAN_SET_SHADOW(f5);
>  DEFINE_ASAN_SET_SHADOW(f8);
>
> +void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +
> +       alloc_meta = kasan_get_alloc_meta(cache, object);
> +       if (alloc_meta)
> +               __memset(alloc_meta, 0, sizeof(*alloc_meta));
> +}
> +
>  static void __kasan_record_aux_stack(void *addr, bool can_alloc)
>  {
>         struct slab *slab = kasan_addr_to_slab(addr);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 4005da62a1e1..751c3b17749a 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -278,6 +278,8 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
>  struct page *kasan_addr_to_page(const void *addr);
>  struct slab *kasan_addr_to_slab(const void *addr);
>
> +void kasan_init_object_meta(struct kmem_cache *cache, const void *object);
> +
>  depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
>  void kasan_set_track(struct kasan_track *track, gfp_t flags);
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 7b1fc8e7c99c..2e200969a4b8 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -17,6 +17,15 @@
>
>  #include "kasan.h"
>
> +void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +
> +       alloc_meta = kasan_get_alloc_meta(cache, object);
> +       if (alloc_meta)
> +               __memset(alloc_meta, 0, sizeof(*alloc_meta));
> +}
> +
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>  {
>         struct kasan_alloc_meta *alloc_meta;
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8d1cf94238a325e441f684cbdbb2a1da0db78add.1655150842.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO_DqF%2B%3DHMQ%2Bj9uL7qeO4a7FGy1Vuzs%3DpHhpQVC_is9Pw%40mail.gmail.com.

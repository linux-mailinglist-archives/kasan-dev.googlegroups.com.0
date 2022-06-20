Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRXRYGKQMGQE6JAADAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BD9B551AD1
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 15:40:23 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-101bc088474sf4922577fac.18
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 06:40:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655732422; cv=pass;
        d=google.com; s=arc-20160816;
        b=zAJ/86iKKWpUcWJ7Re/yxwGNSRJg9D7BXACiQENpzs/pBhZRFATDUvBlr89VokmKaZ
         iuLSouf/2Mp+9g+KR90MmouvijF555O4wEdWTwMLSYNorSu1uxpx1n3il8G35X/Y6bU/
         G7vWaXMuOMBCuSzZvs9lEjn77oKdMPjomvbhgPtO4QU1Ei3SrNo2M3wKDMVDnfJcg85s
         yWhlcKt4wOgwllsbe/K3E7yGv83GZfbVuQC/voHXp50Ck+AGIFsnbIE5PLQE/KFGTKrH
         N93dl7y8sbK5bkhGncUqDm+CKrljF2fh3weBguY17riVRxH8KfV6xlYtuTrd77AWvK0D
         99rA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VQtvqEB2nd6ZuOlGq4I7NmDcGKvGa+l+zpVDof3+No8=;
        b=QHZFgpNsSKhno6Js6ZZ/KwB/5yqHxuj1XS6m1ljmNGIduIeNG/5+bl8WV++gBzjI0H
         88iVw2xmoPtkGoIPhk3YbWs5VruYLazo6p9wvrx25ijDShQIwPyJv1N6P0zRMz2r2oji
         UrlvOZtsAMeUobA3pmR40llzi5MFh9P1fBmQvdDHaq2+S+z3mllRNNcTHDi6h6dE/G1i
         u2PFgPROyV0X1CR1RkIDbm0KdlSmZJOcXiclw4xPBRoFcndmq9XGANMdgAIpK7cDy+kk
         RUCVeM8WC1P/yi3rr3tCqFKR3R54oaSWDFsWn24Rd/m1soea4UkObgrcowDGA7O3qAzM
         b5qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eQi9zaET;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VQtvqEB2nd6ZuOlGq4I7NmDcGKvGa+l+zpVDof3+No8=;
        b=Edp1nPn4V0xeJNsX0YHgFRxmIbxJdCusgxAIU3O8+rfv3sgchTb2Phby/dFp5Ox2GJ
         oHEkU4duhgWJzGoY1I/B4oQDRpiSgO/hTrCJbMTfHKtlWxVKfOvpJgvik3gLWL3QTamv
         o076EeoQxcQQWTOKwcWS7O/D8p8Q0O0PJCJowbxgj/+3DxOUTNlAPoLG4yTYLk1iDBz+
         jbpSKOU5D53L+ZWkLXkkYcGFHnKJ44HRPPKn1Y/jpBhHRgBPU6jWY0p+oXkXd2BLeNIT
         EYDiNZ1Qpd69eRyMwx405tWwJHPkgen20tgomYBd5l0cjV2HvZoo4T3/7mIdRzQCsB1n
         OdXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VQtvqEB2nd6ZuOlGq4I7NmDcGKvGa+l+zpVDof3+No8=;
        b=iu0AqyARSNcOlcKSy2EjVndtqzDEus0/GnII1AQeVk88AL75vl6nqU2MZ5shGUs1W+
         ZZ1ncPuuAhdaWNiPfgoHpXdnuTPc2ymhOrFKXzO4BQ/io5TADrVT14Q1DbJNrwY5/Z8r
         EUkMjVkHB0zx+uc/k0svrTprsN9OflgfbQrx/+BrY2f7lB+moGPvUgbPwyHh87i/OXzk
         DSjjy24GCE0nCHPgv3sGB/pJoPbYY1f7s47sr+1b6m6d9EL1Bl1MssfAmxOiuLI1M3G2
         /VBYRKzIBJRww91jjlELwz12IFE+vpf1wgPQyKN3SFgkvvwzlg4lPw0ZrB7SzJJ2YdQf
         J8rQ==
X-Gm-Message-State: AJIora8Dktvt9GIbAvp4QIXBPbk8a4bv4Z9TekIf2W8XirpD8k5yNZbY
	PTnV0QUV/5dg1WSgdDHdXSk=
X-Google-Smtp-Source: AGRyM1vA6X+z9RMUdE+IFzCVzOPttaPDoaSM3AEdWBH8C7nF3PnPwB87wxeSMSizpl09ZLDz5rhM5A==
X-Received: by 2002:a05:6870:c890:b0:fe:5223:29f0 with SMTP id er16-20020a056870c89000b000fe522329f0mr18728447oab.6.1655732422608;
        Mon, 20 Jun 2022 06:40:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1898:b0:32f:7913:80c8 with SMTP id
 bi24-20020a056808189800b0032f791380c8ls3859437oib.10.gmail; Mon, 20 Jun 2022
 06:40:22 -0700 (PDT)
X-Received: by 2002:aca:2306:0:b0:32e:d234:30f0 with SMTP id e6-20020aca2306000000b0032ed23430f0mr16898172oie.6.1655732422202;
        Mon, 20 Jun 2022 06:40:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655732422; cv=none;
        d=google.com; s=arc-20160816;
        b=g/PFGQNxWXQ7DWkJhdF48ITzOKvA4UygCI4chwxOD9GlnwMjlk6qrv8T3jtA4AtPPA
         G54rEFzQ2fd4tRedw4dsUrDezQE3ByXQ5E0cUDyn71+xaG3Ez2f5iXDw0obsGo6kCFsw
         QZnO8NglDiz0kUDOaiLkS+i1oNMPySG27C/tMft9dYbnscOnzstJA8VlqWLyUSJ8jf4I
         C/hp+HZ9uOt50KxzfqhxC5VVKw1DvYyh6Uvmbzgni02U2i4sNAoBNCHRl31nb8x1f5H8
         3mEy3NNZJ60ozViRksjDikNDdNzZ8S1Ct/2sZhxMVeUdInV8sk9RMIPwFOZT8G6K4vdv
         7pPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G3ftVDEg1TDDghcSSxJkEC5/y2JJbqzI/pYg/LWTE5M=;
        b=HaMBfxuuXcgnoWJzwTAyxt0jcWekh8Zf19cY1itMROFVky2wo+oJyywyzWwA5usLCM
         sESMEqgHMBOVGFymy6g0UUWZkX3hhIhS2xGZfchTBEkvK7W+XrfZ3QDYeWz+sslfElML
         5Z3cDpUMg41k9nyrjayQ4cP4UtLZ0LkitUT8xBkb047t1KhWbRwGdzsL/qsLMwdc1aCn
         bdxRtVJar13b7wCzLkGmW91QchT2Dh8yKff2O5KLLPDuaYvQ8dtYXU6ZOXjXoaLKD6PJ
         6v63NgkFmzpN9rtbn7HyzLa8JdwoBq5a+ii1G8uWByW6bIBQGKTBQfSbmRhuTvg35VxY
         UZdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eQi9zaET;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id bd23-20020a056808221700b0032f15fa78efsi675071oib.4.2022.06.20.06.40.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jun 2022 06:40:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-3176d94c236so100787727b3.3
        for <kasan-dev@googlegroups.com>; Mon, 20 Jun 2022 06:40:22 -0700 (PDT)
X-Received: by 2002:a81:3a12:0:b0:314:6097:b801 with SMTP id
 h18-20020a813a12000000b003146097b801mr27848775ywa.512.1655732421684; Mon, 20
 Jun 2022 06:40:21 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1655150842.git.andreyknvl@google.com> <184ac9df81406e73611e1f639c5d4d09f8d7693a.1655150842.git.andreyknvl@google.com>
In-Reply-To: <184ac9df81406e73611e1f639c5d4d09f8d7693a.1655150842.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jun 2022 15:39:45 +0200
Message-ID: <CANpmjNM63AQK71Nd2UQ2VNFDQfog9rMScdG2FatgHnGVX4F+gQ@mail.gmail.com>
Subject: Re: [PATCH 07/32] kasan: introduce kasan_get_alloc_track
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=eQi9zaET;       spf=pass
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

On Mon, 13 Jun 2022 at 22:16, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Add a kasan_get_alloc_track() helper that fetches alloc_track for a slab
> object and use this helper in the common reporting code.
>
> For now, the implementations of this helper are the same for the Generic
> and tag-based modes, but they will diverge later in the series.
>
> This change hides references to alloc_meta from the common reporting code.
> This is desired as only the Generic mode will be using per-object metadata
> after this series.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  mm/kasan/generic.c | 14 +++++++++++++-
>  mm/kasan/kasan.h   |  4 +++-
>  mm/kasan/report.c  |  8 ++++----
>  mm/kasan/tags.c    | 14 +++++++++++++-
>  4 files changed, 33 insertions(+), 7 deletions(-)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 98c451a3b01f..f212b9ae57b5 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -381,8 +381,20 @@ void kasan_save_free_info(struct kmem_cache *cache,
>         *(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREETRACK;
>  }
>
> +struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
> +                                               void *object)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +
> +       alloc_meta = kasan_get_alloc_meta(cache, object);
> +       if (!alloc_meta)
> +               return NULL;
> +
> +       return &alloc_meta->alloc_track;
> +}
> +
>  struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> -                               void *object, u8 tag)
> +                                               void *object, u8 tag)
>  {
>         if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREETRACK)
>                 return NULL;
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index bcea5ed15631..4005da62a1e1 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -282,8 +282,10 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
>  void kasan_set_track(struct kasan_track *track, gfp_t flags);
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
>  void kasan_save_free_info(struct kmem_cache *cache, void *object, u8 tag);
> +struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
> +                                               void *object);
>  struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> -                               void *object, u8 tag);
> +                                               void *object, u8 tag);
>
>  #if defined(CONFIG_KASAN_GENERIC) && \
>         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 35dd8aeb115c..f951fd39db74 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -251,12 +251,12 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
>  static void describe_object_stacks(struct kmem_cache *cache, void *object,
>                                         const void *addr, u8 tag)
>  {
> -       struct kasan_alloc_meta *alloc_meta;
> +       struct kasan_track *alloc_track;
>         struct kasan_track *free_track;
>
> -       alloc_meta = kasan_get_alloc_meta(cache, object);
> -       if (alloc_meta) {
> -               print_track(&alloc_meta->alloc_track, "Allocated");
> +       alloc_track = kasan_get_alloc_track(cache, object);
> +       if (alloc_track) {
> +               print_track(alloc_track, "Allocated");
>                 pr_err("\n");
>         }
>
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index e0e5de8ce834..7b1fc8e7c99c 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -38,8 +38,20 @@ void kasan_save_free_info(struct kmem_cache *cache,
>         kasan_set_track(&alloc_meta->free_track, GFP_NOWAIT);
>  }
>
> +struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
> +                                               void *object)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +
> +       alloc_meta = kasan_get_alloc_meta(cache, object);
> +       if (!alloc_meta)
> +               return NULL;
> +
> +       return &alloc_meta->alloc_track;
> +}
> +
>  struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> -                               void *object, u8 tag)
> +                                               void *object, u8 tag)
>  {
>         struct kasan_alloc_meta *alloc_meta;
>
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/184ac9df81406e73611e1f639c5d4d09f8d7693a.1655150842.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM63AQK71Nd2UQ2VNFDQfog9rMScdG2FatgHnGVX4F%2BgQ%40mail.gmail.com.

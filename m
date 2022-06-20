Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTPRYGKQMGQEGF72M5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 633B2551AD3
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 15:40:30 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id q126-20020aca5c84000000b0032ebb50e698sf6240205oib.11
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 06:40:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655732429; cv=pass;
        d=google.com; s=arc-20160816;
        b=a+Bktm5g/tMgk0LsOI+ycdHU5orMm/rbzh+waeSygRZAjoS87CBpJj2FPynKAAKvph
         4RMGa88ijff7UShfYM/L+SR/nVTCpUMozTI70QGbYTHonJxabFvVMyB68Zvlve/gQh5G
         jNieLKrjuSJMImQmSXxJTaDLlT47l5HDo0ZjN6W1RuX6/C7WzeUMyPauL3JSVbcThVLy
         L72DMPJa+yvQnGUf563hj5hkt+Tj4wP5cQfOYUD7S2sFex+5Xm6p07P/Va4sIvaU7H4X
         CkLY1/OJo2LmcOdmv3KnpUoFAeFlhB3hPLn042v+SFfVMffXLVOn0O5THSdN0++waVaI
         KgiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hmv0ExsyKYU+TU3qwTDfQuuF7gBJU5Wp6gpfGgaxuqE=;
        b=kyu/IO7D0gm/eduZkms+/S035CmIp31810wOLLL0NVhEBrRy9logG1B232u8vl0xo5
         sjezvWIt4Dz0rY5zV3ZDskmyb0o1FH6AsT353jWYsB6bl0vO5EBlmyWr+O/bCOBPPZKX
         iC54nEqQAmEk1h4wEmw2YsiksG2bBSpbDI+Xr/9qIAXPKUmGbhDMBCkBNuDPOhFU4tQx
         FZ41SsLcgFd7sE9gyJjUeSuDGY+u1Ibo1FqU8GJRXL+arjWOqvUTaKMLBdqVgj9Ljtc1
         2QGBAWNcBibp9F/PexoTmBzDSAFr3urZ8n7t3wSFmlM3Ux/5fr7BlsXITvLSfKqS+c+t
         Yb2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cAFK183y;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hmv0ExsyKYU+TU3qwTDfQuuF7gBJU5Wp6gpfGgaxuqE=;
        b=RB+AV4fIoDjBV3+IenUD+E14Agh8A9nbSeEsS/+zoPS1gdTssEQ74ko2lFcET7N5bH
         5siNwa6gVOjN7UFGl5v19RKKKTLcbtE8Q0/wXYRm3kUtYlhyQ8LSYaZs1g+cdJQJyZSv
         LpyEFtscWiIfWYPspo9JMYOX0JG/OgRPunnjmupIuq2FBz2LS2YP7zshON+10hoODZv8
         pModZWzbrlWb0o86tIF+Iq9gh7a1zdNkJfkIDH2AW9YxVWY0AlYJpHUo19tzh7IZS1MP
         5qLa0F6rK7XqCPrU+iXFYym02Em57h0hWif1ktQgo7EMio4K8dP6nE8nCngUgdZYYMTA
         pJFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hmv0ExsyKYU+TU3qwTDfQuuF7gBJU5Wp6gpfGgaxuqE=;
        b=bMPLiY+ugWhO/3D1o6mlkWmLDNYLptAOOeiCHxDMIjfYFeNfn//7scMGExXiY+xnaa
         SZzVs5M+Dy+p+q5qTgyRwnH1HQdwMIaS1002O2By5kAGOCBOGNXF6cYp6pMXTi/Bopde
         Qd9MYY8AT044MgKgHp/07Yhj2uXEUc4Z+HGjMPNJpVnOMrwqsyGgcTJqKK5H/b2NqCSq
         abIFoNyRpdG64C1qRVc2Q8m6fGjqTrjvqMxJ91rW8K3EbK3G6RFwuO8aybLK+Yjk2s9w
         zQVEz4FzTNcA3fGekYmCyiXL+pPU3SFv4nI1Ug8kXA0U7N7f09APOzZ4jyvIUCmQYMcp
         MQSw==
X-Gm-Message-State: AJIora/MtzbK7AA6zWE1phrKLY5oaJm7G1+L4ISYuafBlO6byJSscGj/
	03IFknEcGxUWN/xiZT1rvZM=
X-Google-Smtp-Source: AGRyM1ucW85XRnyivo30imoVeCcR12nIWRV8UJn4Gliki/AmNxCGJ7tkEvr0fJizGnGWGLAmwK6SoA==
X-Received: by 2002:a05:6870:eaa9:b0:101:325b:b5ca with SMTP id s41-20020a056870eaa900b00101325bb5camr17903849oap.7.1655732429338;
        Mon, 20 Jun 2022 06:40:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:179e:b0:332:6558:29 with SMTP id
 bg30-20020a056808179e00b0033265580029ls2482996oib.1.gmail; Mon, 20 Jun 2022
 06:40:28 -0700 (PDT)
X-Received: by 2002:a05:6808:124a:b0:32c:45f0:5011 with SMTP id o10-20020a056808124a00b0032c45f05011mr11175244oiv.217.1655732428902;
        Mon, 20 Jun 2022 06:40:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655732428; cv=none;
        d=google.com; s=arc-20160816;
        b=FQNWj1sDrwol9BSTGN5QQHLfwUIocpjNW9kfISdIZ0D9wk0Ow7nZX9/728C4ca4qNw
         LPnamxm75eGTGQ5Edbeq1Gsw5+5rbm7pFSfWkWHb4O2DtUYPtzCegiHGXvunlG45mtR4
         E0fK2Bw2KfMEcvY75VLZ9j7rMS3hG9QmDD1SIMvYbQal2NjM+JZ/IfRmc5EjoX0jtvUJ
         ZpQ5Y8db75crBoNEOX5KQv6N7diEk1fXtOuhgQzeFPodLEdCWKS6EnyYtVZ4CRjwvH6z
         1IMIDlEXCRXafCwkacI1Aa9OHX1z+S05D9neQlEhchG0IB172QFvUqDwpiXMrhxC6/9t
         ywLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=noyHdIdjcWgOmBONcZA8+AUOpZ6dpWhX/KlWjxQGveQ=;
        b=kdJIxsXZF8YxS6bCu9AJuvVUj03dm3RczwZtw3aeP3VepjCaMyVAtrHBZGQnoqpLnD
         CsCtrbRfQJsRjjwnGeua/YVyW2XPQyN6H1S7apxz8t3swl4r8HfZNiCWie3HOjXL5oE9
         D6xtUT05QWdKJS5kPgyt7wcGaInMMmfpQP5BvjGRMjIN7y7DjnX8iTQotox/mY4w45UQ
         cIIecbAeqgPYRfbn/K0RZ2vlepoQfbUTnXjcmHm8rftw29anpEk6zNuTNzZGqajjVCxW
         3szlAwjkbe3jxUbG1q4dF+0EtmWVmTsm0izSsiRfYRnHxAr4LXKAYcSClyVzBoh/WZWv
         1s7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cAFK183y;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id bd23-20020a056808221700b0032f15fa78efsi675071oib.4.2022.06.20.06.40.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jun 2022 06:40:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-3176d94c236so100787727b3.3
        for <kasan-dev@googlegroups.com>; Mon, 20 Jun 2022 06:40:28 -0700 (PDT)
X-Received: by 2002:a81:1591:0:b0:317:bb1f:fb83 with SMTP id
 139-20020a811591000000b00317bb1ffb83mr8126761ywv.362.1655732428401; Mon, 20
 Jun 2022 06:40:28 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1655150842.git.andreyknvl@google.com> <db6ce7b46d47aa26056e9eae5c2aa49a3160a566.1655150842.git.andreyknvl@google.com>
In-Reply-To: <db6ce7b46d47aa26056e9eae5c2aa49a3160a566.1655150842.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jun 2022 15:39:52 +0200
Message-ID: <CANpmjNOhyoQH0_RiWa+hGqsXq1kR06n+A1aoFL4YhZ9LsVbawA@mail.gmail.com>
Subject: Re: [PATCH 09/32] kasan: clear metadata functions for tag-based modes
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=cAFK183y;       spf=pass
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
> Remove implementations of the metadata-related functions for the tag-based
> modes.
>
> The following patches in the series will provide alternative
> implementations.
>
> As of this patch, the tag-based modes no longer collect alloc and free
> stack traces. This functionality will be restored later in the series.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  mm/kasan/tags.c | 33 ++-------------------------------
>  1 file changed, 2 insertions(+), 31 deletions(-)
>
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 2e200969a4b8..f11c89505c77 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -19,54 +19,25 @@
>
>  void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
>  {
> -       struct kasan_alloc_meta *alloc_meta;
> -
> -       alloc_meta = kasan_get_alloc_meta(cache, object);
> -       if (alloc_meta)
> -               __memset(alloc_meta, 0, sizeof(*alloc_meta));
>  }
>
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>  {
> -       struct kasan_alloc_meta *alloc_meta;
> -
> -       alloc_meta = kasan_get_alloc_meta(cache, object);
> -       if (alloc_meta)
> -               kasan_set_track(&alloc_meta->alloc_track, flags);
>  }
>
>  void kasan_save_free_info(struct kmem_cache *cache,
>                                 void *object, u8 tag)
>  {
> -       struct kasan_alloc_meta *alloc_meta;
> -
> -       alloc_meta = kasan_get_alloc_meta(cache, object);
> -       if (!alloc_meta)
> -               return;
> -
> -       kasan_set_track(&alloc_meta->free_track, GFP_NOWAIT);
>  }
>
>  struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
>                                                 void *object)
>  {
> -       struct kasan_alloc_meta *alloc_meta;
> -
> -       alloc_meta = kasan_get_alloc_meta(cache, object);
> -       if (!alloc_meta)
> -               return NULL;
> -
> -       return &alloc_meta->alloc_track;
> +       return NULL;
>  }
>
>  struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>                                                 void *object, u8 tag)
>  {
> -       struct kasan_alloc_meta *alloc_meta;
> -
> -       alloc_meta = kasan_get_alloc_meta(cache, object);
> -       if (!alloc_meta)
> -               return NULL;
> -
> -       return &alloc_meta->free_track;
> +       return NULL;
>  }
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/db6ce7b46d47aa26056e9eae5c2aa49a3160a566.1655150842.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOhyoQH0_RiWa%2BhGqsXq1kR06n%2BA1aoFL4YhZ9LsVbawA%40mail.gmail.com.

Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUPQQKHAMGQEVTIWPIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E24D47B1D7
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 18:07:30 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id z16-20020a056830129000b0055c7b3ceaf5sf3520744otp.8
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 09:07:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640020049; cv=pass;
        d=google.com; s=arc-20160816;
        b=VdVBB+Nv7cEG11GZzAqyhu+cqZoWpDYLyRQKUVXm245MXAKXhKF5PzmamRJuDj0Lcp
         uzYgtiqLvoG55IfvpUD52L8/Wg4vvUPnlL1Nvpv4eQsxxS/5I45U/ZMk6BeHWYP3Hd7K
         VnPhwJ1khPJSaI2yseQE5VdFPMCnVHdB8nC307oompzBkjRDA3BkZ7JB+adQD1p0k+XO
         /AfKxr5XGTE1MISjnoIptHnJAoghux/wyqhhHE6o8D3+askhTMrC98yGOtHMDvGDGbZn
         d/9XwfrijHyw4vhREryF2Ifh80j7QrDxFrp+Aa2aEp92EiVDt/YYMajmFLsZj2diR5aY
         hm0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WSD3bWJs/tPrL23Rgkjt5SLznqh88y36vZlPpd1AL4g=;
        b=gyd2Z+wx7qahCGyKEAoWFAAWu8N8EcYpTaguKXi8c2GpmCEjruJgxxGLKUnb+Nt45P
         tAWkEtOLHdoRvW5/HLX9GRkyIRO55lX4H/0wBLR68uYvlqJpyjifXh1BH+LNXOVRV2PW
         C0xKhh56BqC5SZK9oBkGlWCBm4KtASZPUiWYtkRfqiGGRBoodchu2CsDTNhNU1B8pynX
         osZrc7twitSEt5nipIJhs1/RUzLxFlmPu3kC28B6UycpNQsuMaYdfLBMiKIGvAMqF/PS
         xEGDa0RHwEkYTg0RKKkKIyV8KkKzMAFK8TwaarUPrEG60FFIClLCQ956jeLFpEvNq596
         YY4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DbzOy6XX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WSD3bWJs/tPrL23Rgkjt5SLznqh88y36vZlPpd1AL4g=;
        b=lfC/LAKKDNBmhtkWPfvymfamnhW/XkSAODRNUlENI480ddMsJqlXLcjxBmxuLjDAZf
         RvZ+PMoTt/t/gm6LvqxNfws2dYqH/MGgKQ92wNXwlIC7QJG9r5PfgoUD7YYsmls4OymW
         7dcCBQjeBJJlQcN9gPKrg4ycAlC5pMfBiCVn68pG75OuqREY9QXMZL1W/YAYBlFycX1x
         pqlzByUpVqBk8T3iIJD4+y0xsV5QU7kaMTMZ4EiQpIjkJ203JtxAjaF4aBy0Bp85X/ft
         MgCKMe8BuVChB35KR1KuW5SgKyY+9CvgfJYa/LDaoNLAYdGwJzcI5LZFLNEzMkZsvwap
         h0Xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WSD3bWJs/tPrL23Rgkjt5SLznqh88y36vZlPpd1AL4g=;
        b=1jChZjbm6mDMnF+J3jCzMVK5gbfue2MGD6uiPMksdkqkEO9VZ0pGjQYVFeOZH8oM4a
         n8ng1RTjWz9wQgXCg2Scz6RUf+e0SYNPPZZLXE+MamE+8PoCN0FlE5rumhyzdq2mqX2C
         W+xOXifGZc/rkA+kLR4XoGl36KjHc7Yn5qwOehgQYgE11VVbMDqDf5YMwKwo3qJsQM5e
         lzzUArs35rPgRVF3UXyUv0L5h4h9Y5RjLhzn5hwE27tdzsqqtPaSXAEZNFLI8tEaeLF3
         EcGciwT8eU1vAMIhGk9e5PVgEJ0lUN8FeqO7yJcRXAzBh2SIXDF/3KP1ZMuN3B42C+mg
         RHUQ==
X-Gm-Message-State: AOAM531YYTgfhsORA67fgRZzrYMviiOhcEv2Eo1N1EozVx7BY7nHD2WL
	egnVoH45h0Gtx3TcCwSmU14=
X-Google-Smtp-Source: ABdhPJyozQQtkpkKsxe/L4Yd2cPlQzn75CQ6DxLeXvFetw9SbEcPwYF5pibTXAfqhetIEIDVwolzRQ==
X-Received: by 2002:a05:6830:34a0:: with SMTP id c32mr12677034otu.379.1640020049138;
        Mon, 20 Dec 2021 09:07:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:1107:: with SMTP id 7ls911172ooc.5.gmail; Mon, 20 Dec
 2021 09:07:28 -0800 (PST)
X-Received: by 2002:a4a:5a43:: with SMTP id v64mr10897052ooa.26.1640020048741;
        Mon, 20 Dec 2021 09:07:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640020048; cv=none;
        d=google.com; s=arc-20160816;
        b=E/qVvLW4rWPeLJKjdBEjLM3kG0MqPW6MfrBQu4JtGE1bPxETQtSM7EgvQwNYtMQVVy
         RcvrYG1AGHAmYWWCBxTS3DqSkATmg1ol4EXsFcggnPCyZKcNWCr/6xbhfCRETSzE18eE
         OUDU0jaRr4CaUnQtAKotYey4eYngjVeHHl8SNEdQNeRABhwGNZD3PxngXTWB9zS0sufL
         EQWBSFDg0JN+cCVmWFCY68vJCdpfjQ6969+PYU+4ZUmKyKkVamPThWspIRXNvBFFc4R1
         RBtpj8Yy8YgjKe0iq92ejlou0Lx7kkTNmCk0bALSYLQqQPvbF40bZ2VLbr1S3FCqDfZl
         QOZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=l2fOqYYhEHrIQH3EGI+nA0MRIDmpXYHQDdPKYEFCJPU=;
        b=a7El4j2Jl8/HGAAisHSgXV91AIvpXCY9w7V7UaKOYgBhCaWgGOIDWLVztdsBNNX4jo
         3BU8pWh1iEBBLlBSmpTaUCNbwPq7SW7ZiNUit8LVsaWKDquKZW3qHLtyMFIikV1LBJ1y
         wvwH7nUPnKdnFXjk/3HXR1BXnnDOIX6QAU/5iXcStnPO4cyq5PMD0Vj3Kg1mBv+SZeuB
         uKAnypZwFi+8WcImGVdMaPNIS9q8xbX7LGnffBalosvDjmz/SijE46gPJyf7SIz3u/Dv
         Qte9O+4Z992Q3rDRv+PEqP6YOrudnSgFBnh8mW9XJ1pZKDUhNdjim/r8xi9RPzqXHne0
         l/UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DbzOy6XX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22b.google.com (mail-oi1-x22b.google.com. [2607:f8b0:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id ay24si1389274oob.1.2021.12.20.09.07.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Dec 2021 09:07:28 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) client-ip=2607:f8b0:4864:20::22b;
Received: by mail-oi1-x22b.google.com with SMTP id t23so16743391oiw.3
        for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 09:07:28 -0800 (PST)
X-Received: by 2002:a05:6808:118c:: with SMTP id j12mr12803071oil.65.1640020048260;
 Mon, 20 Dec 2021 09:07:28 -0800 (PST)
MIME-Version: 1.0
References: <a746b5baebbf79f8160c1fe09d6f8a5ab7bde1d7.1640017993.git.andreyknvl@google.com>
In-Reply-To: <a746b5baebbf79f8160c1fe09d6f8a5ab7bde1d7.1640017993.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Dec 2021 18:07:17 +0100
Message-ID: <CANpmjNP11JKCEE328XomcReP7uBwZ=da=SD5OS09N4co-WPhMQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix quarantine conflicting with init_on_free
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DbzOy6XX;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as
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

On Mon, 20 Dec 2021 at 17:37, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> KASAN's quarantine might save its metadata inside freed objects. As
> this happens after the memory is zeroed by the slab allocator when
> init_on_free is enabled, the memory coming out of quarantine is not
> properly zeroed.
>
> This causes lib/test_meminit.c tests to fail with Generic KASAN.
>
> Zero the metadata when the object is removed from quarantine.
>
> Fixes: 6471384af2a6 ("mm: security: introduce init_on_alloc=1 and init_on_free=1 boot options")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/kasan/quarantine.c | 11 +++++++++++
>  1 file changed, 11 insertions(+)
>
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 587da8995f2d..2e50869fd8e2 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -132,11 +132,22 @@ static void *qlink_to_object(struct qlist_node *qlink, struct kmem_cache *cache)
>  static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
>  {
>         void *object = qlink_to_object(qlink, cache);
> +       struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
>         unsigned long flags;
>
>         if (IS_ENABLED(CONFIG_SLAB))
>                 local_irq_save(flags);
>
> +       /*
> +        * If init_on_free is enabled and KASAN's free metadata is stored in
> +        * the object, zero the metadata. Otherwise, the object's memory will
> +        * not be properly zeroed, as KASAN saves the metadata after the slab
> +        * allocator zeroes the object.
> +        */
> +       if (slab_want_init_on_free(cache) &&
> +           cache->kasan_info.free_meta_offset == 0)
> +               memset(meta, 0, sizeof(*meta));

memzero_explicit()

although in this case it probably doesn't matter much, because AFAIK
memzero_explicit() only exists to prevent the compiler from eliding
the zeroing. Up to you.

> +
>         /*
>          * As the object now gets freed from the quarantine, assume that its
>          * free track is no longer valid.
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP11JKCEE328XomcReP7uBwZ%3Dda%3DSD5OS09N4co-WPhMQ%40mail.gmail.com.

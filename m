Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTEP3WIAMGQEY2X34XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E2CB4C269D
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Feb 2022 09:54:37 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id a12-20020a056902056c00b0061dc0f2a94asf1364247ybt.6
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Feb 2022 00:54:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645692876; cv=pass;
        d=google.com; s=arc-20160816;
        b=CQYRYO3kMjqJbyqZlo2oA9KNbNEU1y+w8glHlCSLfXZdce1rNkqkmcXbmlItuy0rw9
         eQWZun19w8dzPwrvwGYQ0fFj2981JJ/2u7oBY+UP1IMS8G12Og4R92neNzgTVp+XMkaU
         LLNcVpAFMooR8xJHWWevnTJcHR9VICIPWPV5ZW3dkTah1uNzmgQeIAyF3lpB8B3D6J6w
         Jsr9aAJm5Sp9fsgxhR5ZCxGuCFKTdQqr0kE16INc+YG2OyGMIsmPNNSuo4cAZI0IYfhT
         2KA1loZKgsagj3vir2YvDsr666rSmude6EMNQmZXXW8VE7rbdUehuU3nzSzWMy3E2qnV
         QxpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=akNwxwJIC+rQ3GgNkMO3ZsBLjGvKyzsZP3Rv2KMnRAo=;
        b=KcIX9rsdTZeN6vpqofL0+RXnzXJ50DMYmXkLy+5l/NzbdcTq5Le/P+2p6htJxk4mL3
         cn1QS9EeqVY+dmOLzo4Ig4bnaFZCCRGVGUudJ8UcHCZIRzNBgqcioslfo9UTM50Y8RVo
         hntQS5RtBvPTi6RqFXW/ztD+Au8sZBSkuUobFCaxF/GmYlbxEMrD0gf4+hGIKTdsph5t
         qwI6m4XHCUUUKrL4EuAJxVSeo4xdU365ynG5GvN5xNo7bQbKYJz57s4j/U6go6eVLdGn
         4IK0/glMlP/fB1DVF32OObmezQ9iGhn7xqO+p80hybfgV8UZCSTdtWgM0e8pnNOAj6jV
         rgoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tAwCy0Ju;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=akNwxwJIC+rQ3GgNkMO3ZsBLjGvKyzsZP3Rv2KMnRAo=;
        b=b0V7gunUb7aCw1SxPv2Sp6V3UCOWzy7Nd2aGCgaeKPdP0gvB1NkPrPIP22z9TNoZSj
         y9DUmU0rV3u3RsV3wt9GA1jfyUbnmrqhWbuYCz0vqzlXJNLhSuuU3hnNZdUUNLU33KvY
         EEldAVFF13KKwQuBo7haxwFB+wddS2cIxLgoBuah7FXOWOPJr8dZLrNp/HCZlkRFRLKJ
         0A8fGIFznKmdpAtXL0mwCi6dZ60pu/l6H7kcyyL0P0sTpg2yBd6zWHd717rTpU+TVDrc
         qpbVaBlLOyBEqNp2P8v4PdgHgSiUtDciPHao9gHFBD5beH3kRX2wXbueqFvGLWFz2JE8
         JY6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=akNwxwJIC+rQ3GgNkMO3ZsBLjGvKyzsZP3Rv2KMnRAo=;
        b=bwZgKsmU7Tx+CN80lTsgPNQsRNotqpjiU+eUjiX214b27l0oMVIqhc++oM8GmPQnRU
         VbGq3t4PEGQdVwkOO0fFXpCfEF1zitM5P6BH6jAY1LIpycW17EA/RQKaQIzVM0kjN1tG
         IM9G7X/PX7oTsUmLJt05DOgqEvpDMuvDvWh0Lh91ooaxlydMzIpio9FjI3NRkEijU8yY
         DBS4m/KAeuHDD9ksrci3jtvixdsA1o63BZIPE+L5ocdxbJVH3jO7smnJSHY3UA003Zr4
         g3zzao2pS0vEDmN5YO5AyUjY4Eq/JziMw9Tk0qFN088qKgSCstwBvZ8cqhbdXGOrjJv4
         QHUA==
X-Gm-Message-State: AOAM53261sOaGjw913w4fBqyHhie9jIAASYpODHl4++Cr/2azBgHyi5F
	p1p7Q05x8gKLKQaxtN6LMH0=
X-Google-Smtp-Source: ABdhPJzN4sl0ZhZvGx0qWELlgdvg3ffxmSMaLkquwB2rSKxJXbK/GwzpaOtGXSE5JKVCELhix8MMKw==
X-Received: by 2002:a81:918b:0:b0:2d6:5636:4594 with SMTP id i133-20020a81918b000000b002d656364594mr1408102ywg.72.1645692876350;
        Thu, 24 Feb 2022 00:54:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:d6d3:0:b0:2d6:ac1d:f80b with SMTP id y202-20020a0dd6d3000000b002d6ac1df80bls599282ywd.1.gmail;
 Thu, 24 Feb 2022 00:54:35 -0800 (PST)
X-Received: by 2002:a0d:d995:0:b0:2d6:f086:c0ec with SMTP id b143-20020a0dd995000000b002d6f086c0ecmr1450796ywe.396.1645692875839;
        Thu, 24 Feb 2022 00:54:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645692875; cv=none;
        d=google.com; s=arc-20160816;
        b=PqE1pstVegTIsJsOU7VvOviucX4VJNde5ckptjeoAyBluV8LoxnncT/mgUEF+vSe6z
         NL8Iz+ftoRif5CdKVfY2h7SYOsQ7WKu3rmvxu8C6oLxceUVyqs9l2QSZGZd8ww4N7TYT
         C47J3OiVHkTihB99LeueA7VbpS7y33o+Y4Z4PPlSYpdnJ61sAF/+WQ6QnisFzpMO/B0d
         Jhek0zawrE0TWl/aPlk/1aXppoRHkmbEJq1AwuJ9ICIdrOBHilqzAD1NZ1r93zzJnMyx
         sO/AfTYM3NnPZ8KvGU1viL2XScQKWhttMMH8tIJoMzwQ/N1g6MYzdORQM7Qs3yVfbZfA
         oGcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6LyzN4y/7LbQq4KLs8Ged395bQeALH2HjEMTuIFD+Xs=;
        b=moVw4nftfjJS17b1IHK+mqs9yvGcWsGiSKKZNgo0KV1cqyiriDjvJaZKIhHz04tf61
         RSaH46iZC2b+ONX80TaZwLApuq15RKKjm7CZCyqDrLPilBAwIEGEgwmw/mSgYW/T/ZHL
         w6FhTQy/f/2yMM9LLaKgjAZuf9hw4UkgM4VkiaGFvREgEYOgCElUS0SZxX4MsFoGb3ID
         S3dbSq7lmpSUmG+mIzREJN+gV9xxIgY6iV24XpWwvpmMwnAzJTAoHBlxGcOzVoOEx1Af
         WomF453uENv1ORQJXSaavS9Esm/Zey924AYEuXzwoQcBjH6x3YWuyfpBlNpTfPyfrHDz
         pdHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tAwCy0Ju;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id l63si165900ywg.4.2022.02.24.00.54.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Feb 2022 00:54:35 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id u12so2439047ybd.7
        for <kasan-dev@googlegroups.com>; Thu, 24 Feb 2022 00:54:35 -0800 (PST)
X-Received: by 2002:a25:a4e8:0:b0:61e:1eb6:19bd with SMTP id
 g95-20020a25a4e8000000b0061e1eb619bdmr1613695ybi.168.1645692875363; Thu, 24
 Feb 2022 00:54:35 -0800 (PST)
MIME-Version: 1.0
References: <20220224002024.429707-1-pcc@google.com>
In-Reply-To: <20220224002024.429707-1-pcc@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Feb 2022 09:54:23 +0100
Message-ID: <CANpmjNOaZNtsJ+5pgJrpHb5VZtXjFs1i1L2S6Q_oqFo3hFt4Tg@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: fix more unit tests with CONFIG_UBSAN_LOCAL_BOUNDS
 enabled
To: Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Daniel Micay <danielmicay@gmail.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=tAwCy0Ju;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as
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

On Thu, 24 Feb 2022 at 01:20, Peter Collingbourne <pcc@google.com> wrote:
>
> This is a followup to commit f649dc0e0d7b ("kasan: fix unit tests
> with CONFIG_UBSAN_LOCAL_BOUNDS enabled") that fixes tests that fail
> as a result of __alloc_size annotations being added to the kernel
> allocator functions.
>
> Link: https://linux-review.googlesource.com/id/I4334cafc5db600fda5cebb851b2ee9fd09fb46cc
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Cc: <stable@vger.kernel.org> # 5.16.x
> Fixes: c37495d6254c ("slab: add __alloc_size attributes for better bounds checking")

Reviewed-by: Marco Elver <elver@google.com>

Thanks!

> ---
> v2:
> - use OPTIMIZER_HIDE_VAR instead of volatile
>
>  lib/test_kasan.c | 4 ++++
>  1 file changed, 4 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 26a5c9007653..7c3dfb569445 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -185,6 +185,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
>
>         kfree(ptr);
> @@ -295,6 +296,7 @@ static void krealloc_more_oob_helper(struct kunit *test,
>                 KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
>
>         /* For all modes first aligned offset after size2 must be inaccessible. */
> +       OPTIMIZER_HIDE_VAR(ptr2);
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 ptr2[round_up(size2, KASAN_GRANULE_SIZE)] = 'x');
>
> @@ -319,6 +321,8 @@ static void krealloc_less_oob_helper(struct kunit *test,
>         /* Must be accessible for all modes. */
>         ptr2[size2 - 1] = 'x';
>
> +       OPTIMIZER_HIDE_VAR(ptr2);
> +
>         /* Generic mode is precise, so unaligned size2 must be inaccessible. */
>         if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>                 KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
> --
> 2.35.1.473.g83b2b277ed-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOaZNtsJ%2B5pgJrpHb5VZtXjFs1i1L2S6Q_oqFo3hFt4Tg%40mail.gmail.com.

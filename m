Return-Path: <kasan-dev+bncBDW2JDUY5AORBRM3QWXAMGQEZOHTY6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 508BD84A69B
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 22:06:15 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2d0ab3c5eecsf14547311fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 13:06:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707167174; cv=pass;
        d=google.com; s=arc-20160816;
        b=N9tSogZNlDLo+0gkQEFWfnaD84HDqB1qTrgC5j3/+5xPqEeqWx0J514JXRpduMVtar
         SNQWYaPpsujpz0yoGHdd482IUZgThhFeMNH9Ftly/wo2645UsOvHQ6SFVn/WcLAgXTYK
         kk0xygCCX5zquuRt5o6drOPYlneMAObBU1vQGTug4fBNWi1bT/MAUwR7dYhjVeuB5x/9
         CYKt2qUc5QF47Ihy3/KphXv/roG7OXMXHQuxZKl9L1peJ6DBxMvJ3Ot1CAu9wTsS9W+S
         I9t6ljwgRehFCBOmJea/fPt6ZXhEk7bJcyYNTt3d2Cn3MUOOUQ4s2aZ5+OkdVtoDe9ZC
         +l0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=L7f3UD6YzHfYAdSIQNV6GaDvzYJnc/2Awm1WI3fw+20=;
        fh=lwhxkJI+9AxWHHMCNqDPurBZ1nR2ooCzpu1Piu7bAkU=;
        b=FwQ4VSxkTB9ilKkdetgx50+GCnds+45JPZdrBYXwS5o9xoB/zUYe53lzReKbOE1bNH
         I5AKoRkxtBCcnwqOJgvX/sqEw3Ad3dlIs4eLKdsFbjZSgGNPkFGnrTIwWcPMly1bsZW0
         z12LvBcXilx0UFF4opSqAjWjumkq3cwhjMO+xFCA/0c1LWCpb++XOQDSV1tQk4riTIqS
         +0NbowJSwmbsItT99VkaTGaT89TQM1XAzxiJTSXikre28Q7MnDjkxo1ReqgdXEHfWbJ3
         cFYm85S7KI1DUm1B+7SF7QSPdApvEnC4zaTkCxNPRK9ybkY7K5vBtbJruJ15tKs0dtK1
         C8AA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=B5dY71MS;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707167174; x=1707771974; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=L7f3UD6YzHfYAdSIQNV6GaDvzYJnc/2Awm1WI3fw+20=;
        b=hMlEuvqrQcdzZ3EypmK9Va0uqZszHvX6hZY1LMlG9nUYsdzAkBjOQNEbGJvgqYwDjs
         p4CjBKLiXweGUibTo5elguybAbGt58S9s5QxB7ekkNOJjMu95fMd6D+Qf0vjrEbULGPD
         XT7XAmcH+K86oisZOj48l6DFvZjT6B8GyMvzb878swCElHgvZQ4huTiW/cgRhsJmHbfF
         x9AD/ntih6qeai0bt1L2YHtv4BQv2noxzCEJhIaXOgXjQJjjrft4kEI2XSretb6oKKqW
         1hXdY+BNswhX301csVs5ByREAOHF2r/j779st9sdNEOlknJy6IsWzRyhQZsRzTic+ksc
         yHSA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1707167174; x=1707771974; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=L7f3UD6YzHfYAdSIQNV6GaDvzYJnc/2Awm1WI3fw+20=;
        b=nbdTUOtByW8Vg34X/i4s6RO+747o12ubXg0iS4RR4j4I+ID9CQGJW/c6Q26IhYr/ig
         Re1eDHxJoHzdpIWopcXotMWFHMx1Nd1ZBY7rfbFfdmUwFd3WsWrKWs7m9E71q0vCwvII
         xRNmTpFlaiMMHsl+yco8/5vofAiV6NTMGDcXjArFZxi2v3uIy+cyEO0W/jllbLll46FL
         LD2Sl9zDDqyNTE5vWPr0IvX+wVtPkXqxsSwGue83tN873PB8fHFDaUDXEQgsA33xBEYU
         z6h3tlecQOxQWLmxTMoZSaIFRZ7xSihn42xo95RlbPWTwBqkCUqc6JJ9jt7h0bpwr2ZD
         +FMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707167174; x=1707771974;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=L7f3UD6YzHfYAdSIQNV6GaDvzYJnc/2Awm1WI3fw+20=;
        b=mQVkEvmvuTiIAF3qE9OtyBGevPtOL/JCfdynRZM8qbiAIEIA/kleS/0pJtdUrX+jGO
         bsyojxc0nijh7qw9TxUGBvUfeiHZ8w1bxnHcWLGHxy52/TfuQeeUkesEUKxYJ7O5Vtoe
         c9dl4RaAFFxdmvQ6e5J9yBSBOwrqkZyEzAcYStuXKypfbzyegQOPWHQbqI8Q2xbfYILW
         6b0imqoJbFZpJvbE/8l2tnGp+LA4okcW8wVnlduEI9h8qsGctDwpuYNW56dkua4QKJMr
         TJi3pnuJscDWPmY8bg/FHcUpjJOvc61Y7C4XuQNb8zVAbV2T+rwNmcyuUZr76S+qgiN/
         LHkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxh/VhcDB2NGGX07kgI8tfdMU7A3KI0ODMp4Azn3O04tB+jO4jY
	o13OP9K1pjKUfP7a0z5kDkTa1MP9MC35rLJp9A1svH5UIYbbnHEg
X-Google-Smtp-Source: AGHT+IHDaZi616DcaqK0yNK9Bcln0PboVYxbqsvXQ6VlxSlbX0GyfOwEoIEAr8GvVkuc3mAViOYLSw==
X-Received: by 2002:a2e:9255:0:b0:2d0:87a8:bda4 with SMTP id v21-20020a2e9255000000b002d087a8bda4mr250074ljg.25.1707167174020;
        Mon, 05 Feb 2024 13:06:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a0f:b0:2cc:e70b:1d80 with SMTP id
 by15-20020a05651c1a0f00b002cce70b1d80ls537943ljb.1.-pod-prod-08-eu; Mon, 05
 Feb 2024 13:06:12 -0800 (PST)
X-Received: by 2002:a2e:99d5:0:b0:2d0:b1a9:dfba with SMTP id l21-20020a2e99d5000000b002d0b1a9dfbamr233680ljj.29.1707167171919;
        Mon, 05 Feb 2024 13:06:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707167171; cv=none;
        d=google.com; s=arc-20160816;
        b=TTV+PusbDcNMSz/soK3G5hwoBevymjKv7i5JQG+NnvCeRu4YEYjLZqT6lvZMYVQTqq
         5jqxExdFb8IRgcu+hBmHUF+XseJkoyUuyZS60SmwSAYE7zrepwjauQC2I4tq1yHH7VKi
         EgadoG6Pfkeo9Zmim2Bp57gcIxdD7vDyZzJmUekp7r4ri66YOCGM/kqjAG0L4TZ/nFze
         ExaIwxKIY5NgUAmX9T/gLmHwoHnhOD4EwoWyozWY8/R5jrork+MsuXcbewf9gHTsnheG
         UKuqoshx8/tKIthind/z1NcQKnEFzV3tH6ZW+GEOyxx6zWW+FLutEVeeM7iQ5O/DRT36
         y3qQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oYuB7rX3JOcdu5mrg7aKnBeo6EiHj+iA643HXTXEZt0=;
        fh=lwhxkJI+9AxWHHMCNqDPurBZ1nR2ooCzpu1Piu7bAkU=;
        b=VTeyKA5L4/c1i+hx29HkGRmRDVUqNUSxAcq3TxnrmdgH6gXpyGAozyFLXRXGAP3yzD
         1PVNL1MbZ/2ACDkhD6zy9WNetUusCYJScKNlgQhqHkGjCYXImAypR522LfzI20+/GFj8
         nzofw+h8ru/BVk/L79cir1jv8cDqQvXWWBrX2xyPNte7BbjE/dxE566fMGfBCJ1qLtc3
         r7/a0pIkZ9i9x3dSysMfRu8o8YoIjGagEJbcPV8a4li5XuHqRAeWKI7LWFkZcEgb8zQ8
         11+idRzIa7nNn2oetPiF/1Km3NlSO5d40I0TVdDm6eGNBesHlelTAd8L1gSFcDDZzwoi
         JvPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=B5dY71MS;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
X-Forwarded-Encrypted: i=0; AJvYcCXf4zQfJ3R3rYupOpoMao5Ui1B9O7Bh5K8bqFoocI/3gDw+7WjY4nCyEiZugM7+rRwvql4JwrFka2R2eE9vgaBFvKNJH8SqYgiFyw==
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id y27-20020a05651c021b00b002d0afeedd11si39912ljn.8.2024.02.05.13.06.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Feb 2024 13:06:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-40fc6343bd2so31391695e9.1
        for <kasan-dev@googlegroups.com>; Mon, 05 Feb 2024 13:06:11 -0800 (PST)
X-Received: by 2002:a05:600c:3ba8:b0:40f:b630:a9e2 with SMTP id
 n40-20020a05600c3ba800b0040fb630a9e2mr181152wms.14.1707167171018; Mon, 05 Feb
 2024 13:06:11 -0800 (PST)
MIME-Version: 1.0
References: <20240205060925.15594-1-yangtiezhu@loongson.cn> <20240205060925.15594-3-yangtiezhu@loongson.cn>
In-Reply-To: <20240205060925.15594-3-yangtiezhu@loongson.cn>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 5 Feb 2024 22:06:00 +0100
Message-ID: <CA+fCnZdvQmA7S6cnFS5niSm3zERyaLpb_wp5Y6=na-yeNNX9=A@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan: Rename test_kasan_module_init to kasan_test_module_init
To: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: Andrew Morton <akpm@linux-foundation.org>, Jonathan Corbet <corbet@lwn.net>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=B5dY71MS;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Feb 5, 2024 at 7:09=E2=80=AFAM Tiezhu Yang <yangtiezhu@loongson.cn>=
 wrote:
>
> After commit f7e01ab828fd ("kasan: move tests to mm/kasan/"),
> the test module file is renamed from lib/test_kasan_module.c
> to mm/kasan/kasan_test_module.c, in order to keep consistent,
> rename test_kasan_module_init to kasan_test_module_init.
>
> Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
> ---
>  mm/kasan/kasan_test_module.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/kasan_test_module.c b/mm/kasan/kasan_test_module.c
> index 8b7b3ea2c74e..27ec22767e42 100644
> --- a/mm/kasan/kasan_test_module.c
> +++ b/mm/kasan/kasan_test_module.c
> @@ -62,7 +62,7 @@ static noinline void __init copy_user_test(void)
>         kfree(kmem);
>  }
>
> -static int __init test_kasan_module_init(void)
> +static int __init kasan_test_module_init(void)
>  {
>         /*
>          * Temporarily enable multi-shot mode. Otherwise, KASAN would onl=
y
> @@ -77,5 +77,5 @@ static int __init test_kasan_module_init(void)
>         return -EAGAIN;
>  }
>
> -module_init(test_kasan_module_init);
> +module_init(kasan_test_module_init);
>  MODULE_LICENSE("GPL");
> --
> 2.42.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdvQmA7S6cnFS5niSm3zERyaLpb_wp5Y6%3Dna-yeNNX9%3DA%40mail.=
gmail.com.

Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOMMT73QKGQEBPIVWJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A458F1F9FDB
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 21:04:26 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id x63sf12653766ilk.8
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 12:04:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592247865; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sqq2nesA1qOmA4hPfZtN8PwppGefdjfx5vcrNMtm0VifI5yo6hKds3zIIVEX1/FAbZ
         jMX+wEXlxqu9kAUG/cZnu9BMQGqz2WkzpxX/sojtEOIFA2fRoI7focUobai1Z/9Z8NtE
         nbHyrKyFE5r3+1+0VRbUI/ZAGQZICUKRXuwlCb7I4FT7iF4e/q39AVlQOcm8eg1cNV3+
         C6eueONJOjWWiJKopYGkK2caGix4xlxJ5KcA3RkVoS8a6Q3J6aILB4RrC6QBHa+cxPio
         /YjPfUo1ip0n/n+IzPOJ2AKr5NQL6i4S3D11nONQEL01EFCjUQP1XqrooN+4wu4KwtIn
         m+Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zqRyJZcVlr80XQK04EaNaEp89akchEyxP7u4rQOiBmI=;
        b=Kj8v0CDbRvHNuEoIxyl1ssGwOPO6X1V4fs+UpEabNWkrb4/x648wtepivjHmUZ7Ocv
         2uwzDeVem28FY/lrW+I9d2k2/LLBumXZquVNNxX6FLeAGy2iFiLrYIEuS5sa8NpBO5j2
         aqmEtmdxDZ6Xi/87Af3T/pko/ZPYniN/URiJSfE1wYXv+jWiUlHSmDAy5PZg+c6mu91J
         Y6p7JsVqNipUQ5JAYbSo1UCnAZyS1hIq4TBR+913NwtYNmkYKfdytMEYUui7HdwUBC2j
         sGeg0s/jBm2pNQj9OnmN8iFv9ZD8G60pGXxJEh7jDcn7Nd0S6x9Ss3UeJBItajlqM9dn
         pJ/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lMnXpMZZ;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zqRyJZcVlr80XQK04EaNaEp89akchEyxP7u4rQOiBmI=;
        b=clG7XStJ87gvUve20qMLT4RGmt0GrM12Y3p6aN/e8L0jhf7ecX+R9JRN3QwRen+NIo
         xSN561iUz/kPSz5RWTDc6WGJMQSUdfR4ktGMh1lGQN72xkiDthaLn0VT3c6b6J2uXPXW
         AS3rNBb8oyYYmnNXNKj+ARgIz2LdIH2Q2aoSaQxOjX0shM3StaCnuG3XybAeO90Da9NW
         YC4nSG70oLhGYtht4hNMmUf0no19ZvZ8f8NMr2tqFI7HymCwDYwtJXIDYXHjnp2olxtA
         r38tD5345JYAJOI4lm2gcN3xt6P8AQ2bVGjVzdLqSLWOuAi2wt0lhbzH7VlXkz/BwA1K
         bUQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zqRyJZcVlr80XQK04EaNaEp89akchEyxP7u4rQOiBmI=;
        b=EunX1KPDpKZzw57p//5emypvltzuvgrSM3jlXtFiahA4KVpPRnKJC1Q40jUYFF8eR8
         FanGYMEe6yQxZrSKGUPU9pkxwMNmrYAXgpkufG7p31TQCmxXD/cEYAykYfvIspyptfrC
         IlqTZ6RrS8SgKN+SBQlWW5+uJ2TS2P/62TN/clB8nBgOXkE7U1Ua2gg2FBjflXjWk3o0
         FBF/14N+G2rjlb3HeRCXjoEVPLCGDtwFMkJaZNAIeWhdERvGhPViPI9CJJj2Grd9vXnk
         xaYV7kriTwoWF/T213kLDe9hFASI28A/pu5mST6AtRBUvzf0v8c7iAhwiJWuA2QxObaM
         piZg==
X-Gm-Message-State: AOAM531AA/EhOKUhaYGyOA+QQ6jL3X6Id78wNCBs/O+xrzyXaHU7uyH1
	ZR3RfkwsjY1DjLHfbGUtESI=
X-Google-Smtp-Source: ABdhPJyl0YKiLPUNKbKUtIAActJ0aMmOrWU3Q1SzREdsv+Nd85mrJL7dOI8gsz5aOqVWtWnIxVTA4g==
X-Received: by 2002:a92:c643:: with SMTP id 3mr29030838ill.229.1592247865614;
        Mon, 15 Jun 2020 12:04:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:113:: with SMTP id x19ls1904918jao.0.gmail; Mon, 15
 Jun 2020 12:04:25 -0700 (PDT)
X-Received: by 2002:a02:b0d1:: with SMTP id w17mr23118320jah.75.1592247865262;
        Mon, 15 Jun 2020 12:04:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592247865; cv=none;
        d=google.com; s=arc-20160816;
        b=SdTixOI+4I52jtB4KP5ogtP/0hx9qsxCPI5JjzUNrVt19+s4Zg9U1DZ0KLfy7LfyTl
         mSGBL09rQLxH5auZVQ/fMBSLsg3AEctehKiMrrOJG0/9uOAjT93mhxbZkGHNpyAFXUuZ
         5QnJHi42T94W5m6Us8LwPFOQWyP5VO2Kg5a82sJULHT+T+lzlDlApoPX8xwY6V2yjju/
         bCIRKp7hl/4HpeuwGg/08xDKqPxdNNG2ikaY/0AwCUnR5btTUbol6l4SxLwVREEEIUUz
         BATmqPsrYmlYy+FQjfBnV3Ko4gx0yZRWRo/hhq9tMu2FzOuhKEbCde5PpYnIA0hW5NZ4
         9TPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9aW2TqrBLH8LeFdcz9gJFpsSwBcZN5ImxsbMz/APSqI=;
        b=TdUbtsj0CHvA3/CxGgVfAW/JXNzJlx/qPC8l2Y7vv3qnRwLovElIbRoXZngwA0As2Q
         ZvEP2iZOhsSrGMfe+4v3kXkCM8nIkOQNwopnXQJYC2RU8UNyYwGQFdn0CtKMfulgkARx
         N042RHsCLxsJbQof9PftyK+auDUkoUPKOHJ8zyBlFWR7ExMPz/9XrEok+uvtiWxEyRso
         JkeJK/ItQy/uRYx7ECP49sJu3HeQngYCYXzdY1DTrB4gxiI3FrMyn/YLSwZMou5Al+GG
         l4pDhexxWPrPWQIksOJVMDh6N0lvdgntBMYycLiCnA0zpoUIiY1AJWKRyF1jm5NCyvEI
         yvmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lMnXpMZZ;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id g12si719361iow.3.2020.06.15.12.04.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jun 2020 12:04:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id m7so7173930plt.5
        for <kasan-dev@googlegroups.com>; Mon, 15 Jun 2020 12:04:25 -0700 (PDT)
X-Received: by 2002:a17:90b:1244:: with SMTP id gx4mr707505pjb.136.1592247864399;
 Mon, 15 Jun 2020 12:04:24 -0700 (PDT)
MIME-Version: 1.0
References: <20200615184302.7591-1-elver@google.com>
In-Reply-To: <20200615184302.7591-1-elver@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Jun 2020 21:04:13 +0200
Message-ID: <CAAeHK+zdNpMhpaHRYHxc9a5ghp4MBR3ecxxWem8-yrNFLYTFEg@mail.gmail.com>
Subject: Re: [PATCH] kcov: Unconditionally add -fno-stack-protector to
 compiler options
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Nick Desaulniers <ndesaulniers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lMnXpMZZ;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Jun 15, 2020 at 8:43 PM Marco Elver <elver@google.com> wrote:
>
> Unconditionally add -fno-stack-protector to KCOV's compiler options, as
> all supported compilers support the option. This saves a compiler
> invocation to determine if the option is supported.
>
> Because Clang does not support -fno-conserve-stack, and
> -fno-stack-protector was wrapped in the same cc-option, we were missing
> -fno-stack-protector with Clang. Unconditionally adding this option
> fixes this for Clang.
>
> Suggested-by: Nick Desaulniers <ndesaulniers@google.com>
> Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> Split out from series:
>         https://lkml.kernel.org/r/20200605082839.226418-2-elver@google.com
> as there is no dependency on the preceding patch (which will be dropped).
> ---
>  kernel/Makefile | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/Makefile b/kernel/Makefile
> index f3218bc5ec69..592cb549dcb8 100644
> --- a/kernel/Makefile
> +++ b/kernel/Makefile
> @@ -35,7 +35,7 @@ KCOV_INSTRUMENT_stacktrace.o := n
>  KCOV_INSTRUMENT_kcov.o := n
>  KASAN_SANITIZE_kcov.o := n
>  KCSAN_SANITIZE_kcov.o := n
> -CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> +CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
>
>  # cond_syscall is currently not LTO compatible
>  CFLAGS_sys_ni.o = $(DISABLE_LTO)
> --
> 2.27.0.290.gba653c62da-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzdNpMhpaHRYHxc9a5ghp4MBR3ecxxWem8-yrNFLYTFEg%40mail.gmail.com.
